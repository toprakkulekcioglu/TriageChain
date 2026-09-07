"""Volume Shadow Copy anlik goruntusu (pywin32 / WMI COM ile).

Bu modul yalnizca gercek Windows'ta ve yonetici haklariyla calisir; testlerde
sahte bir `win32com.client` modulu enjekte edilerek mock'lanir.

BAGIMLILIK NOTU: Bu dosya, projenin "ucuncu parti bagimliliktan kacin"
ilkesinin BILINCLI ve KULLANICI ONAYLI tek istisnasidir -- `pywin32`
(`win32com.client`) yalnizca burada kullaniliyor, projenin geri kalani hala
stdlib + pydantic/PyYAML ile yetiniyor. Gerekce: onceki cozum golge kopyayi
`powershell.exe` uzerinden olusturup komutun METIN ciktisini ayristiriyordu;
WMI'yi dogrudan cagirmak hem metin ayristirma kirilganligini tamamen ortadan
kaldiriyor hem de ekstra bir surec (powershell.exe) baslatmayi gereksiz
kiliyor. Detaylar: docs/aldigim_kararlar.md.

ONEMLI DERS (gercek makinede test edilerek bulundu, bkz.
docs/hatalar_ve_sonuclar.md): `vssadmin create shadow` bu projenin ilk
tasarim varsayimiydi ama GERCEK bir Windows 11 makinesinde calismiyor --
Microsoft bunu istemci surumlerinde kaldirdi. Golge kopya olusturmanin hala
calisan yolu WMI'nin `Win32_ShadowCopy.Create()` metodu. Silme icin de ayri
bir `vssadmin` cagrisina gerek yok: WMI orneginin kendi `Delete_()` metodu
kullaniliyor.

GERCEK ZAMAN ASIMI (bkz. docs/aldigim_kararlar.md -> "VSS icin gercek zaman
asimi"): WMI cagrilari senkron oldugu icin dogrudan cagrilirsa askida kalirsa
hicbir sekilde kesilemez. Bu yuzden hem olusturma hem silme, ayri bir DAEMON
thread'de calistirilip `join(timeout)` ile bekleniyor. Python thread'leri
ZORLA durdurulamadigindan (dil kisitlamasi), zaman asimi gercek bir "iptal"
degil -- cagiran tarafa kontrolu geri verir ama arka plan thread'i (COM
kendi apartmaninda) calismaya devam edebilir. Bu, YETIM bir golge kopya
birakma riski tasir; __enter__ zaman asiminda kullaniciya `vssadmin list
shadows` ile elle kontrol onerisi verir.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Optional

from triagechain.core.errors import CollectionError

logger = logging.getLogger(__name__)

try:
    import win32com.client
except ImportError:  # pywin32 yoksa (or. CI'daki Linux) modul yine de import edilebilir
    win32com = None  # type: ignore[assignment]

try:
    import pythoncom
except ImportError:  # ayni gerekce: win32com yoksa pythoncom da yok
    pythoncom = None  # type: ignore[assignment]


class VssSnapshot:
    """`with VssSnapshot(volume="C:") as snap:` seklinde kullanilir."""

    def __init__(self, volume: str = "C:", timeout: float = 180) -> None:
        self.volume = volume.rstrip("\\")
        self.timeout = timeout
        self.shadow_id: Optional[str] = None
        self.device_path: Optional[str] = None
        # __exit__'te Delete_() cagrilacak WMI ornegi.
        self._shadow_instance: Any = None

    def __enter__(self) -> "VssSnapshot":
        if win32com is None:
            raise CollectionError(
                "pywin32 kurulu degil; bu ozellik yalnizca Windows'ta calisir."
            )

        completed, value, error = self._run_with_timeout(
            self._create_shadow_copy, self.timeout
        )
        if not completed:
            raise CollectionError(
                f"Golge kopya olusturma {self.timeout} saniyede tamamlanmadi "
                f"({self.volume}); WMI cagrisi askida kalmis olabilir. Arka "
                "plandaki islem daha sonra tamamlanirsa golge kopya sistemde "
                "YETIM kalabilir -- 'vssadmin list shadows' ile kontrol edip "
                "gerekirse elle silin."
            )
        if error is not None:
            raise error

        self.shadow_id, self.device_path, self._shadow_instance = value
        logger.info("Golge kopya olusturuldu: %s -> %s", self.shadow_id, self.device_path)
        return self

    def _create_shadow_copy(self) -> tuple[str, str, Any]:
        """WMI ile golge kopya olusturur; (shadow_id, device_path, instance) dondurur.

        Ayri bir thread'de cagirilabilecek sekilde SAF (self disindaki hicbir
        paylasilan duruma yazmiyor) tutuluyor -- sonuc __enter__'de ana
        thread'e donuyor, thread'in kendisi COM nesnesine bir daha dokunmuyor.
        """
        try:
            wmi = win32com.client.GetObject(r"winmgmts:\\.\root\cimv2")
            shadow_class = wmi.Get("Win32_ShadowCopy")
            in_params = shadow_class.Methods_("Create").InParameters.SpawnInstance_()
            # WMI surucu harfini ters slash ile bekliyor: "C:\"
            in_params.Volume = self.volume + "\\"
            in_params.Context = "ClientAccessible"
            out_params = wmi.ExecMethod("Win32_ShadowCopy", "Create", in_params)

            return_value = out_params.Properties_("ReturnValue").Value
            if return_value != 0:
                raise CollectionError(
                    f"Golge kopya olusturulamadi ({self.volume}). "
                    f"Win32_ShadowCopy.Create ReturnValue={return_value!r}. "
                    "Yonetici haklariyla calistirdiginizdan emin olun."
                )
            shadow_id = out_params.Properties_("ShadowID").Value

            # DeviceObject, Create ciktisinda donmuyor; ornegi ayrica sorguluyoruz.
            results = list(
                wmi.ExecQuery(f"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadow_id}'")
            )
            if not results:
                raise CollectionError(
                    f"Golge kopya olusturuldu ({shadow_id}) ama WMI sorgusunda "
                    "bulunamadi; cihaz yolu alinamiyor."
                )
            shadow_instance = results[0]
            device_path = shadow_instance.Properties_("DeviceObject").Value
            return shadow_id, device_path, shadow_instance
        except CollectionError:
            raise
        except Exception as exc:  # noqa: BLE001 - ham COM hatasi disari sizmamali
            raise CollectionError(
                f"Golge kopya olusturulurken WMI/COM hatasi ({self.volume}): {exc}"
            ) from exc

    def translate(self, original_path: Path | str) -> Path:
        """`C:\\$MFT` gibi bir yolu golge kopya uzerindeki karsiligina cevirir."""
        if not self.device_path:
            raise CollectionError("Golge kopya henuz olusturulmadi.")
        text = str(original_path)
        # Surucu harfini ('C:') atip geri kalanini cihaz yoluna ekliyoruz.
        if len(text) >= 2 and text[1] == ":":
            text = text[2:]
        return Path(self.device_path.rstrip("\\") + "\\" + text.lstrip("\\"))

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        # Temizlik asla orijinal hatayi maskelemez, ama sessizce de gecilmez.
        if self._shadow_instance is None:
            return False

        completed, _value, error = self._run_with_timeout(
            self._shadow_instance.Delete_, self.timeout
        )
        if not completed:
            logger.error(
                "Golge kopya silme %s saniyede tamamlanmadi (%s). Sistemde "
                "yetim kalmis olabilir, elle silin: "
                "vssadmin delete shadows /shadow=%s.",
                self.timeout,
                self.shadow_id,
                self.shadow_id,
            )
        elif error is not None:
            logger.error(
                "Golge kopya silinemedi (%s). Sistemde artik kalmis olabilir, "
                "elle silin: vssadmin delete shadows /shadow=%s. Hata: %s",
                self.shadow_id,
                self.shadow_id,
                error,
            )
        else:
            logger.info("Golge kopya silindi: %s", self.shadow_id)
        return False

    @staticmethod
    def _run_with_timeout(func, timeout: float) -> tuple[bool, Any, Optional[Exception]]:
        """`func()`'u ayri bir daemon thread'de calistirir, `timeout` saniye bekler.

        Donen (completed, value, error) uclusu:
          - completed=False: thread suresinde bitmedi (deger/hata anlamsiz).
          - completed=True, error=None: value gecerli sonuc.
          - completed=True, error=Exception: func() bu hatayi firlatti.

        pythoncom kuruluysa (gercek Windows) her cagri kendi COM apartmanini
        thread icinde acip kapatir -- COM nesneleri apartman-bagli oldugu icin
        bu, WMI cagrisinin OLUSTURULDUGU thread'de kalmasini garantiler.
        """
        result: dict[str, Any] = {}

        def worker() -> None:
            if pythoncom is not None:
                pythoncom.CoInitialize()
            try:
                result["value"] = func()
            except Exception as exc:  # noqa: BLE001 - ana thread'e tasinip orada degerlendirilir
                result["error"] = exc
            finally:
                if pythoncom is not None:
                    pythoncom.CoUninitialize()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            return False, None, None
        return True, result.get("value"), result.get("error")
