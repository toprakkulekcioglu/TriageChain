"""VssSnapshot: WMI (pywin32) tabanli golge kopya olusturma/silme testleri.

Hicbir test gercek bir golge kopya olusturmaz ve GERCEK pywin32'ye de
ihtiyac duymaz: `win32com.client` sys.modules'a sahte bir modul olarak
enjekte ediliyor (bkz. `fake_win32com` fixture'i). Bu sart, cunku CI
`ubuntu-latest` uzerinde calisiyor ve orada pywin32 kurulu olmayacak.

Gercek makinede dogrulanan bulgular icin bkz. docs/hatalar_ve_sonuclar.md.
"""

import importlib
import sys
import time
from unittest.mock import MagicMock

import pytest

from triagechain.core.errors import CollectionError

SHADOW_ID = "{B6A8C555-5A91-40EF-9F04-7A5A59C338BA}"
DEVICE_PATH = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7"


@pytest.fixture
def fake_win32com(monkeypatch):
    """Sahte bir `win32com.client` enjekte edip modulu taze import eder.

    Modul-seviyesindeki `try: import win32com.client` satirinin sahte modulu
    yakalamasi icin `vss_snapshot` her testte yeniden yukleniyor; testten
    sonra da gercek/orijinal duruma geri donduruluyor.
    """
    fake_client = MagicMock()
    monkeypatch.setitem(sys.modules, "win32com", MagicMock(client=fake_client))
    monkeypatch.setitem(sys.modules, "win32com.client", fake_client)

    import triagechain.collection.vss_snapshot as mod

    importlib.reload(mod)
    yield fake_client, mod
    monkeypatch.undo()  # once sahte moduller kaldirilsin...
    importlib.reload(mod)  # ...sonra modul gercek durumuyla yeniden yuklensin


def _wire_wmi(fake_client, return_value=0, query_results=None):
    """Dogrulanmis WMI cagri zincirini sahte nesnelerle kurar.

    Donen `shadow_instance`, `__exit__`'te `Delete_()` cagrilacak nesnedir.
    """
    out_values = {"ReturnValue": return_value, "ShadowID": SHADOW_ID}
    out_params = MagicMock()
    out_params.Properties_.side_effect = lambda name: MagicMock(Value=out_values[name])

    shadow_instance = MagicMock()
    shadow_instance.Properties_.side_effect = lambda name: MagicMock(
        Value={"DeviceObject": DEVICE_PATH}[name]
    )

    wmi = MagicMock()
    wmi.ExecMethod.return_value = out_params
    wmi.ExecQuery.return_value = (
        [shadow_instance] if query_results is None else query_results
    )
    fake_client.GetObject.return_value = wmi
    return wmi, shadow_instance


def test_enter_creates_snapshot_and_exit_deletes_it(fake_win32com):
    fake_client, mod = fake_win32com
    wmi, shadow_instance = _wire_wmi(fake_client)

    with mod.VssSnapshot(volume="C:") as snap:
        assert snap.shadow_id == SHADOW_ID
        assert snap.device_path == DEVICE_PATH
        assert str(snap.translate(r"C:\$MFT")) == DEVICE_PATH + r"\$MFT"

    # Volume, WMI'nin bekledigi bicimde (surucu harfi + ters slash) verilmis olmali.
    in_params = wmi.Get.return_value.Methods_.return_value.InParameters.SpawnInstance_.return_value
    assert in_params.Volume == "C:\\"
    assert in_params.Context == "ClientAccessible"
    # Silme, ayri bir vssadmin cagrisi degil, WMI orneginin kendi metodu.
    shadow_instance.Delete_.assert_called_once_with()


def test_enter_raises_collection_error_on_nonzero_return_value(fake_win32com):
    fake_client, mod = fake_win32com
    _wire_wmi(fake_client, return_value=8)

    with pytest.raises(CollectionError):
        with mod.VssSnapshot(volume="C:"):
            pass  # pragma: no cover - __enter__ hata firlatir, buraya gelinmez


def test_enter_wraps_raw_com_exception_in_collection_error(fake_win32com):
    """Ham COM/WMI istisnasi disari sizmamali, CollectionError'a sarilmali."""
    fake_client, mod = fake_win32com
    raw = Exception("COM hatasi: erisim reddedildi")
    fake_client.GetObject.side_effect = raw

    with pytest.raises(CollectionError) as excinfo:
        with mod.VssSnapshot(volume="C:"):
            pass  # pragma: no cover
    assert excinfo.value.__cause__ is raw


def test_enter_raises_collection_error_when_pywin32_missing(fake_win32com):
    """pywin32 hic kurulu degilmis gibi (Linux) davranildiginda anlamli hata."""
    _, mod = fake_win32com
    mod.win32com = None

    with pytest.raises(CollectionError, match="pywin32"):
        with mod.VssSnapshot(volume="C:"):
            pass  # pragma: no cover


def test_enter_raises_collection_error_on_real_timeout(fake_win32com):
    """WMI cagrisi gercekten askida kalirsa (timeout'tan uzun surerse)
    CollectionError firlatilmali -- eskiden bu asla olmazdi (timeout hic
    kullanilmiyordu), bkz. aldigim_kararlar.md -> 'VSS icin gercek zaman asimi'."""
    fake_client, mod = fake_win32com
    wmi, _ = _wire_wmi(fake_client)
    # GetObject cagrisini yavaslatarak gercek bir "askida kalma" simule edilir.
    real_get_object = fake_client.GetObject

    def slow_get_object(*args, **kwargs):
        time.sleep(0.3)
        return real_get_object(*args, **kwargs)

    fake_client.GetObject = MagicMock(side_effect=slow_get_object)

    with pytest.raises(CollectionError, match="saniyede tamamlanmadi"):
        with mod.VssSnapshot(volume="C:", timeout=0):
            pass  # pragma: no cover


def test_exit_delete_timeout_is_logged_not_raised(fake_win32com, caplog):
    """Silme cagrisi askida kalirsa (timeout) with blogundan yine de
    istisnasiz cikilmali -- sadece loglanir, tipki normal silme hatasi gibi."""
    fake_client, mod = fake_win32com
    _, shadow_instance = _wire_wmi(fake_client)

    def slow_delete():
        time.sleep(0.3)

    shadow_instance.Delete_ = MagicMock(side_effect=slow_delete)

    # Kucuk ama sifir olmayan bir zaman asimi: olusturma (yavaslatilmamis,
    # hemen biter) icin yeterli, yavaslatilmis silme (0.3s) icin yetersiz.
    with mod.VssSnapshot(volume="C:", timeout=0.05):
        pass

    assert any("saniyede tamamlanmadi" in message for message in caplog.messages)


def test_exit_failure_is_logged_not_raised(fake_win32com, caplog):
    """Silme basarisiz olsa bile with blogundan cikarken istisna firlamamali
    (orijinal hatayi maskeleme riski) - sadece loglanir."""
    fake_client, mod = fake_win32com
    _, shadow_instance = _wire_wmi(fake_client)
    shadow_instance.Delete_.side_effect = Exception("silinemiyor")

    with mod.VssSnapshot(volume="C:"):
        pass

    assert any("silinemedi" in message for message in caplog.messages)
