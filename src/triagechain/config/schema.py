"""Konfigurasyon semasi (pydantic v2)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from triagechain.collection import catalog as catalog_module
from triagechain.collection.selector import load_catalog
from triagechain.core.case import validate_case_id


class CaseConfig(BaseModel):
    """Vaka basligi: kimlik, operator ve serbest aciklama."""

    case_id: str
    operator: str
    description: str = ""

    @field_validator("case_id")
    @classmethod
    def _check_case_id(cls, value: str) -> str:
        # Dogrulama tek yerde (core.case) duruyor; burada sadece cagriliyor.
        return validate_case_id(value)


class CollectionConfig(BaseModel):
    """Neyin, nasil ve nereye toplanacagi."""

    targets: list[str] = Field(min_length=1)
    hash_algorithm: Literal["sha256", "sha1", "md5"] = "sha256"
    output_dir: str
    # Katalogdaki hedefler (targets) HEP %SystemDrive%'a gore cozulur --
    # $MFT her NTFS biriminde ayri ayri var oldugu icin, sistem disindaki
    # sabit diskler (orn. "D:") burada listelenirse onlarin da $MFT'si
    # toplanir. Bilerek SADECE $MFT: registry/event log/prefetch gibi
    # digerleri zaten Windows kurulumuna (sistem diskine) ozgu, baska bir
    # birimde anlamli bir karsiligi yok.
    additional_volumes: list[str] = Field(default_factory=list)
    # capa (bkz. DetectionConfig.capa_path) davranis/yetenek analizi icin
    # bir OLAY GUNLUGU degil, ANALISTIN KENDI SECTIGI supheli bir yurutulebilir
    # (.exe/.dll) dosya ister -- katalogdaki diger hedefler gibi sabit,
    # herkesce bilinen bir konum degil. Bu yuzden ayri bir liste: analist
    # supheli bulunan dosyanin/dosyalarin MUTLAK yolunu buraya yazar.
    suspicious_binaries: list[str] = Field(default_factory=list)

    @field_validator("targets")
    @classmethod
    def _check_targets_exist_in_catalog(cls, value: list[str]) -> list[str]:
        catalog = load_catalog(catalog_module.default_catalog_path())
        unknown = [tid for tid in value if tid not in catalog]
        if unknown:
            raise ValueError(
                "katalogda olmayan hedef kimlikleri: " + ", ".join(sorted(unknown))
            )
        return value

    @field_validator("additional_volumes")
    @classmethod
    def _check_volume_letters(cls, value: list[str]) -> list[str]:
        # Sadece "D:" ya da "D:\" bicimini kabul ediyoruz -- baska her sey
        # (goreli yol, UNC yolu, tam bir dosya yolu) burada bir surucu harfi
        # degil, kullanicinin yanlislikla bir yol yapistirdigini gosterir.
        pattern = re.compile(r"^[A-Za-z]:\\?$")
        invalid = [v for v in value if not pattern.match(v)]
        if invalid:
            raise ValueError(
                "additional_volumes yalnizca surucu harfi olmali (orn. 'D:'): "
                + ", ".join(repr(v) for v in invalid)
            )
        return [v.rstrip("\\").upper() for v in value]

    @field_validator("suspicious_binaries")
    @classmethod
    def _check_suspicious_binary_paths(cls, value: list[str]) -> list[str]:
        # additional_volumes'daki _check_absolute ile ayni gerekce: goreli
        # yol hangi dosyanin gercekte kastedildigini belirsizlestirir. Dosyanin
        # VAR olmasi burada aranmaz -- analiz konusu dosya toplama aninda
        # eklenmemis/silinmis olabilir; varlik kontrolu kosu aninda yapilir
        # ve olumcul olmayan bir hataya doner (bkz. collector.py).
        not_absolute = [v for v in value if not Path(v).is_absolute()]
        if not_absolute:
            raise ValueError(
                "suspicious_binaries yalnizca mutlak yol olmali: "
                + ", ".join(repr(v) for v in not_absolute)
            )
        return value


class RouterConfig(BaseModel):
    """Ayristirma araclarinin (MFTECmd, RECmd, EvtxECmd, PECmd) tanimlari.

    Araclar TriageChain ile birlikte dagitilmaz; kullanici kendi kurdugu
    surumlerin yolunu burada bildirir. Tanimsiz birakilan arac hata degildir,
    yonlendirme sirasinda "atlandi" olarak kaydedilir.
    """

    # Arac adi (tool_mapping.yaml'daki 'tool' degeri) -> mutlak .exe yolu.
    tools: dict[str, str] = {}
    # RECmd'in --bn bayragina verilecek toplu (batch) dosyasinin MUTLAK yolu.
    # None ise pakete gomulu varsayilan kullanilir
    # (router/catalog/recmd_batch/DFIRBatch.reb).
    recmd_batch_file: Optional[str] = None
    timeout_seconds: int = 300

    @field_validator("recmd_batch_file")
    @classmethod
    def _check_batch_file_absolute(cls, value: Optional[str]) -> Optional[str]:
        # Deger verilmemisse (None) gomulu varsayilan kullanilacak, kontrol
        # edilecek bir sey yok. Verilmisse mutlak olmali: tools/hayabusa_path
        # ile ayni gerekce (goreli yol hangi kural setinin kullanildigini
        # belirsizlestirir). Dosyanin VAR olmasi burada aranmaz; varlik
        # kontrolu kosu aninda yapilir ve olumcul olmayan bir atlamaya doner.
        if value is not None and not Path(value).is_absolute():
            raise ValueError(f"mutlak yol olmali: {value}")
        return value

    @field_validator("tools")
    @classmethod
    def _check_absolute(cls, value: dict[str, str]) -> dict[str, str]:
        # Goreli yol PATH belirsizligi/hijack riski tasir - config asamasinda
        # reddedilir. Dosyanin VAR olmasi burada aranmaz: kullanici araclari
        # kurmadan once konfigurasyonu yazmis olabilir; varlik kontrolu
        # yonlendirme aninda yapilir ve olumcul olmayan bir atlamaya doner.
        not_absolute = [name for name, p in value.items() if not Path(p).is_absolute()]
        if not_absolute:
            raise ValueError(
                "mutlak yol olmayan arac tanimlari: " + ", ".join(sorted(not_absolute))
            )
        return value


class DetectionConfig(BaseModel):
    """Sigma kural tabanli tespit (Hayabusa) ayarlari.

    RouterConfig ile ayni desen: arac TriageChain ile dagitilmaz, kullanici
    kendi kurdugu surumun yolunu bildirir. Tanimsiz birakilmak hata degildir;
    tespit kosusu "arac konfigure edilmemis" diyerek atlanir.
    """

    # Hayabusa calistirilabilirinin mutlak yolu (None ise tespit atlanir).
    hayabusa_path: Optional[str] = None
    # Sigma/Hayabusa kural klasorunun mutlak yolu (None ise tespit atlanir).
    rules_dir: Optional[str] = None
    # Hayabusa tum bir .evtx'i tarar; router'in 300 sn'sinden uzun tutuldu.
    timeout_seconds: int = 600

    # YARA calistirilabilirinin mutlak yolu (None ise imza taramasi atlanir).
    # Hayabusa ile AYNI gerekce: arac dagitilmaz, kullanici kendi kurdugu
    # surumun yolunu bildirir (bkz. aldigim_kararlar.md -> "YARA entegrasyonu").
    yara_path: Optional[str] = None
    # Tek bir .yar/.yara kural dosyasinin mutlak yolu. Birden fazla kural
    # istenirse YARA'nin KENDI `include` direktifi kullanilir -- TriageChain
    # kendi kural birlestirme mekanizmasini icat etmez.
    yara_rules_file: Optional[str] = None
    yara_timeout_seconds: int = 300

    # Chainsaw calistirilabilirinin mutlak yolu (None ise tespit atlanir).
    # Hayabusa ile AYNI `rules_dir`'i (Sigma kural klasoru) kullanir --
    # BILEREK: amaci ayni kural setini IKI BAGIMSIZ motorla calistirip
    # sonuclarin ORTUSUP ORTUSMEDIGINI gormek (gercek capraz dogrulama,
    # bkz. aldigim_kararlar.md -> "Chainsaw entegrasyonu").
    chainsaw_path: Optional[str] = None
    # Chainsaw'in Sigma kurallarini .evtx alanlarina eslemek icin gerektirdigi
    # dosya (Hayabusa'nin ihtiyaci OLMAYAN, Chainsaw'a ozgu bir kavram) --
    # kendi ikilisiyle birlikte gelir (mappings/sigma-event-logs-all.yml).
    chainsaw_mapping_file: Optional[str] = None
    chainsaw_timeout_seconds: int = 600

    # capa calistirilabilirinin mutlak yolu (None ise yetenek analizi atlanir).
    # Hayabusa/Chainsaw/YARA'dan farki: capa GOMULU bir varsayilan kural
    # setiyle kutudan ciktigi gibi calisir -- capa_rules_dir SADECE bir
    # override, zorunlu degil (bkz. aldigim_kararlar.md -> "capa entegrasyonu").
    capa_path: Optional[str] = None
    capa_rules_dir: Optional[str] = None
    # capa'nin statik analizi (vivisect ile disassembly) Hayabusa/Chainsaw'dan
    # BELIRGIN sekilde daha yavas -- gercek bir notepad.exe'ye karsi ~43 saniye
    # surdu; buyuk/paketlenmis bir kotu amacli yazilim dosyasi dakikalar
    # alabilir. Bu yuzden varsayilan diger tum zaman asimlarindan uzun.
    capa_timeout_seconds: int = 1800

    @field_validator(
        "hayabusa_path", "rules_dir", "yara_path", "yara_rules_file",
        "chainsaw_path", "chainsaw_mapping_file", "capa_path", "capa_rules_dir",
    )
    @classmethod
    def _check_absolute(cls, value: Optional[str]) -> Optional[str]:
        # RouterConfig._check_absolute ile ayni gerekce: goreli yol hangi
        # ikilinin/kural setinin kullanildigini belirsizlestirir. Yolun VAR
        # olmasi burada aranmaz; varlik kontrolu kosu aninda yapilir ve
        # olumcul olmayan bir atlamaya doner.
        if value is not None and not Path(value).is_absolute():
            raise ValueError(f"mutlak yol olmali: {value}")
        return value


class CustodyConfig(BaseModel):
    """Chain-of-custody defteri ayarlari."""

    # None ise yol loader'da <output_dir>/<case_id>/custody.jsonl olarak turetilir.
    log_path: Optional[str] = None


class LoggingConfig(BaseModel):
    """Uygulama gunlugu ayarlari."""

    level: Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"] = "INFO"


class TriageChainConfig(BaseModel):
    """Ust duzey konfigurasyon nesnesi."""

    case: CaseConfig
    collection: CollectionConfig
    custody: CustodyConfig = CustodyConfig()
    router: RouterConfig = RouterConfig()
    detection: DetectionConfig = DetectionConfig()
    logging: LoggingConfig = LoggingConfig()
