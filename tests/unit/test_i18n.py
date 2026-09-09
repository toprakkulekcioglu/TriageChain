"""i18n.py'nin dil tablosu testleri.

i18n modulu SUREC GENELINDE PAYLASILAN modul-seviyesi durum tasiyor -- her
test sonunda "tr"ye DONDURULUYOR (autouse fixture) ki bu dosyadaki testler
diger test dosyalarinin varsaydigi varsayilan dili BOZMASIN.
"""

import pytest

from triagechain.gui_qt import i18n


@pytest.fixture(autouse=True)
def _reset_language_after_test():
    yield
    i18n.set_language("tr")


def test_varsayilan_dil_turkce():
    assert i18n.get_language() == "tr"
    assert i18n.t("nav_settings") == "Ayarlar"


def test_desteklenen_diller_kullanicinin_istedigi_sira_ve_kapsam():
    assert list(i18n.SUPPORTED_LANGUAGES.keys()) == ["tr", "en", "es", "de", "pt", "fr"]


def test_dil_basligi_aktif_dildeki_kelimeyi_ingilizceyle_esler():
    """Kullanicinin acik istegi: baslik aktif dildeki 'dil' kelimesini
    'Language' ile eslesin (henuz cevrilmemis bir dile gecilmis olsa bile),
    TEK istisna Ingilizce'nin kendisi -- o zaman tekrar olmasin diye
    sadece 'Language' gosterilir."""
    i18n.set_language("tr")
    assert i18n.language_heading() == "Dil / Language"

    i18n.set_language("en")
    assert i18n.language_heading() == "Language"

    i18n.set_language("es")
    assert i18n.language_heading() == "Idioma / Language"

    i18n.set_language("de")
    assert i18n.language_heading() == "Sprache / Language"

    i18n.set_language("pt")
    assert i18n.language_heading() == "Idioma / Language"

    i18n.set_language("fr")
    assert i18n.language_heading() == "Langue / Language"


def test_set_language_ingilizceye_geciyor():
    i18n.set_language("en")

    assert i18n.get_language() == "en"
    assert i18n.t("nav_settings") == "Settings"
    assert i18n.t("window_title") == "TriageChain Console"


def test_set_language_gecersiz_kod_turkceye_duser():
    i18n.set_language("xx")
    assert i18n.get_language() == "tr"


def test_tr_ve_en_gercekten_cevrili():
    assert i18n.is_translated("tr")
    assert i18n.is_translated("en")


def test_es_de_pt_fr_henuz_cevrilmedi():
    for code in ("es", "de", "pt", "fr"):
        assert not i18n.is_translated(code)


def test_cevrilmemis_dil_secilince_t_ingilizceye_duser():
    i18n.set_language("de")

    # get_language() KULLANICININ SECTIGI ham kodu doner (Ayarlar
    # sayfasindaki acilir liste bunu dogru gostersin diye), ama t() sessizce
    # (yanlis/eksik metin YERINE) Ingilizce'ye duser.
    assert i18n.get_language() == "de"
    assert i18n.t("window_title") == "TriageChain Console"


def test_bilinmeyen_anahtar_kendisini_doner_asla_patlamaz():
    assert i18n.t("hic_boyle_bir_anahtar_yok") == "hic_boyle_bir_anahtar_yok"


def test_tr_ve_en_ayni_anahtar_kumesine_sahip():
    tr_keys = set(i18n.STRINGS["tr"].keys())
    en_keys = set(i18n.STRINGS["en"].keys())
    assert tr_keys == en_keys
