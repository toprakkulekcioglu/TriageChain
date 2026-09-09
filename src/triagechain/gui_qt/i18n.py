"""Basit dil tablosu -- kullanicinin chameleon projesindeki
`shared/i18n/strings.py` deseniyle ayni (STRINGS sozlugu + t(key)
fonksiyonu), TriageChain'in kendi anahtarlariyla.

KAPSAM: pencere cevresi (pencere basligi, sidebar navigasyon etiketleri,
Ayarlar sayfasi) tamamen bu tablodan geciyor -- main_window.py::
SIDEBAR_PAGES/NAV_ICONS artik SABIT (dile bagli olmayan) Ingilizce sayfa
kimlikleriyle ("cases", "custody", "reports", "findings", "files",
"timeline", "settings") calisiyor, GORUNEN etiket i18n.t(f"nav_{id}")'den
geliyor -- ic dispatch mantigi ile goruntulenen metin artik BIRBIRINDEN
BAGIMSIZ. Sayfalarin KENDI icerigi (Dashboard/Bulgular/Raporlar/Vakalar/
Toplanan Dosyalar/Delil Zinciri/Zaman Çizelgesi'nin tablo basliklari,
etiketleri, durum mesajlari) sayfa sayfa tasiniyor -- bkz.
docs/aldigim_kararlar.md'deki ilerleme notlari.

Su an TR (varsayilan) + EN dolu ve DOGRULANMIS (proje sozlugundeki DFIR
terimleriyle tutarli); DE/FR/ES `SUPPORTED_LANGUAGES`'de SECENEK olarak
GORUNUYOR (kullanicinin "5 dil" istegine uygun) ama gercek ceviri
YOK -- secilirse t() sessizce EN'e duser VE Ayarlar sayfasi bunu ACIKCA
bir notla kullaniciya gosterir (sessizce yanlis/eksik metin gostermek
yerine). Gercek DE/FR/ES/PT cevirisi -- adli bilisim terminolojisinin o
dildeki gercek kaynaklara karsi dogrulanmasi (kullanicinin acik istegi:
"kendimiz çevirmeyelim, literatüre uygun olsun") -- ayri bir arastirma
asamasi gerektiriyor, henuz yapilmadi.
"""

from __future__ import annotations

# Sira kullanicinin istedigi sira (TR/EN/ES/DE/PT/FR) -- dict Python
# 3.7+'de EKLENME sirasini korur, iterasyon/dropdown sirasi buradan gelir.
# Her deger (kod, yerel ad) ikilisi -- Ayarlar sayfasindaki acilir listede
# "<KOD> <yerel ad>" biciminde gosteriliyor (orn. "EN English").
SUPPORTED_LANGUAGES: dict[str, str] = {
    "tr": "Türkçe",
    "en": "English",
    "es": "Español",
    "de": "Deutsch",
    "pt": "Português",
    "fr": "Français",
}

# Su an GERCEKTEN cevrilmis diller -- bkz. modul basi not.
_TRANSLATED_LANGUAGES = {"tr", "en"}

STRINGS: dict[str, dict[str, str]] = {
    "tr": {
        "window_title": "TriageChain Konsolu",
        "nav_dashboard": "Dashboard",
        "nav_cases": "Vakalar",
        "nav_custody": "Delil Zinciri",
        "nav_reports": "Raporlar",
        "nav_findings": "Bulgular",
        "nav_files": "Toplanan Dosyalar",
        "nav_timeline": "Zaman Çizelgesi",
        "nav_settings": "Ayarlar",
        "sidebar_section_general": "GENEL",
        "sidebar_active_case": "AKTİF VAKA",
        "sidebar_no_case": "Vaka yüklenmedi",
        "sidebar_footer": "Zincir bütünlüğü izleniyor",
        "settings_title": "Ayarlar",
        "settings_subtitle": "Görünüm ve dil tercihleri -- değişiklik hemen uygulanır.",
        "settings_appearance": "Görünüm",
        "settings_theme_dark": "Koyu",
        "settings_theme_light": "Açık",
        "settings_language_hint": (
            "Türkçe ve İngilizce tam çevrilidir. Arayüzün geri kalanının "
            "(sayfa içerikleri) çevirisi henüz eklenmedi -- şimdilik yalnızca "
            "pencere başlığı ve bu sayfa dile göre değişiyor."
        ),
        "settings_untranslated_notice": (
            "Bu dil için çeviri henüz eklenmedi -- arayüz İngilizce gösteriliyor."
        ),
    },
    "en": {
        "window_title": "TriageChain Console",
        "nav_dashboard": "Dashboard",
        "nav_cases": "Cases",
        "nav_custody": "Chain of Custody",
        "nav_reports": "Reports",
        "nav_findings": "Findings",
        "nav_files": "Collected Files",
        "nav_timeline": "Timeline",
        "nav_settings": "Settings",
        "sidebar_section_general": "GENERAL",
        "sidebar_active_case": "ACTIVE CASE",
        "sidebar_no_case": "No case loaded",
        "sidebar_footer": "Chain integrity monitored",
        "settings_title": "Settings",
        "settings_subtitle": "Appearance and language preferences -- changes apply immediately.",
        "settings_appearance": "Appearance",
        "settings_theme_dark": "Dark",
        "settings_theme_light": "Light",
        "settings_language_hint": (
            "Turkish and English are fully translated. The rest of the "
            "interface (page content) isn't translated yet -- for now only "
            "the window title and this page change with the language."
        ),
        "settings_untranslated_notice": (
            "Translation for this language isn't available yet -- showing "
            "the interface in English."
        ),
    },
}

# Dil secici basliginin ozel durumu: kullanicinin acik istegi -- baslik
# aktif dil ne olursa olsun (henuz cevrilmemis bir dil dahil) o dildeki
# "dil" kelimesini TANIYABILMELI, hep "Language" (Ingilizce, ortak referans)
# ile eslenmis. STRINGS'e KONULMADI cunku degeri _current_language'in HAM
# kodundan (t()'nin dustugu EN'den DEGIL) hesaplanmasi gerekiyor -- bkz.
# language_heading().
_LANGUAGE_WORD_IN_OWN_LANGUAGE: dict[str, str] = {
    "tr": "Dil",
    "en": "Language",
    "es": "Idioma",
    "de": "Sprache",
    "pt": "Idioma",
    "fr": "Langue",
}

_current_language = "tr"


def set_language(lang: str) -> None:
    global _current_language
    _current_language = lang if lang in SUPPORTED_LANGUAGES else "tr"


def language_heading() -> str:
    """Dil secici kartinin basligi: '<aktif dildeki "dil" kelimesi> /
    Language' -- aktif dil zaten Ingilizce'yse tekrar olmasin diye sadece
    'Language' doner."""
    native = _LANGUAGE_WORD_IN_OWN_LANGUAGE.get(_current_language, "Language")
    if native == "Language":
        return "Language"
    return f"{native} / Language"


def get_language() -> str:
    return _current_language


def is_translated(lang: str) -> bool:
    return lang in _TRANSLATED_LANGUAGES


def t(key: str) -> str:
    """Aktif dildeki metni dondurur.

    Aktif dil cevrilmemisse (DE/FR/ES) EN'e duser; EN'de de yoksa anahtarin
    kendisi donuyor -- hicbir zaman patlamaz ya da bos metin gostermez.
    """
    lookup_lang = _current_language if _current_language in _TRANSLATED_LANGUAGES else "en"
    return STRINGS.get(lookup_lang, {}).get(key) or STRINGS["en"].get(key, key)
