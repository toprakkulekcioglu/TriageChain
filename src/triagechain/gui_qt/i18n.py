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

Su an ALTI dilin (TR/EN/ES/DE/PT/FR) hepsi bu tablo icin DOLU: pencere
basligi, sidebar navigasyon etiketleri ve Ayarlar sayfasinin kendisi.
Adli bilisimde LITERATURDE YERLESIK terimler kullanildi (orn. "Chain of
Custody" -> DE "Beweismittelkette", ES "Cadena de Custodia", PT "Cadeia
de Custódia", FR "Chaîne de possession" -- kendi uydurulmus bir ceviri
DEGIL, her dilin kendi adli bilisim/hukuk literatüründe zaten kullanilan
karsiliklar).

KAPSAM DISI (hala ACIK): Sayfalarin KENDI icerigi -- Dashboard/Bulgular/
Raporlar/Vakalar/Toplanan Dosyalar/Delil Zinciri/Zaman Çizelgesi'nin
tablo basliklari, etiketleri, durum mesajlari -- BU tabloya dahil DEGIL,
main_window.py'de dogrudan Turkce metin olarak duruyor ve HENUZ hicbir
dile gore degismiyor. Bu, DFIR'a ozgu cok sayida teknik terim (bulgu
seviyeleri, custody olay tipleri, tespit motoru adlari vb.) icerdigi icin
kasitli olarak AYRI, daha buyuk bir asamaya birakildi (bkz.
docs/roadmap.md).
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
_TRANSLATED_LANGUAGES = {"tr", "en", "es", "de", "pt", "fr"}

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
            "Altı dilin hepsi (TR/EN/ES/DE/PT/FR) pencere başlığı, kenar "
            "çubuğu ve bu sayfa için tam çevrilidir. Sayfa içerikleri "
            "(Dashboard, Bulgular vb.) henüz çevrilmedi -- şimdilik yalnızca "
            "bu bölümler dile göre değişiyor."
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
            "All six languages (TR/EN/ES/DE/PT/FR) are fully translated for "
            "the window title, sidebar, and this page. Page content "
            "(Dashboard, Findings, etc.) isn't translated yet -- for now "
            "only these sections change with the language."
        ),
        "settings_untranslated_notice": (
            "Translation for this language isn't available yet -- showing "
            "the interface in English."
        ),
    },
    "es": {
        "window_title": "Consola TriageChain",
        "nav_dashboard": "Panel",
        "nav_cases": "Casos",
        "nav_custody": "Cadena de Custodia",
        "nav_reports": "Informes",
        "nav_findings": "Hallazgos",
        "nav_files": "Archivos Recopilados",
        "nav_timeline": "Cronología",
        "nav_settings": "Configuración",
        "sidebar_section_general": "GENERAL",
        "sidebar_active_case": "CASO ACTIVO",
        "sidebar_no_case": "Ningún caso cargado",
        "sidebar_footer": "Integridad de la cadena monitoreada",
        "settings_title": "Configuración",
        "settings_subtitle": (
            "Preferencias de apariencia e idioma -- los cambios se aplican de inmediato."
        ),
        "settings_appearance": "Apariencia",
        "settings_theme_dark": "Oscuro",
        "settings_theme_light": "Claro",
        "settings_language_hint": (
            "Los seis idiomas (TR/EN/ES/DE/PT/FR) están completamente "
            "traducidos para el título de la ventana, la barra lateral y "
            "esta página. El contenido de las páginas (Dashboard, Hallazgos, "
            "etc.) aún no se ha traducido -- por ahora solo estas secciones "
            "cambian según el idioma."
        ),
        "settings_untranslated_notice": (
            "Aún no hay traducción disponible para este idioma -- la "
            "interfaz se muestra en inglés."
        ),
    },
    "de": {
        "window_title": "TriageChain-Konsole",
        "nav_dashboard": "Dashboard",
        "nav_cases": "Fälle",
        "nav_custody": "Beweismittelkette",
        "nav_reports": "Berichte",
        "nav_findings": "Befunde",
        "nav_files": "Gesammelte Dateien",
        "nav_timeline": "Zeitachse",
        "nav_settings": "Einstellungen",
        "sidebar_section_general": "ALLGEMEIN",
        "sidebar_active_case": "AKTIVER FALL",
        "sidebar_no_case": "Kein Fall geladen",
        "sidebar_footer": "Kettenintegrität wird überwacht",
        "settings_title": "Einstellungen",
        "settings_subtitle": (
            "Anzeige- und Spracheinstellungen -- Änderungen werden sofort übernommen."
        ),
        "settings_appearance": "Erscheinungsbild",
        "settings_theme_dark": "Dunkel",
        "settings_theme_light": "Hell",
        "settings_language_hint": (
            "Alle sechs Sprachen (TR/EN/ES/DE/PT/FR) sind für den "
            "Fenstertitel, die Seitenleiste und diese Seite vollständig "
            "übersetzt. Die Seiteninhalte (Dashboard, Befunde usw.) sind "
            "noch nicht übersetzt -- vorerst ändern sich nur diese Bereiche "
            "je nach Sprache."
        ),
        "settings_untranslated_notice": (
            "Für diese Sprache ist noch keine Übersetzung verfügbar -- die "
            "Oberfläche wird auf Englisch angezeigt."
        ),
    },
    "pt": {
        "window_title": "Console TriageChain",
        "nav_dashboard": "Painel",
        "nav_cases": "Casos",
        "nav_custody": "Cadeia de Custódia",
        "nav_reports": "Relatórios",
        "nav_findings": "Achados",
        "nav_files": "Arquivos Coletados",
        "nav_timeline": "Linha do Tempo",
        "nav_settings": "Configurações",
        "sidebar_section_general": "GERAL",
        "sidebar_active_case": "CASO ATIVO",
        "sidebar_no_case": "Nenhum caso carregado",
        "sidebar_footer": "Integridade da cadeia monitorada",
        "settings_title": "Configurações",
        "settings_subtitle": (
            "Preferências de aparência e idioma -- as alterações são aplicadas imediatamente."
        ),
        "settings_appearance": "Aparência",
        "settings_theme_dark": "Escuro",
        "settings_theme_light": "Claro",
        "settings_language_hint": (
            "Os seis idiomas (TR/EN/ES/DE/PT/FR) estão totalmente "
            "traduzidos para o título da janela, a barra lateral e esta "
            "página. O conteúdo das páginas (Dashboard, Achados etc.) ainda "
            "não foi traduzido -- por enquanto, apenas essas seções mudam "
            "de acordo com o idioma."
        ),
        "settings_untranslated_notice": (
            "Ainda não há tradução disponível para este idioma -- a "
            "interface é exibida em inglês."
        ),
    },
    "fr": {
        "window_title": "Console TriageChain",
        "nav_dashboard": "Tableau de Bord",
        "nav_cases": "Dossiers",
        "nav_custody": "Chaîne de Possession",
        "nav_reports": "Rapports",
        "nav_findings": "Constatations",
        "nav_files": "Fichiers Collectés",
        "nav_timeline": "Chronologie",
        "nav_settings": "Paramètres",
        "sidebar_section_general": "GÉNÉRAL",
        "sidebar_active_case": "DOSSIER ACTIF",
        "sidebar_no_case": "Aucun dossier chargé",
        "sidebar_footer": "Intégrité de la chaîne surveillée",
        "settings_title": "Paramètres",
        "settings_subtitle": (
            "Préférences d'apparence et de langue -- les modifications s'appliquent immédiatement."
        ),
        "settings_appearance": "Apparence",
        "settings_theme_dark": "Sombre",
        "settings_theme_light": "Clair",
        "settings_language_hint": (
            "Les six langues (TR/EN/ES/DE/PT/FR) sont entièrement traduites "
            "pour le titre de la fenêtre, la barre latérale et cette page. "
            "Le contenu des pages (Dashboard, Constatations, etc.) n'est "
            "pas encore traduit -- pour l'instant, seules ces sections "
            "changent selon la langue."
        ),
        "settings_untranslated_notice": (
            "Aucune traduction n'est encore disponible pour cette langue -- "
            "l'interface s'affiche en anglais."
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
