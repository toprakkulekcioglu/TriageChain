"""Arayuzun renk/tipografi/bosluk sabitleri + uygulama geneli taban QSS.

Desen, kullanicinin chameleon projesindeki `shared/ui_kit/theme_qt.py`
dosyasindan alindi (modul seviyesi sabitler + `base_stylesheet()`), renk
degerleri TriageChain'in kendi kimligine (yesil vurgu) gore secildi.

ONEMLI (chameleon'daki ayni notun karsiligi): bilesenler bu degerleri
KURULUM ANINDA QSS string'ine gomerek okur, canli guncellenmez. Renk degeri
bu dosya disinda hicbir yerde tekrar yazilmaz.

Acik/koyu tema: baslangicta bilerek TEK (koyu) temayla baslanmisti ("acik
tema gercekten istenirse chameleon'daki globals().update() deseni birebir
buraya eklenebilir" notuyla). Kullanici acik temayi istedi -- desen AYNEN
chameleon'dan alindi: DARK/LIGHT sozlukleri + set_mode()/get_mode(),
modul seviyesi degiskenler globals().update() ile guncelleniyor. Widget'lar
degerleri KURULUM ANINDA gomdugu icin (yukarida), tema degisince gorunmesi
icin cagiran taraf (main_window.py::_apply_theme) TUM PENCEREYI (sidebar +
sayfa yigini) yeniden kurmali -- chameleon'daki _apply_theme() ->
_build_shell() deseniyle birebir ayni, bkz. docs/aldigim_kararlar.md.

Kontrast olcumleri (WCAG 2.1, sRGB relative luminance formuluyle
HESAPLANDI -- tahmin degil; acik tema degerleri GitHub Primer'in kendi
YAYIMLANMIS acik tema renk token'larindan turetildi, ayni koyu temanin
Primer koyu temasindan turetilmis olmasi gibi):

  KOYU:
    ACCENT_TEXT (#3FB950) / BG_DARKEST .......... 7.45:1  (AA metin >= 4.5)
    ACCENT_TEXT (#3FB950) / BG_SURFACE .......... 6.81:1
    BORDER (#6A727E)      / BG_LAYER2 ........... 3.24:1  (UI bileseni >= 3.0)
    TEXT_MAIN              / BG_DARKEST .......... 16.02:1
    TEXT_SECONDARY         / BG_SURFACE ........... 5.62:1
    ERROR                  / BG_SURFACE ........... 5.16:1
    TEXT_ON_ACCENT (koyu)  / ACCENT dolgu .......... 7.45:1  (buton yazisi)

  ACIK (Primer acik tema token'lari: success.emphasis/fg, danger.fg,
  attention.fg, accent.fg, fg.default, fg.muted, border.default civari):
    ACCENT_TEXT (#1A7F37) / BG_DARKEST .......... 4.77:1
    ACCENT_TEXT (#1A7F37) / BG_SURFACE .......... 5.08:1
    BORDER (#6A727E, koyuyla AYNI deger) / BG_LAYER2 ... 4.17:1
    TEXT_MAIN (#1F2328)   / BG_DARKEST .......... 14.84:1
    TEXT_SECONDARY (#656D76) / BG_SURFACE ........ 5.25:1
    ERROR (#D1242F)       / BG_SURFACE ........... 5.24:1
    TEXT_ON_ACCENT (beyaz) / ACCENT dolgu (#1A7F37) .. 5.08:1

  TEXT_ON_ACCENT: chameleon'un aksine (orada ACCENT iki temada da AYNI
  deger, beyaz metin ikisinde de yeterli) TriageChain'in koyu temadaki
  acik yesili (#3FB950) acik temada aynen kullanirsa beyaz metin sadece
  ~2.5:1 verirdi -- bu yuzden ACCENT'in KENDISI de tema basina ayri
  (Primer'in success.emphasis/fg ayrimiyla ayni fikir) ve buton yazi
  rengini tasiyan bu YENI token (koyuda BG_DARKEST'e esit, acikta beyaz)
  eklendi. bkz. widgets.py::PrimaryButton.
"""

from pathlib import Path

from PySide6.QtGui import QColor, QFontDatabase

FONT_UI = "Inter"
FONT_MONO = "JetBrains Mono"

# Bu iki font kullanicinin makinesinde KURULU OLMAYABILIR -- gercekten de
# bir turda oyle cikti (Qt sessizce bir yedek fonta dustu, tasarim bozuldu;
# bkz. docs/aldigim_kararlar.md). Bu yuzden gomulu: assets/fonts/ altindaki
# OFL lisansli TTF'ler load_embedded_fonts() ile QApplication kurulur
# kurulmaz yukleniyor (bkz. app.py:main()) -- artik hangi makinede
# calistigindan bagimsiz olarak hep AYNI font kullaniliyor.
_FONTS_DIR = Path(__file__).resolve().parent / "assets" / "fonts"
_EMBEDDED_FONT_FILES = (
    "inter/Inter-Regular.ttf",
    "inter/Inter-Medium.ttf",
    "inter/Inter-SemiBold.ttf",
    "inter/Inter-Bold.ttf",
    "jetbrains_mono/JetBrainsMono-Regular.ttf",
    "jetbrains_mono/JetBrainsMono-Medium.ttf",
    "jetbrains_mono/JetBrainsMono-SemiBold.ttf",
    "jetbrains_mono/JetBrainsMono-Bold.ttf",
)


def load_embedded_fonts() -> list[str]:
    """assets/fonts/ altindaki TTF'leri uygulamaya yukler.

    QApplication KURULDUKTAN SONRA ama pencereler acilmadan once cagrilmali.
    Bir dosya eksik/bozuksa o TEK dosya sessizce atlanir (uygulamayi
    cokertmez) -- dondurulen liste hangi dosyalarin GERCEKTEN yuklendigini
    gosterir, cagiran taraf isterse loglayabilir.
    """
    loaded: list[str] = []
    for relative_path in _EMBEDDED_FONT_FILES:
        path = _FONTS_DIR / relative_path
        if not path.is_file():
            continue
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id != -1:
            loaded.append(relative_path)
    return loaded

SIZE_TITLE = 22
SIZE_BODY = 14
SIZE_HELPER = 12

WEIGHT_REGULAR = 400
WEIGHT_SEMIBOLD = 600

SPACING_UNIT = 8
CARD_PADDING = 24
CARD_GAP = 24
FORM_GAP = 12

# RADIUS onceden 5px'ti ("AI-dashboard hissi yaratmasin" notuyla bilincli
# kucuk tutulmustu). Kullanicinin onayladigi referans tasarim buyuk/yumusak
# koseli kartlar gosterdigi icin bu karar bilerek tersine cevrildi -- bkz.
# docs/aldigim_kararlar.md. RADIUS buyuk yuzeyler (kart, tablo paneli) icin,
# RADIUS_SM kucuk elemanlar (ikon kutusu, sidebar satiri, buton, input) icin.
RADIUS = 14
RADIUS_SM = 10

# Buyuk metrik degerleri (247, 04:12) icin -- normal govde metninden
# kasitli olarak cok daha buyuk/kalin, referans tasarimdaki "hero number"
# hissi icin.
SIZE_METRIC_VALUE = 36
WEIGHT_METRIC_VALUE = 700

# reporting/executive.RISK_LEVELS ile BIREBIR ayni anahtarlar -- GUI ve
# offline HTML raporu ayni risk seviyesini ayni anlamda renklendirsin diye
# (HTML kendi ayri, acik-tema CSS paletini kullanir, ama SIRALAMA/anlam ayni).
_RISK_LABELS = ("Bulgu Yok", "Düşük", "Orta", "Yüksek", "Kritik")

# -- Renk paletleri (tema basina) --------------------------------------------
# Sadece GERCEKTEN tema ile degisen degerler burada; boyut/font/bosluk
# sabitleri (yukarida) her iki temada da AYNI, o yuzden bu sozluklerin
# DISINDA duruyor (chameleon'daki ayni ayrimla ayni).
DARK = {
    "BG_DARKEST": "#0D1117",   # Arka plan (en koyu / ana)
    "BG_SURFACE": "#161B22",   # Kart/panel yuzeyi
    "BG_LAYER2": "#1C2330",    # Ikinci katman (input, hover, ikon kutusu)
    "ACCENT": "#3FB950",
    "ACCENT_HOVER": "#4AC65C",
    "ACCENT_PRESSED": "#34A244",
    # chameleon'da bu token, duz ACCENT'in kucuk metin olarak AA'yi
    # geceMEmesi yuzunden ayri (daha acik) bir tona kaymisti. Burada ayni
    # hesap yapildi ve GEREK OLMADIGI gorildu: yesil #3FB950 hem BG_DARKEST
    # (7.45:1) hem BG_SURFACE (6.81:1) uzerinde AA'nin (4.5:1) cok uzerinde.
    "ACCENT_TEXT": "#3FB950",
    # Buton dolgusu (ACCENT) uzerindeki yazi rengi -- koyu temada dolgu
    # zaten acik oldugu icin EN KOYU arka plan rengiyle ayni (7.45:1).
    "TEXT_ON_ACCENT": "#0D1117",
    "SUCCESS": "#3FB950",
    "WARNING": "#F85149",
    "ERROR": "#F85149",
    # "Yonetici Raporu" risk seviyesi renkleri icin -- geri kalan palet
    # zaten GitHub Primer koyu temasindan geldigi icin (ACCENT/ERROR ayni
    # fg degerleri) bu ikisi de ayni ailenin degerleri: attention.fg ve
    # accent.fg.
    "ATTENTION": "#D29922",
    "INFO": "#58A6FF",
    "TEXT_MAIN": "#E6EDF3",
    "TEXT_SECONDARY": "#8B949E",
    # Ilk onerilen deger #454C56 idi; olculdugunde BG_LAYER2'ye karsi
    # yalnizca 1.82:1 cikti -- WCAG'in UI bilesen sinirlari icin istedigi
    # 3:1'in altinda, yani bir input alaninin nerede basladigi dusuk
    # gorusle ayirt edilemezdi (chameleon'un erisilebilirlik denetiminde
    # ogrendigi ayni ders). Kenarlik/kart siniri/tablo cizgisinin TAMAMI
    # bu tek tokenden geldigi icin buradan duzeltildi: #6A727E ->
    # BG_LAYER2'ye karsi 3.24:1.
    "BORDER": "#6A727E",
}

LIGHT = {
    # GitHub Primer acik tema: canvas.subtle / canvas.default / bir tik
    # daha koyu ikinci katman.
    "BG_DARKEST": "#F6F8FA",   # Ana arka plan (acik temada EN ACIK)
    "BG_SURFACE": "#FFFFFF",
    "BG_LAYER2": "#EAEEF2",
    # Primer'in success.fg'si (#1A7F37) HEM kucuk metin HEM dolgulu buton
    # icin yeterli kontrasti veriyor (bkz. modul basi olcumler) -- iki ayri
    # yesil tonu icat etmek yerine TEK deger kullanildi.
    "ACCENT": "#1A7F37",
    "ACCENT_HOVER": "#186B31",
    "ACCENT_PRESSED": "#145C2A",
    "ACCENT_TEXT": "#1A7F37",
    "TEXT_ON_ACCENT": "#FFFFFF",
    "SUCCESS": "#1A7F37",
    "WARNING": "#D1242F",
    "ERROR": "#D1242F",
    "ATTENTION": "#9A6700",
    "INFO": "#0969DA",
    "TEXT_MAIN": "#1F2328",
    "TEXT_SECONDARY": "#656D76",
    # Koyu temanin BORDER degeriyle (#6A727E) BIREBIR AYNI -- olculdugunde
    # acik temanin ucunun UCUNDE de rahatca 3:1'i gectigi gorildu (BG_LAYER2
    # 4.17:1, BG_SURFACE 4.86:1, BG_DARKEST 4.57:1), ayri bir deger icat
    # etmeye gerek kalmadi.
    "BORDER": "#6A727E",
}

_current_mode = "dark"


def _tint(hex_color: str, alpha: int = 38) -> str:
    """hex rengin dusuk-opakli rgba() string'i -- widgets.py::tint() ile ayni
    hesap, burada AYRI duruyor (theme.py<->widgets.py dongusel import
    olusturmamak icin, bkz. widgets.py'nin bu modulu zaten import etmesi)."""
    color = QColor(hex_color)
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


def set_mode(mode: str) -> None:
    """mode: 'light' ya da 'dark'. Modul degiskenlerini (BG_DARKEST vb.)
    ve bunlardan TURETILEN degerleri (ACCENT_TINT, RISK_COLORS) gunceller.

    Widget'lar bu degerleri KURULUM ANINDA gomdugu icin, cagirdiktan sonra
    zaten var olan widget'lar OTOMATIK degismez -- cagiran taraf
    (main_window.py::_apply_theme) pencereyi yeniden kurmali.
    """
    global _current_mode
    _current_mode = mode if mode in ("light", "dark") else "dark"
    palette = DARK if _current_mode == "dark" else LIGHT
    globals().update(palette)
    # Turetilmis degerler: dogrudan ACCENT/SUCCESS/INFO/ATTENTION/ERROR'a
    # bagli olduklari icin palet degisince ELLE yeniden hesaplanmalilar --
    # globals().update() SADECE yukaridaki sozlukte ADI GECEN anahtarlari
    # gunceller, bu ikisi sozlukte yok.
    globals()["ACCENT_TINT"] = _tint(palette["ACCENT"], 34)
    globals()["RISK_COLORS"] = {
        _RISK_LABELS[0]: palette["SUCCESS"],
        _RISK_LABELS[1]: palette["INFO"],
        _RISK_LABELS[2]: palette["ATTENTION"],
        _RISK_LABELS[3]: palette["ERROR"],
        _RISK_LABELS[4]: palette["ERROR"],
    }


def get_mode() -> str:
    return _current_mode


set_mode("dark")


def base_stylesheet() -> str:
    """QApplication.setStyleSheet ile uygulanan taban QSS.

    Ozel bilesenler (PrimaryButton, Input, Card...) kendi class secicileriyle
    bunun UZERINE ek kural getirir; burasi yalnizca genel gorunumu belirler.
    Tema degisince (set_mode) TEKRAR cagirilip QApplication'a yeniden
    uygulanmali (bkz. main_window.py::_apply_theme).
    """
    return f"""
    QWidget {{
        background-color: {BG_DARKEST};
        color: {TEXT_MAIN};
        font-family: "{FONT_UI}";
        font-size: {SIZE_BODY}px;
    }}

    /* QLabel her zaman kendi konteynerinin (kart, sidebar) arka plani
    uzerinde oturmali -- aksi halde bir kartin icindeki etiket genel
    arka plani miras alip fark edilir bir kutu birakiyor. */
    QLabel {{
        background: transparent;
    }}

    QScrollArea {{
        border: none;
        background-color: transparent;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {BORDER};
        border-radius: 4px;
        min-height: 24px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {TEXT_SECONDARY};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QToolTip {{
        background-color: {BG_LAYER2};
        color: {TEXT_MAIN};
        border: 1px solid {BORDER};
        border-radius: {RADIUS}px;
        padding: 4px 8px;
    }}
    """
