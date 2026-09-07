"""Arayuzun renk/tipografi/bosluk sabitleri + uygulama geneli taban QSS.

Desen, kullanicinin chameleon projesindeki `shared/ui_kit/theme_qt.py`
dosyasindan alindi (modul seviyesi sabitler + `base_stylesheet()`), renk
degerleri TriageChain'in kendi kimligine (yesil vurgu) gore secildi.

ONEMLI (chameleon'daki ayni notun karsiligi): bilesenler bu degerleri
KURULUM ANINDA QSS string'ine gomerek okur, canli guncellenmez. Renk degeri
bu dosya disinda hicbir yerde tekrar yazilmaz.

Tek tema (koyu): GitHub/Vercel tarzi gelistirici araclarinda oldugu gibi bu
urun her zaman koyu acilir -- HTML maketinde de bu bilincli olarak boyle
yazilmisti. Bu yuzden chameleon'daki `set_mode()`/`get_mode()` ikilisi ve
ikinci (acik) palet BURAYA ALINMADI: kullanilmayan ikinci bir palet, hicbir
ekranin cagirmadigi olu bir esneklik olurdu. Acik tema gercekten istenirse
chameleon'daki `globals().update()` deseni birebir buraya eklenebilir.

Kontrast olcumleri (WCAG 2.1, hepsi bu palet uzerinde HESAPLANDI):
  ACCENT_TEXT (#3FB950) / BG_DARKEST .......... 7.45:1  (AA metin >= 4.5)
  ACCENT_TEXT (#3FB950) / BG_SURFACE .......... 6.81:1
  BORDER (#6A727E)      / BG_LAYER2 ........... 3.24:1  (UI bileseni >= 3.0)
  TEXT_MAIN             / BG_DARKEST .......... 16.02:1
  TEXT_SECONDARY        / BG_SURFACE ........... 5.62:1
  ERROR                 / BG_SURFACE ........... 5.16:1
  BG_DARKEST metin      / ACCENT dolgu ......... 7.45:1  (buton yazisi)
"""

from pathlib import Path

from PySide6.QtGui import QFontDatabase

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

BG_DARKEST = "#0D1117"   # Arka plan (en koyu / ana)
BG_SURFACE = "#161B22"   # Kart/panel yuzeyi
BG_LAYER2 = "#1C2330"    # Ikinci katman (input, hover, ikon kutusu)

ACCENT = "#3FB950"
ACCENT_HOVER = "#4AC65C"
# chameleon'da bu token, duz ACCENT'in kucuk metin olarak AA'yi geceMEmesi
# yuzunden ayri (daha acik) bir tona kaymisti. Burada ayni hesap yapildi ve
# GEREK OLMADIGI gorildu: yesil #3FB950 hem BG_DARKEST (7.45:1) hem
# BG_SURFACE (6.81:1) uzerinde AA'nin (4.5:1) cok uzerinde. Bu yuzden token
# ayri duruyor (kullanim yerleri chameleon'la ayni kalsin diye) ama degeri
# bilincli olarak ACCENT ile ayni.
ACCENT_TEXT = "#3FB950"
ACCENT_TINT = "rgba(63, 185, 80, 0.14)"   # rozet/pill arka plani

SUCCESS = "#3FB950"
WARNING = "#F85149"
ERROR = "#F85149"

# "Yonetici Raporu" risk seviyesi renkleri icin -- geri kalan palet zaten
# GitHub Primer koyu temasindan geldigi icin (ACCENT/ERROR ayni fg degerleri)
# bu ikisi de ayni ailenin degerleri: attention.fg ve accent.fg.
#   ATTENTION (#D29922) / BG_DARKEST .......... 7.50:1
#   ATTENTION (#D29922) / BG_SURFACE ........... 6.85:1
#   INFO      (#58A6FF) / BG_DARKEST .......... 7.49:1
#   INFO      (#58A6FF) / BG_SURFACE ........... 6.85:1
ATTENTION = "#D29922"
INFO = "#58A6FF"

# reporting/executive.RISK_LEVELS ile BIREBIR ayni anahtarlar -- GUI ve
# offline HTML raporu ayni risk seviyesini ayni anlamda renklendirsin diye
# (HTML kendi ayri, acik-tema CSS paletini kullanir, ama SIRALAMA/anlam ayni).
RISK_COLORS = {
    "Bulgu Yok": SUCCESS,
    "Düşük": INFO,
    "Orta": ATTENTION,
    "Yüksek": ERROR,
    "Kritik": ERROR,
}

TEXT_MAIN = "#E6EDF3"
TEXT_SECONDARY = "#8B949E"

# Ilk onerilen deger #454C56 idi; olculdugunde BG_LAYER2'ye karsi yalnizca
# 1.82:1 cikti -- WCAG'in UI bilesen sinirlari icin istedigi 3:1'in altinda,
# yani bir input alaninin nerede basladigi dusuk gorusle ayirt edilemezdi
# (chameleon'un erisilebilirlik denetiminde ogrendigi ayni ders). Kenarlik/
# kart siniri/tablo cizgisinin TAMAMI bu tek tokenden geldigi icin buradan
# duzeltildi: #6A727E -> BG_LAYER2'ye karsi 3.24:1.
BORDER = "#6A727E"


def base_stylesheet() -> str:
    """QApplication.setStyleSheet ile uygulanan taban QSS.

    Ozel bilesenler (PrimaryButton, Input, Card...) kendi class secicileriyle
    bunun UZERINE ek kural getirir; burasi yalnizca genel gorunumu belirler.
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
