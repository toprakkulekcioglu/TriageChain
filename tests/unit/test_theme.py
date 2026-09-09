"""theme.py'nin acik/koyu tema gecisinin (set_mode/get_mode) testleri.

theme modulu SUREC GENELINDE PAYLASILAN modul-seviyesi durum tasiyor --
her test sonunda "dark"a DONDURULUYOR (autouse fixture) ki bu dosyadaki
testler diger test dosyalarinin (orn. test_gui_qt.py) varsaydigi varsayilan
temayi BOZMASIN.
"""

import pytest

from triagechain.gui_qt import theme as t


@pytest.fixture(autouse=True)
def _reset_theme_after_test():
    yield
    t.set_mode("dark")


def test_varsayilan_mod_koyu():
    assert t.get_mode() == "dark"
    assert t.ACCENT == "#3FB950"


def test_set_mode_acik_temaya_geciyor():
    t.set_mode("light")

    assert t.get_mode() == "light"
    assert t.BG_SURFACE == "#FFFFFF"
    assert t.TEXT_MAIN == "#1F2328"


def test_set_mode_gecersiz_deger_koyuya_duser():
    t.set_mode("purple")
    assert t.get_mode() == "dark"


def test_set_mode_dark_ve_light_ayni_anahtar_kumesini_tasir():
    dark_keys = set(t.DARK.keys())
    light_keys = set(t.LIGHT.keys())
    assert dark_keys == light_keys


def test_accent_tint_tema_degisince_yeniden_hesaplanir():
    dark_tint = t.ACCENT_TINT
    t.set_mode("light")
    light_tint = t.ACCENT_TINT

    assert dark_tint != light_tint
    assert light_tint.startswith("rgba(26, 127, 55,")  # #1A7F37'nin RGB'si


def test_risk_colors_tema_degisince_yeniden_hesaplanir():
    assert t.RISK_COLORS["Kritik"] == "#F85149"

    t.set_mode("light")

    assert t.RISK_COLORS["Kritik"] == "#D1242F"
    assert set(t.RISK_COLORS.keys()) == {"Bulgu Yok", "Düşük", "Orta", "Yüksek", "Kritik"}


def test_text_on_accent_iki_temada_da_farkli_ve_dogru():
    assert t.TEXT_ON_ACCENT == t.DARK["BG_DARKEST"]  # koyuda: en koyu renk
    t.set_mode("light")
    assert t.TEXT_ON_ACCENT == "#FFFFFF"


def test_border_iki_temada_da_ayni_deger():
    # Olculdugunde (bkz. aldigim_kararlar.md) ayni gri her iki temada da
    # 3:1'i rahatca geciyor, ayri bir deger icat edilmedi.
    assert t.DARK["BORDER"] == t.LIGHT["BORDER"] == "#6A727E"


def test_base_stylesheet_aktif_temanin_renklerini_kullanir():
    dark_css = t.base_stylesheet()
    assert t.DARK["BG_DARKEST"] in dark_css

    t.set_mode("light")
    light_css = t.base_stylesheet()
    assert t.LIGHT["BG_DARKEST"] in light_css
    assert t.DARK["BG_DARKEST"] not in light_css


# -- WCAG 2.1 kontrast dogrulamasi (acik tema) -------------------------------
# Koyu temanin degerleri onceki oturumlarda dogrulanmisti; acik tema
# BURADA, GERCEK sRGB luminance formuluyle (tahmin degil) dogrulaniyor.

def _contrast(hex1: str, hex2: str) -> float:
    def srgb_to_linear(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def luminance(hex_color: str) -> float:
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
        r, g, b = srgb_to_linear(r), srgb_to_linear(g), srgb_to_linear(b)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    l1, l2 = luminance(hex1), luminance(hex2)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize(
    "fg_key, bg_key, minimum",
    [
        ("ACCENT_TEXT", "BG_DARKEST", 4.5),
        ("ACCENT_TEXT", "BG_SURFACE", 4.5),
        ("TEXT_MAIN", "BG_DARKEST", 4.5),
        ("TEXT_SECONDARY", "BG_SURFACE", 4.5),
        ("ERROR", "BG_SURFACE", 4.5),
        ("ATTENTION", "BG_SURFACE", 4.5),
        ("INFO", "BG_SURFACE", 4.5),
        ("BORDER", "BG_LAYER2", 3.0),
    ],
)
def test_acik_tema_wcag_aa_kontrasti_geciyor(fg_key, bg_key, minimum):
    ratio = _contrast(t.LIGHT[fg_key], t.LIGHT[bg_key])
    assert ratio >= minimum, f"{fg_key}/{bg_key} = {ratio:.2f}:1 (>= {minimum} olmali)"


def test_acik_temada_buton_yazisi_dolguya_karsi_yeterli_kontrast():
    ratio = _contrast(t.LIGHT["TEXT_ON_ACCENT"], t.LIGHT["ACCENT"])
    assert ratio >= 4.5, f"TEXT_ON_ACCENT/ACCENT = {ratio:.2f}:1"
