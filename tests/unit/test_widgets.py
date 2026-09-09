"""gui_qt/widgets.py bilesenlerinin ekransiz testleri.

test_gui_qt.py ile ayni desen: QT_QPA_PLATFORM=offscreen, gercek pencere
acilmaz.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from triagechain.gui_qt import theme as t  # noqa: E402
from triagechain.gui_qt.widgets import MonoLabel  # noqa: E402


@pytest.fixture(scope="session")
def qt_app():
    return QApplication.instance() or QApplication([])


def test_monolabel_klavye_ile_odaklanabilir(qt_app):
    """Erisilebilirlik: fare kullanmayan biri de metni secebilmeli."""
    label = MonoLabel("abc123")
    assert label.focusPolicy() != 0  # NoFocus degil


def test_monolabel_kendi_focus_stilini_tanimliyor(qt_app):
    """Gercek bir kullanici hatasi: StrongFocus + ozel bir `:focus` QSS
    kurali OLMADAN Qt/Windows kendi ham (markanin yesil paletiyle
    uyusmayan, mavi) varsayilan odak dikdortgenini ciziyordu -- kullanici
    bunu gercek bir ekran goruntusunde bulup bildirdi. Bu test, bilesenin
    KENDI stylesheet'inin ACCENT_TEXT tabanli bir `:focus` kurali
    tasidigini dogrudan dogrular (goruntu karsilastirmasi degil, ama
    regresyonu yakalar)."""
    label = MonoLabel("abc123")
    stylesheet = label.styleSheet()
    assert "QLabel:focus" in stylesheet
    assert t.ACCENT_TEXT in stylesheet
