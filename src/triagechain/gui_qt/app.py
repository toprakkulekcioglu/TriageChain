"""GUI giris noktasi -- `triagechain-gui` konsol komutu burayi cagirir."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from triagechain.gui_qt import icons, theme
from triagechain.gui_qt.main_window import TriageChainWindow


def main() -> int:
    """QApplication'i kurar, gomulu fontlari yukler, taban QSS'i uygular ve pencereyi acar."""
    # QApplication'dan ONCE ayarlanmali. Kesirli ekran olcegi (%125/%150 gibi
    # tam sayi olmayan carpanlar) kullanan monitorlerde Qt'nin VARSAYILAN
    # yuvarlama politikasi, widget'in DUSUNDUGU boyutla Windows'un GERCEKTE
    # cizdigi boyut arasinda kucuk bir fark yaratabiliyor -- bu da pencere
    # cercevesinin (baslik cubugu + native kapat dugmesi dahil) ekranin
    # gercek sinirina gore hafifce kaymis/tasmis gorunmesine yol aciyor.
    # PassThrough, Qt'ye olcegi YUVARLAMADAN oldugu gibi kullanmasini
    # soyleyip bu uyusmazligi ortadan kaldirir (bkz. Qt belgeleri).
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("TriageChain")
    # Windows'ta varsayilan "windowsvista"/"windows11" native stili, agir
    # QSS temalarini (ozellikle QPushButton/QLineEdit'in disabled/hover
    # durumlari) TUTARSIZ uyguluyor -- native "chrome" QSS'in ALTINDAN
    # sizip acik/beyaz bir gorunum birakabiliyor (gercek ekran goruntusuyle
    # referans tasarimla karsilastirirken bulundu, bkz. aldigim_kararlar.md).
    # "Fusion", Qt'nin QSS'i platform bagimsiz ve TAM olarak uyguladigi
    # cizim stili -- bu yuzden herhangi bir widget kurulmadan ONCE, acikca
    # secilir.
    app.setStyle("Fusion")
    # QApplication'dan SONRA, herhangi bir widget olusturulmadan ONCE --
    # QFontDatabase QApplication'a ihtiyac duyar, widget'lar ise fontu
    # kurulumda okur (bkz. theme.py basindaki not).
    theme.load_embedded_fonts()
    app.setStyleSheet(theme.base_stylesheet())
    # QApplication uzerinde ayarlanan ikon TUM pencerelere (ve gorev
    # cubugu gruplamasina) varsayilan olarak uygulanir -- her pencerede
    # ayrica setWindowIcon cagirmaya gerek yok.
    app.setWindowIcon(icons.app_icon())

    window = TriageChainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
