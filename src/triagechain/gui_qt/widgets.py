"""Tasarim sistemine uygun, tekrar kullanilabilir PySide6 bilesenleri.

Ekranlar duz QPushButton/QLineEdit yerine bunlari kullanir; renk/tipografi/
bosluk degerleri SADECE theme.py'de tanimli, burada tekrar yazilmaz. Sinif
isimleri ve davranislari kullanicinin chameleon projesindeki
`shared/ui_kit/widgets.py` ile birebir ayni tutuldu -- iki proje arasinda
gecis yapan biri ayni API'yi bulsun diye.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from triagechain.gui_qt import theme as t


def tint(hex_color: str, alpha: int = 38) -> str:
    """hex rengin dusuk-opakli 'pill' arka plani icin rgba() string'i.

    Qt QSS'de alpha 0-255 araliginda (CSS'teki 0-1 degil).
    """
    color = QColor(hex_color)
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


# ---------------------------------------------------------------------------
# Butonlar -- normal / hover / pressed / disabled, 4 net durum
# ---------------------------------------------------------------------------
class PrimaryButton(QPushButton):
    """Ana aksiyon butonu (marka rengi dolu).

    Yazi rengi chameleon'daki gibi SABIT BEYAZ DEGIL, TEXT_ON_ACCENT
    tokeni: koyu temada ACCENT (#3FB950) acik bir yesil oldugu icin en koyu
    arka plan rengiyle 7.45:1 veriyor (beyaz olsaydi sadece 2.54:1); acik
    temada ACCENT (#1A7F37) yeterince koyu oldugu icin beyaz 5.08:1 veriyor
    -- bkz. theme.py modul basi olcumler.
    """

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(36)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {t.ACCENT};
                color: {t.TEXT_ON_ACCENT};
                border: none;
                border-radius: {t.RADIUS_SM}px;
                padding: 6px 18px;
                font-family: "{t.FONT_UI}";
                font-size: {t.SIZE_BODY}px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {t.ACCENT_HOVER}; }}
            QPushButton:pressed {{ background-color: {t.ACCENT_PRESSED}; }}
            QPushButton:disabled {{ background-color: {t.BG_LAYER2}; color: {t.TEXT_SECONDARY}; }}
            /* Odak halkasi da dolgunun kendisine karsi ayirt edilebilmeli:
            TEXT_ON_ACCENT zaten dolguya karsi yeterli kontrasti tasiyor
            (bkz. yukaridaki not) -- ayni rengi burada da kullaniyoruz. */
            QPushButton:focus {{ border: 2px solid {t.TEXT_ON_ACCENT}; padding: 5px 17px; }}
        """)


class SecondaryButton(QPushButton):
    """Ikincil aksiyon: kenarlikli, dolgusuz -- gorsel olarak geride durur."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(36)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {t.TEXT_MAIN};
                border: 1px solid {t.BORDER};
                border-radius: {t.RADIUS_SM}px;
                padding: 6px 18px;
                font-family: "{t.FONT_UI}";
                font-size: {t.SIZE_BODY}px;
            }}
            QPushButton:hover {{ background-color: {t.BG_LAYER2}; }}
            QPushButton:pressed {{ background-color: {t.BG_SURFACE}; }}
            QPushButton:disabled {{ color: {t.TEXT_SECONDARY}; border-color: {t.BG_LAYER2}; }}
            QPushButton:focus {{ border: 2px solid {t.ACCENT_TEXT}; padding: 5px 17px; }}
        """)


# ---------------------------------------------------------------------------
# Girdi alanlari -- focus'ta kenarlik marka rengine doner + hafif glow
# ---------------------------------------------------------------------------
class Input(QLineEdit):
    """Genel metin girisi. Teknik degerler (yol/hash/vaka no) icin MonoInput."""

    def __init__(self, placeholder: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        if placeholder:
            self.setPlaceholderText(placeholder)
        self.setMinimumHeight(32)
        self._apply_style(focused=False)
        self._glow = QGraphicsDropShadowEffect(self)
        self._glow.setColor(QColor(t.ACCENT_TEXT))
        self._glow.setBlurRadius(0)
        self._glow.setOffset(0, 0)
        self.setGraphicsEffect(self._glow)

    def _font_family(self) -> str:
        return t.FONT_UI

    def _apply_style(self, focused: bool) -> None:
        # Odaklaninca kenarlik hem yesile doner hem 1px'ten 2px'e cikar --
        # odagin nerede oldugu dusuk gorusle de fark edilebilsin diye
        # (ACCENT'in BG_LAYER2'ye karsi kontrasti 6.20:1).
        border_color = t.ACCENT_TEXT if focused else t.BORDER
        border_width = 2 if focused else 1
        h_pad = 10 if focused else 11
        v_pad = 3 if focused else 4
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: {t.BG_LAYER2};
                color: {t.TEXT_MAIN};
                border: {border_width}px solid {border_color};
                border-radius: {t.RADIUS_SM}px;
                padding: {v_pad}px {h_pad}px;
                font-family: "{self._font_family()}";
                font-size: {t.SIZE_BODY}px;
            }}
            QLineEdit:disabled {{ color: {t.TEXT_SECONDARY}; }}
        """)

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        self._apply_style(focused=True)
        self._glow.setBlurRadius(14)  # hafif glow, abartisiz

    def focusOutEvent(self, event) -> None:
        super().focusOutEvent(event)
        self._apply_style(focused=False)
        self._glow.setBlurRadius(0)


class MonoInput(Input):
    """Yol, vaka no, SHA-256 gibi teknik degerler icin -- JetBrains Mono."""

    def _font_family(self) -> str:
        return t.FONT_MONO


class MonoLabel(QLabel):
    """Salt-okunur teknik deger gosterimi (orn. entry_hash) icin.

    Klavye ile de secilebilir: hash gibi bir degeri fare kullanmayan biri de
    kopyalayabilmeli (chameleon'un erisilebilirlik denetiminde bulunmustu;
    TextInteractionFlags tek basina yetmiyor, FocusPolicy de gerekiyor).

    ONEMLI: StrongFocus'un kendisi bir `:focus` QSS kurali GEREKTIRIR --
    yoksa Qt/Windows kendi HAM (uygulamanin yesil paletiyle hic
    uyusmayan, mavi) varsayilan odak dikdortgenini ciziyor. Kullanici
    gercek bir ekran goruntusunde bunu ("tasarim sirittiginda/bagirdiginda")
    bulup bildirdi -- sidebar'daki vaka kimligi kutusunu SARAN, markaya
    uymayan mavi bir cerceve olarak gorunuyordu (bkz. aldigim_kararlar.md).
    """

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setStyleSheet(f"""
            QLabel {{
                color: {t.TEXT_SECONDARY};
                font-family: "{t.FONT_MONO}";
                font-size: {t.SIZE_HELPER}px;
                background: transparent;
                border: 1px solid transparent;
                border-radius: {t.RADIUS_SM}px;
            }}
            QLabel:focus {{
                border: 1px solid {t.ACCENT_TEXT};
            }}
        """)
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)


# ---------------------------------------------------------------------------
# Durum rozeti -- renkli nokta + kisa metin, soluk renkli pill zemin
# ---------------------------------------------------------------------------
class StatusBadge(QWidget):
    """'● Zincir Geçerli' gibi durum gostergeleri icin pill/rozet.

    set_status(color_hex, text) ile guncellenir; hem sayfa basligindaki
    zincir durumu hem tablo satirlarindaki Doğrulandı/Şüpheli hucreleri
    ayni bileseni kullanir.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        # QWidget stylesheet'teki background/border-radius'u ancak bu
        # ozellikle boyar (QFrame'in aksine varsayilan olarak boyamiyor).
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(30)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 14, 0)
        layout.setSpacing(7)

        self._dot = QLabel("●")
        self._label = QLabel()
        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        self.set_status(t.TEXT_SECONDARY, "—")

    def set_status(self, color: str, text: str) -> None:
        # Referans tasarimdaki gibi daha "dolu"/belirgin bir pill: soluk
        # tint yerine biraz daha yogun bir zemin + ayni renkte ince kenarlik.
        self.setStyleSheet(f"""
            StatusBadge {{
                background-color: {tint(color, 30)};
                border: 1px solid {tint(color, 90)};
                border-radius: 15px;
            }}
        """)
        dot_css = (
            f"color: {color}; font-family: '{t.FONT_UI}'; "
            f"font-size: 10px; background: transparent;"
        )
        self._dot.setStyleSheet(dot_css)
        self._label.setStyleSheet(
            f"color: {color}; font-family: '{t.FONT_UI}'; "
            f"font-size: {t.SIZE_HELPER}px; font-weight: 700; background: transparent;"
        )
        self._label.setText(text)

    def text(self) -> str:
        """Testlerin ve cagiranin okuyabilmesi icin gosterilen metin."""
        return self._label.text()


# ---------------------------------------------------------------------------
# Ilerleme cubugu -- belirli (%) + belirsiz (indeterminate) mod
# ---------------------------------------------------------------------------
class ProgressBar(QProgressBar):
    """Islem surerken SESSIZ BEKLEME olmasin diye.

    Yuzde biliniyorsa set_determinate(pct), bilinmiyorsa set_indeterminate()
    ile Qt'nin kendi "busy" animasyonuna gecilir (min=0, max=0).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setTextVisible(False)
        self.setMinimumHeight(6)
        self.setMaximumHeight(6)
        self.setStyleSheet(f"""
            QProgressBar {{
                background-color: {t.BG_LAYER2};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {t.ACCENT};
                border-radius: 3px;
            }}
        """)
        self.set_determinate(0)

    def set_determinate(self, percent: float) -> None:
        if self.minimum() != 0 or self.maximum() != 100:
            self.setRange(0, 100)
        self.setValue(max(0, min(100, int(percent))))

    def set_indeterminate(self) -> None:
        self.setRange(0, 0)


# ---------------------------------------------------------------------------
# Sparkline -- kucuk cizgi+alan grafigi, HTML maketteki `.sparkline` ile
# birebir ayni gorsel dil (alan dolgusu + cizgi + vurgulanmis son nokta)
# ---------------------------------------------------------------------------
class Sparkline(QWidget):
    """Metrik kartlarinin altindaki mini trend grafigi.

    Veri GERCEK olmali -- bu widget hicbir sey UYDURMAZ, sadece `set_values()`
    ile verileni cizer. 2'den az nokta varsa (ya da hic veri yoksa) veri
    yokmus gibi bos bir grafik CIZMEK yerine, durumu acikca gosteren duz,
    notrsuz bir cizgi cizilir -- boylece kucuk/erken bir vaka icin sahte bir
    egilim goruntusu yaratilmaz (bkz. cagiranin kendi yorumu, main_window.py).
    """

    def __init__(self, color: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._color = QColor(color)
        self._values: list[float] = []
        self.setFixedHeight(36)

    def set_values(self, values: list[float]) -> None:
        self._values = list(values)
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 (Qt'nin kendi ismi)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width, height = self.width(), self.height()
        top_pad, bottom_pad = 3, 4

        if len(self._values) < 2:
            painter.setPen(QPen(QColor(t.BORDER), 1))
            painter.drawLine(0, height - bottom_pad, width, height - bottom_pad)
            painter.end()
            return

        lo, hi = min(self._values), max(self._values)
        span = (hi - lo) or 1.0
        count = len(self._values)
        points = [
            QPointF(
                (i / (count - 1)) * width,
                height - bottom_pad - ((value - lo) / span) * (height - top_pad - bottom_pad),
            )
            for i, value in enumerate(self._values)
        ]

        fill_path = QPainterPath()
        fill_path.moveTo(points[0].x(), height)
        for point in points:
            fill_path.lineTo(point)
        fill_path.lineTo(points[-1].x(), height)
        fill_path.closeSubpath()
        fill_color = QColor(self._color)
        fill_color.setAlphaF(0.20)
        painter.fillPath(fill_path, fill_color)

        painter.setPen(QPen(self._color, 1.8))
        for start, end in zip(points, points[1:]):
            painter.drawLine(start, end)

        # Son noktanin etrafinda yumusak bir "glow" halkasi -- referans
        # tasarimdaki parlak uc nokta hissi icin; asil nokta ustte, halka
        # sadece onun cevresinde soluk bir ekran.
        glow = QColor(self._color)
        glow.setAlphaF(0.22)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(points[-1], 6.0, 6.0)
        painter.setBrush(self._color)
        painter.drawEllipse(points[-1], 2.8, 2.8)
        painter.end()


# ---------------------------------------------------------------------------
# Kart -- (istege bagli) basligi olan, kenarlikli/koseli panel
# ---------------------------------------------------------------------------
class Card(QFrame):
    """Kenarlikli panel; icerik .body layout'una eklenir."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(f"""
            Card {{
                background-color: {t.BG_SURFACE};
                border: 1px solid {t.BORDER};
                border-radius: {t.RADIUS}px;
            }}
        """)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(t.CARD_PADDING, t.CARD_PADDING, t.CARD_PADDING, t.CARD_PADDING)
        outer.setSpacing(t.FORM_GAP)

        if title:
            # Referans tasarimda panel basligi kucuk yesil BUYUK HARF bir
            # etiket degil, normal-case kalin beyaz bir baslik -- kartin
            # kendisiyle ayni gorsel agirlikta.
            label = QLabel(title)
            label.setStyleSheet(f"""
                color: {t.TEXT_MAIN};
                font-family: "{t.FONT_UI}";
                font-size: 16px;
                font-weight: 600;
                background: transparent;
            """)
            outer.addWidget(label)

        self.body = QVBoxLayout()
        self.body.setSpacing(t.FORM_GAP)
        outer.addLayout(self.body)
