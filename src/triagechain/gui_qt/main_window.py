"""TriageChain masaustu arayuzunun ana penceresi.

Yapisi chameleon'un launcher'iyla ayni: solda sabit sidebar, sagda
QStackedWidget ile degisen icerik. Alti sayfanin (Dashboard, Toplanan
Dosyalar, Delil Zinciri, Bulgular, Raporlar, Vakalar) hepsi tam islevsel;
yer tutucu sayfa kalmadi.

Bu dosya IS MANTIGI ICERMEZ: dort aksiyon zaten var olan CLI/kutuphane
fonksiyonlarini (run_collection / run_router / run_detection / build_report)
cagirir, Dashboard verisi de diskteki manifest/defter dosyalarindan TEKRAR
OKUNARAK tazelenir -- yani hicbir sayi arayuzde ayrica hesaplanmiyor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from triagechain.collection.collector import run_collection
from triagechain.collection.models import CollectionManifest
from triagechain.config.loader import (
    load_config,
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_report_path,
    resolve_routing_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.core.errors import TriageChainError
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.capa_runner import run_capa_scan
from triagechain.detection.chainsaw_runner import run_chainsaw_detection
from triagechain.detection.correlation import correlate_findings, correlate_sigma_engines
from triagechain.detection.models import DetectionManifest, YaraManifest
from triagechain.detection.runner import run_detection
from triagechain.detection.yara_runner import run_yara_scan
from triagechain.gui_qt import icons
from triagechain.gui_qt import theme as t
from triagechain.gui_qt.widgets import (
    Card,
    MonoLabel,
    PrimaryButton,
    ProgressBar,
    SecondaryButton,
    Sparkline,
    StatusBadge,
    tint,
)
from triagechain.reporting.builder import build_report, write_report
from triagechain.reporting.executive import build_executive_summary
from triagechain.reporting.models import Report
from triagechain.router.models import RoutingManifest
from triagechain.router.runner import run_router

# Defterdeki ham olay tipleri kullaniciya Turkcelestirilerek gosterilir;
# burada olmayan bir tip (ileride eklenen yeni bir olay) ham haliyle
# gosterilir -- tablo asla bos hucre birakmaz.
EVENT_LABELS = {
    "case_opened": "Vaka Açıldı",
    "case_closed": "Vaka Kapatıldı",
    "artifact_collected": "Dosya Toplandı",
    "collection_error": "Toplama Hatası",
    "integrity_error": "Bütünlük İhlali",
    "routing_started": "Yönlendirme Başladı",
    "routing_completed": "Yönlendirme Bitti",
    "artifact_processed": "Dosya İşlendi",
    "processing_skipped": "İşleme Atlandı",
    "processing_error": "İşleme Hatası",
    "detection_started": "Tarama Başladı",
    "detection_completed": "Tarama Bitti",
    "detection_completed_for_artifact": "Olay Günlüğü Tarandı",
    "detection_skipped": "Tarama Atlandı",
    "detection_error": "Tarama Hatası",
}

# Defter yuzlerce olay tasiyabilir; tabloya yalnizca son bu kadari yazilir.
MAX_TABLE_ROWS = 50

# Olay tipine gore tablo hucresindeki kucuk ikon (bkz. icons.py) - kesin bir
# siniflandirma degil, sadece goze hizli bir ipucu.
_ERROR_ICON = "alert-triangle"
_EVENT_ICONS = {
    "case_opened": "clock",
    "case_closed": "check-circle",
    "artifact_collected": "files",
    "collection_error": _ERROR_ICON,
    "integrity_error": _ERROR_ICON,
    "routing_started": "clock",
    "routing_completed": "check-circle",
    "artifact_processed": "files",
    "processing_skipped": "alert-triangle",
    "processing_error": _ERROR_ICON,
    "detection_started": "clock",
    "detection_completed": "check-circle",
    "detection_completed_for_artifact": "files",
    "detection_skipped": "alert-triangle",
    "detection_error": _ERROR_ICON,
}


def _event_detail(event) -> str:
    """Olayin payload'undan, tabloda ikinci (soluk) satir olarak gosterilecek
    kisa bir ozet cikarir. Hicbir alan uymuyorsa bos doner -- bu bir hata
    degil, her olay tipi ayni detay bicimini tasimiyor."""
    payload = event.payload or {}
    if event.event_type == "artifact_collected":
        return str(payload.get("artifact_type_id", ""))
    if event.event_type == "artifact_processed":
        tool = payload.get("tool", "")
        artifact_type = payload.get("artifact_type_id", "")
        return f"{artifact_type} → {tool}" if tool else artifact_type
    if event.event_type == "detection_completed_for_artifact":
        count = payload.get("finding_count")
        return f"{count} bulgu" if count is not None else ""
    if event.event_type in ("routing_started", "detection_started"):
        count = payload.get("artifact_count")
        return f"{count} artefakt" if count is not None else ""
    if event.event_type in ("case_closed", "routing_completed", "detection_completed"):
        for key in ("artifact_count", "processed_count", "finding_count"):
            if key in payload:
                return f"{payload[key]} {key.replace('_count', '')}"
        return ""
    if "message" in payload:
        message = str(payload["message"])
        return message if len(message) <= 60 else message[:57] + "…"
    return ""

# Dashboard disindaki sidebar sayfalari, gosterilis sirasiyla -- hepsi artik
# gercek sayfa (yer tutucu kalmadi).
SIDEBAR_PAGES = ("Vakalar", "Delil Zinciri", "Raporlar", "Bulgular", "Toplanan Dosyalar")

# Sidebar'daki her sayfa satirinin solundaki ikon (bkz. assets/icons/*.svg).
NAV_ICONS = {
    "Dashboard": "grid",
    "Vakalar": "folder",
    "Delil Zinciri": "link-2",
    "Raporlar": "file-text",
    "Bulgular": "search",
    "Toplanan Dosyalar": "database",
}


# ---------------------------------------------------------------------------
# Diskten okunan vaka durumu
# ---------------------------------------------------------------------------
@dataclass
class CaseSnapshot:
    """Dashboard'un gosterdigi her sey: tek seferde diskten okunmus hali."""

    artifact_count: Optional[int] = None
    duration_text: Optional[str] = None
    finding_count: Optional[int] = None
    has_manifest: bool = False
    chain_valid: Optional[bool] = None   # None = defter henuz yok
    chain_message: str = ""
    chain_total: int = 0
    # Zincirin kirildigi olayin sirasi (1'den baslar); saglamsa None.
    broken_at_index: Optional[int] = None
    events: list = field(default_factory=list)
    # Okunamayan bir dosya varsa kullaniciya gosterilecek kisa not.
    warning: str = ""

    # "Toplanan Dosyalar" sayfasi icin: manifestteki TAM artefakt/hata
    # listesi (Dashboard'daki gibi sadece sayi degil, her satirin kendisi).
    artifacts: list = field(default_factory=list)
    collection_errors: list = field(default_factory=list)

    # "Bulgular" sayfasi icin: tespit manifestindeki TAM bulgu listesi.
    findings: list = field(default_factory=list)

    # "Bulgular" sayfasi icin: YARA tarama manifestindeki TAM eslesme
    # listesi + iki motorun kesisimi (bkz. detection/correlation.py).
    yara_matches: list = field(default_factory=list)
    correlated_artifacts: list = field(default_factory=list)

    # "Bulgular" sayfasi icin: Chainsaw manifestindeki TAM bulgu listesi
    # (Hayabusa ile AYNI Finding semasi) + iki Sigma motorunun ittifaki
    # (bkz. detection/correlation.py::correlate_sigma_engines).
    chainsaw_findings: list = field(default_factory=list)
    engine_agreements: list = field(default_factory=list)

    # "Bulgular" sayfasi icin: capa manifestindeki TAM yetenek-eslesme listesi
    # -- YARA ile AYNI YaraMatch semasini kullanir (bkz. detection/
    # capa_runner.py), risk/korelasyona KATILMAZ (bkz. reporting/executive.py).
    capa_matches: list = field(default_factory=list)

    # "Raporlar" sayfasi icin: en son uretilmis report.json (varsa). Tek
    # bir rapor tutuluyor -- write_report() her calistiginda UZERINE yazar,
    # gecmis surum listesi YOK (bkz. reporting/builder.py).
    report: Optional[Report] = None
    report_path_note: str = ""

    # Metrik kartlarinin altindaki mini grafikler + kucuk delta metni.
    # HEPSI gercek diskteki veriden turetilir, hicbiri uydurulmaz -- bkz.
    # read_snapshot() ve Sparkline'in kendi docstring'i.
    files_trend: list = field(default_factory=list)
    files_delta: str = ""
    duration_trend: list = field(default_factory=list)
    duration_delta: str = ""
    findings_trend: list = field(default_factory=list)
    findings_delta: str = ""


def _human_size(num_bytes: int) -> str:
    """Byte sayisini KB/MB/GB'a cevirir (ikili -- 1024 tabanli)."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


    # QTableWidget::item { padding: ... } (bkz. _style_ledger_table) dikey
    # dolgusu -- Qt bunu setCellWidget() ile konan ozel widget'larin
    # KULLANILABILIR YUKSEKLIGINDEN de dusuyor (QTableWidgetItem'a ozel
    # olmasi beklenirdi ama oyle degil). Bu yuzden satir yuksekligi hesabina
    # geri EKLENMESI gerekiyor -- bkz. _fit_rows_to_cell_widgets.
_TABLE_ITEM_VPADDING = 13


def _fit_rows_to_cell_widgets(table: QTableWidget, column: int = 0) -> None:
    """`table.resizeRowsToContents()` yerine kullanilir.

    Kok neden bulundu: `_style_ledger_table`'daki `QTableWidget::item {
    padding: 13px 10px; }` kurali, setCellWidget() ile konan ozel
    widget'larin (bkz. _build_event_cell vb.) kullanilabilir yuksekligini de
    ayni miktarda kisitliyor -- bu yuzden resizeRowsToContents() (ve duz
    setRowHeight(sizeHint)) satiri, ikon kutusunu/metni gosteremeyecek kadar
    kisa (0-1px etiket yuksekligi) birakiyordu. `_TABLE_ITEM_VPADDING * 2`
    (ust+alt) geri eklenerek widget'a gercekten ihtiyaci kadar yer aciliyor.
    """
    for row in range(table.rowCount()):
        widget = table.cellWidget(row, column)
        if widget is not None:
            table.setRowHeight(row, widget.sizeHint().height() + _TABLE_ITEM_VPADDING * 2)


def _style_ledger_table(table: QTableWidget) -> None:
    """Custody/Dosya tablolarinin ortak gorunumu -- uc ayri yerde (Dashboard
    mini tablo, Toplanan Dosyalar, Delil Zinciri tam sayfasi) tekrar
    yazilmasin diye tek yerde."""
    table.verticalHeader().setVisible(False)
    table.setShowGrid(False)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setAlternatingRowColors(False)
    table.setStyleSheet(f"""
        QTableWidget {{
            background-color: {t.BG_SURFACE};
            border: none;
            gridline-color: {t.BORDER};
            font-size: 13px;
        }}
        QTableWidget::item {{
            padding: {_TABLE_ITEM_VPADDING}px 10px;
            border-bottom: 1px solid {t.BG_LAYER2};
            color: {t.TEXT_MAIN};
        }}
        QHeaderView::section {{
            background-color: {t.BG_SURFACE};
            color: {t.TEXT_SECONDARY};
            border: none;
            border-bottom: 1px solid {t.BORDER};
            padding: 10px 10px;
            font-size: 11px;
            font-weight: 600;
        }}
    """)


def _duration_text(started: datetime, ended: Optional[datetime]) -> Optional[str]:
    """Iki zaman damgasi arasini mm:ss (gerekirse s:mm:ss) olarak yazar."""
    if ended is None:
        return None
    total = int((ended - started).total_seconds())
    if total < 0:
        return None
    hours, rest = divmod(total, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def read_snapshot(config) -> CaseSnapshot:
    """Vakanin diskteki ciktilarindan Dashboard verisini toplar.

    Hicbir dosya zorunlu degil: yalnizca toplama yapilmis bir vakada da,
    hic calistirilmamis bir vakada da coksuz calisir.
    """
    snapshot = CaseSnapshot()
    warnings: list[str] = []

    # Tamamlanmis fazlarin sure/etiketini biriktirir -> "Islem Suresi" karti
    # hem toplam sureyi hem de HANGI fazlarin bittigini gercek veriden
    # gosterebilsin diye (sure sparkline'i = her fazin kendi suresi, saniye).
    phase_labels: list[str] = []
    phase_seconds: list[float] = []

    # 1) Toplama manifesti -> dosya sayisi, kumulatif toplama egrisi, sure
    latest_end: Optional[datetime] = None
    manifest_path = resolve_manifest_path(config)
    if manifest_path.is_file():
        try:
            manifest = CollectionManifest.from_json_file(manifest_path)
            snapshot.has_manifest = True
            snapshot.artifact_count = len(manifest.artifacts)
            snapshot.artifacts = list(manifest.artifacts)
            snapshot.collection_errors = list(manifest.errors)
            # Kumulatif egri: manifest.artifacts zaten toplanma sirasinda --
            # uydurma bir seri degil, gercekten "N. dosyaya kadar kac dosya
            # toplandi" sorusunun cevabi.
            snapshot.files_trend = list(range(1, len(manifest.artifacts) + 1))
            if manifest.errors:
                snapshot.files_delta = f"{len(manifest.errors)} artefakt alınamadı"
            elif manifest.artifacts:
                snapshot.files_delta = "tümü doğrulandı"
            if manifest.ended_at_utc is not None:
                latest_end = manifest.ended_at_utc
                snapshot.duration_text = _duration_text(
                    manifest.started_at_utc, manifest.ended_at_utc
                )
                seconds = (manifest.ended_at_utc - manifest.started_at_utc).total_seconds()
                if seconds >= 0:
                    phase_labels.append("toplama")
                    phase_seconds.append(seconds)
        except (OSError, ValueError, KeyError):
            warnings.append("Toplama manifesti okunamadı, bozulmuş olabilir.")

    # 2) Yonlendirme/tespit manifestleri -> sure her zaman EN SON biten fazdan
    parsed_detection: Optional[DetectionManifest] = None
    for path, model, phase_label in (
        (resolve_routing_manifest_path(config), RoutingManifest, "yönlendirme"),
        (resolve_detection_manifest_path(config), DetectionManifest, "tarama"),
    ):
        if not path.is_file():
            continue
        try:
            parsed = model.from_json_file(path)
        except (OSError, ValueError, KeyError):
            warnings.append(f"{path.name} okunamadı, bozulmuş olabilir.")
            continue
        if isinstance(parsed, DetectionManifest):
            parsed_detection = parsed
            snapshot.finding_count = len(parsed.findings)
            snapshot.findings = list(parsed.findings)
            # Kumulatif bulgu egrisi: findings zaten kesfedilme sirasinda.
            snapshot.findings_trend = list(range(1, len(parsed.findings) + 1))
            high_count = sum(
                1 for finding in parsed.findings if finding.level.lower() in ("high", "critical")
            )
            if high_count:
                snapshot.findings_delta = f"{high_count} yüksek önem"
            elif parsed.findings:
                snapshot.findings_delta = "yüksek önem yok"
        if parsed.ended_at_utc is not None:
            if latest_end is None or parsed.ended_at_utc > latest_end:
                latest_end = parsed.ended_at_utc
                snapshot.duration_text = _duration_text(parsed.started_at_utc, parsed.ended_at_utc)
            seconds = (parsed.ended_at_utc - parsed.started_at_utc).total_seconds()
            if seconds >= 0:
                phase_labels.append(phase_label)
                phase_seconds.append(seconds)

    # YARA tarama manifesti -- Sigma/Hayabusa gibi opsiyonel, hic
    # calistirilmamis olabilir. Korelasyon SADECE iki manifest de varsa
    # hesaplanir (bkz. detection/correlation.py).
    yara_manifest_path = resolve_yara_manifest_path(config)
    if yara_manifest_path.is_file():
        try:
            parsed_yara = YaraManifest.from_json_file(yara_manifest_path)
            snapshot.yara_matches = list(parsed_yara.matches)
            if parsed_detection is not None:
                snapshot.correlated_artifacts = correlate_findings(parsed_detection, parsed_yara)
        except (OSError, ValueError, KeyError):
            warnings.append("yara_manifest.json okunamadı, bozulmuş olabilir.")

    # Chainsaw manifesti -- Hayabusa ile AYNI DetectionManifest/Finding
    # semasini kullanir; motor ittifaki SADECE iki manifest de varsa
    # hesaplanir (bkz. detection/correlation.py::correlate_sigma_engines).
    chainsaw_manifest_path = resolve_chainsaw_manifest_path(config)
    if chainsaw_manifest_path.is_file():
        try:
            parsed_chainsaw = DetectionManifest.from_json_file(chainsaw_manifest_path)
            snapshot.chainsaw_findings = list(parsed_chainsaw.findings)
            if parsed_detection is not None:
                snapshot.engine_agreements = correlate_sigma_engines(
                    parsed_detection, parsed_chainsaw
                )
        except (OSError, ValueError, KeyError):
            warnings.append("chainsaw_manifest.json okunamadı, bozulmuş olabilir.")

    # capa manifesti -- YARA ile AYNI YaraManifest/YaraMatch semasini kullanir
    # (bkz. detection/capa_runner.py); korelasyona KATILMAZ.
    capa_manifest_path = resolve_capa_manifest_path(config)
    if capa_manifest_path.is_file():
        try:
            parsed_capa = YaraManifest.from_json_file(capa_manifest_path)
            snapshot.capa_matches = list(parsed_capa.matches)
        except (OSError, ValueError, KeyError):
            warnings.append("capa_manifest.json okunamadı, bozulmuş olabilir.")

    if phase_labels:
        snapshot.duration_trend = phase_seconds
        snapshot.duration_delta = "+".join(phase_labels)

    # 3) Gozetim defteri -> zincir durumu + olay listesi
    log_path = resolve_custody_log_path(config)
    if log_path.is_file():
        try:
            result = verify_chain(log_path, config.case.case_id)
            snapshot.chain_valid = result.is_valid
            snapshot.chain_message = result.message
            snapshot.chain_total = result.total_events
            if not result.is_valid:
                # verify_chain ilk uyusmazlikta durur, yani dogruladigi olay
                # sayisi = kirilmanin oldugu siradir.
                snapshot.broken_at_index = result.total_events
            snapshot.events = list(read_events(log_path))
        except TriageChainError as exc:
            warnings.append(str(exc))

    # 4) En son uretilmis rapor -- write_report() UZERINE yazdigi icin tek
    # dosya, gecmis surum yok.
    report_path = resolve_report_path(config)
    if report_path.is_file():
        try:
            snapshot.report = Report.from_json_file(report_path)
            snapshot.report_path_note = str(report_path.parent)
        except (OSError, ValueError, KeyError):
            warnings.append("report.json okunamadı, bozulmuş olabilir.")

    snapshot.warning = " ".join(warnings)
    return snapshot


@dataclass
class CaseListItem:
    """'Vakalar' sayfasindaki tek satir -- diskte bulunmus bir vaka klasoru."""

    case_id: str
    is_active: bool = False
    artifact_count: Optional[int] = None
    chain_valid: Optional[bool] = None
    chain_total: int = 0
    finding_count: Optional[int] = None


def list_case_summaries(config) -> list[CaseListItem]:
    """`collection.output_dir` altindaki HER vaka klasorunu tarar.

    Yuklu config TEK bir vakayi biliyor, ama ayni output_dir'i paylasan
    kardes vakalar diskte zaten var olabilir -- read_snapshot()'un tek-vaka
    mantigini (manifest/defter/tespit oku) her klasor icin tekrarlar, hicbir
    sey uydurulmaz. Okunamayan bir klasor listeyi cokertmez, o alan bos kalir.
    """
    root = Path(config.collection.output_dir)
    if not root.is_dir():
        return []

    items: list[CaseListItem] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        case_id = entry.name
        item = CaseListItem(case_id=case_id, is_active=(case_id == config.case.case_id))

        manifest_path = entry / "manifest.json"
        if manifest_path.is_file():
            try:
                item.artifact_count = len(CollectionManifest.from_json_file(manifest_path).artifacts)
            except (OSError, ValueError, KeyError):
                pass

        log_path = entry / "custody.jsonl"
        if log_path.is_file():
            try:
                result = verify_chain(log_path, case_id)
                item.chain_valid = result.is_valid
                item.chain_total = result.total_events
            except TriageChainError:
                pass

        detection_path = entry / "detection_manifest.json"
        if detection_path.is_file():
            try:
                item.finding_count = len(DetectionManifest.from_json_file(detection_path).findings)
            except (OSError, ValueError, KeyError):
                pass

        items.append(item)
    return items


# ---------------------------------------------------------------------------
# Arka plan is parcacigi -- UI asla donmamali
# ---------------------------------------------------------------------------
class ActionWorker(QThread):
    """Dort aksiyondan birini arka planda calistirir.

    Sinyaller ana is parcaciginda islenir; worker hicbir widget'a dokunmaz.
    """

    done = Signal(str)     # basari ozeti
    failed = Signal(str)   # kullaniciya gosterilecek hata cumlesi

    def __init__(self, action: Callable[[Any], str], config, parent=None) -> None:
        super().__init__(parent)
        self._action = action
        self._config = config

    def run(self) -> None:
        try:
            self.done.emit(self._action(self._config))
        except TriageChainError as exc:
            # Projenin tipli hatalari zaten anlasilir mesaj tasiyor.
            self.failed.emit(str(exc))
        except Exception as exc:  # beklenmeyen -- ham traceback ASLA sizmaz
            self.failed.emit(f"Bir şeyler ters gitti: {exc}")


def _action_collect(config) -> str:
    """CLI'nin 'collect' komutuyla ayni akis, ekrana basmadan."""
    ledger = CustodyLedger(resolve_custody_log_path(config), config.case.case_id)
    manifest = run_collection(config, ledger)
    manifest.to_json_file(resolve_manifest_path(config))
    return (
        f"Toplama bitti: {len(manifest.artifacts)} dosya alındı, "
        f"{len(manifest.errors)} artefakt alınamadı."
    )


def _action_route(config) -> str:
    """CLI'nin 'route' komutuyla ayni akis."""
    manifest = CollectionManifest.from_json_file(resolve_manifest_path(config))
    ledger = CustodyLedger(resolve_custody_log_path(config), config.case.case_id)
    routing = run_router(config, manifest, ledger)
    routing.to_json_file(resolve_routing_manifest_path(config))
    return (
        f"Yönlendirme bitti: {len(routing.processed)} işlendi, "
        f"{len(routing.skipped)} atlandı, {len(routing.errors)} hata."
    )


def _action_detect(config) -> str:
    """CLI'nin 'detect' komutuyla ayni akis (manifesti kosunun kendisi yazar)."""
    manifest = CollectionManifest.from_json_file(resolve_manifest_path(config))
    ledger = CustodyLedger(resolve_custody_log_path(config), config.case.case_id)
    detection = run_detection(config, manifest, ledger)
    return (
        f"Tarama bitti: {len(detection.scanned)} olay günlüğü tarandı, "
        f"{len(detection.findings)} bulgu çıktı."
    )


def _action_yara_scan(config) -> str:
    """CLI'nin 'yara-scan' komutuyla ayni akis (manifesti kosunun kendisi yazar)."""
    manifest = CollectionManifest.from_json_file(resolve_manifest_path(config))
    ledger = CustodyLedger(resolve_custody_log_path(config), config.case.case_id)
    yara_manifest = run_yara_scan(config, manifest, ledger)
    return (
        f"YARA taraması bitti: {len(yara_manifest.scanned)} dosya tarandı, "
        f"{len(yara_manifest.matches)} eşleşme bulundu."
    )


def _action_chainsaw_scan(config) -> str:
    """CLI'nin 'chainsaw-scan' komutuyla ayni akis -- Hayabusa ile AYNI
    detection.rules_dir'i kullanan, BAGIMSIZ ikinci bir Sigma motoru
    (bkz. detection/chainsaw_runner.py ve aldigim_kararlar.md)."""
    manifest = CollectionManifest.from_json_file(resolve_manifest_path(config))
    ledger = CustodyLedger(resolve_custody_log_path(config), config.case.case_id)
    chainsaw_manifest = run_chainsaw_detection(config, manifest, ledger)
    return (
        f"Chainsaw taraması bitti: {len(chainsaw_manifest.scanned)} olay günlüğü tarandı, "
        f"{len(chainsaw_manifest.findings)} bulgu çıktı."
    )


def _action_capa_scan(config) -> str:
    """CLI'nin 'capa-scan' komutuyla ayni akis -- SADECE collection.
    suspicious_binaries'daki dosyalari tarar (bkz. detection/capa_runner.py)."""
    manifest = CollectionManifest.from_json_file(resolve_manifest_path(config))
    ledger = CustodyLedger(resolve_custody_log_path(config), config.case.case_id)
    capa_manifest = run_capa_scan(config, manifest, ledger)
    return (
        f"capa taraması bitti: {len(capa_manifest.scanned)} dosya tarandı, "
        f"{len(capa_manifest.matches)} yetenek eşleşmesi bulundu."
    )


def _action_report(config) -> str:
    """CLI'nin 'report' komutuyla ayni akis (bu katman deftere YAZMAZ)."""
    report = build_report(config)
    write_report(config, report)
    durum = "geçerli" if report.chain_status.is_valid else "GEÇERSİZ"
    return f"Rapor yazıldı ({resolve_report_path(config).parent}); zincir {durum}."


# ---------------------------------------------------------------------------
# Sidebar dugmesi
# ---------------------------------------------------------------------------
class SidebarButton(QPushButton):
    """Sol menudeki tek satir. Secili olan yesil tinte + yesil ikona doner.

    Ikon rengi QSS'in :checked sozde-durumuyla CANLI degismiyor (QIcon bir
    kez pixmap'e gomulen bir renktir) -- bu yuzden secili/degil icin iki ayri
    QIcon onceden uretilip toggled sinyaliyle degistiriliyor.
    """

    def __init__(self, label: str, icon_name: str, parent=None) -> None:
        super().__init__(label, parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(40)
        self._icon_off = icons.icon(icon_name, color=t.TEXT_SECONDARY, size=17)
        self._icon_on = icons.icon(icon_name, color=t.ACCENT_TEXT, size=17)
        self.setIcon(self._icon_off)
        self.setIconSize(QSize(17, 17))
        self.toggled.connect(
            lambda checked: self.setIcon(self._icon_on if checked else self._icon_off)
        )
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {t.TEXT_SECONDARY};
                border: 1px solid transparent;
                border-radius: {t.RADIUS_SM}px;
                padding: 8px 12px;
                text-align: left;
                font-family: "{t.FONT_UI}";
                font-size: 13px;
                font-weight: 500;
            }}
            QPushButton:hover {{ background-color: {t.BG_LAYER2}; color: {t.TEXT_MAIN}; }}
            QPushButton:checked {{
                background-color: {tint(t.ACCENT, 36)};
                color: {t.ACCENT_TEXT};
                border-color: {tint(t.ACCENT, 72)};
                font-weight: 600;
            }}
            QPushButton:focus {{ border: 1px solid {t.ACCENT_TEXT}; }}
        """)


# ---------------------------------------------------------------------------
# Ana pencere
# ---------------------------------------------------------------------------
class TriageChainWindow(QMainWindow):
    """Sidebar + Dashboard. Vaka yuklenene kadar dort aksiyon da kapali."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("TriageChain Konsolu")
        self.resize(1180, 760)
        self.config = None
        self.config_path: Optional[Path] = None
        self.snapshot = CaseSnapshot()
        self._worker: Optional[ActionWorker] = None

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_dashboard())   # index 0
        self.stack.addWidget(self._build_files_page())  # index 1
        self.stack.addWidget(self._build_custody_page())  # index 2
        self.stack.addWidget(self._build_findings_page())  # index 3
        self.stack.addWidget(self._build_reports_page())  # index 4
        self.stack.addWidget(self._build_cases_page())  # index 5
        root.addWidget(self.stack, stretch=1)
        self.setCentralWidget(central)

        self._refresh()

    # -- Sidebar ------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        panel = QFrame()
        panel.setFixedWidth(248)
        panel.setStyleSheet(
            f"background-color: {t.BG_SURFACE}; border-right: 1px solid {t.BORDER};"
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 20, 14, 16)
        layout.setSpacing(2)

        # Logo satiri: yesil tintli rozet + marka adi (referans tasarimdaki
        # kalkan/rozet ikonuyla ayni fikir).
        brand_row = QHBoxLayout()
        brand_row.setSpacing(9)
        brand_icon = QLabel()
        brand_icon.setFixedSize(30, 30)
        brand_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand_icon.setPixmap(icons.icon("shield", color=t.ACCENT_TEXT, size=16).pixmap(16, 16))
        brand_icon.setStyleSheet(
            f"background-color:{tint(t.ACCENT, 40)}; border-radius:{t.RADIUS_SM}px;"
        )
        brand_row.addWidget(brand_icon)
        brand = QLabel("TriageChain")
        brand.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:16px; font-weight:600; color:{t.TEXT_MAIN};"
        )
        brand_row.addWidget(brand)
        brand_row.addStretch()
        layout.addLayout(brand_row)
        layout.addSpacing(14)

        # HTML maketteki `.case-pill` ile ayni fikir: kucuk baslik + mono
        # vaka kimligi, kenarlikli/dolgulu bir kutu icinde.
        pill = QFrame()
        pill.setStyleSheet(
            f"background-color:{t.BG_LAYER2}; border:1px solid {t.BORDER}; "
            f"border-radius:{t.RADIUS_SM}px;"
        )
        pill_layout = QVBoxLayout(pill)
        pill_layout.setContentsMargins(10, 6, 10, 6)
        pill_layout.setSpacing(1)
        pill_caption = QLabel("AKTİF VAKA")
        pill_caption.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:9.5px; font-weight:600; letter-spacing:1px;"
        )
        pill_layout.addWidget(pill_caption)
        self.case_pill = MonoLabel("Vaka yüklenmedi")
        pill_layout.addWidget(self.case_pill)
        layout.addWidget(pill)
        layout.addSpacing(18)

        section_label = QLabel("GENEL")
        section_label.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:9.5px; font-weight:600; "
            f"letter-spacing:1px; padding-left:4px;"
        )
        layout.addWidget(section_label)
        layout.addSpacing(6)

        self.nav_buttons: dict[str, SidebarButton] = {}
        group = QButtonGroup(panel)
        group.setExclusive(True)

        dash_btn = SidebarButton("Dashboard", NAV_ICONS["Dashboard"])
        dash_btn.clicked.connect(self._show_dashboard)
        group.addButton(dash_btn)
        layout.addWidget(dash_btn)
        self.nav_buttons["Dashboard"] = dash_btn
        dash_btn.setChecked(True)

        for name in SIDEBAR_PAGES:
            btn = SidebarButton(name, NAV_ICONS[name])
            if name == "Toplanan Dosyalar":
                btn.clicked.connect(self._show_files)
            elif name == "Delil Zinciri":
                btn.clicked.connect(self._show_custody)
            elif name == "Bulgular":
                btn.clicked.connect(self._show_findings)
            elif name == "Raporlar":
                btn.clicked.connect(self._show_reports)
            elif name == "Vakalar":
                btn.clicked.connect(self._show_cases)
            group.addButton(btn)
            layout.addWidget(btn)
            self.nav_buttons[name] = btn

        layout.addStretch()
        foot = QLabel("Zincir bütünlüğü izleniyor")
        foot.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-family:'{t.FONT_UI}'; font-size:11px;"
        )
        layout.addWidget(foot)
        return panel

    def _show_dashboard(self) -> None:
        self.stack.setCurrentIndex(0)

    def _show_files(self) -> None:
        self.stack.setCurrentIndex(1)

    def _show_custody(self) -> None:
        self.stack.setCurrentIndex(2)

    def _show_findings(self) -> None:
        self.stack.setCurrentIndex(3)

    def _show_reports(self) -> None:
        self.stack.setCurrentIndex(4)

    def _show_cases(self) -> None:
        self.stack.setCurrentIndex(5)

    # -- Toplanan Dosyalar ---------------------------------------------------
    def _build_files_page(self) -> QWidget:
        """Manifestteki HER artefagi (Dashboard'daki gibi ozet degil, tam
        liste) gosterir -- veri Dashboard'la ayni read_snapshot()'tan gelir,
        ikinci bir okuma/hesaplama yolu YOK."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(t.CARD_GAP)

        title = QLabel("Toplanan Dosyalar")
        title.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:{t.SIZE_TITLE}px; "
            f"font-weight:600; color:{t.TEXT_MAIN};"
        )
        layout.addWidget(title)

        self.files_subtitle = QLabel("Henüz bir vaka yüklenmedi.")
        self.files_subtitle.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        layout.addWidget(self.files_subtitle)

        panel = Card()
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["DOSYA", "BOYUT", "TOPLANMA ZAMANI", "SHA-256 HASH"])
        _style_ledger_table(table)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        # Hash sutunu KESILMEMELI -- custody tablosuyla ayni gerekce.
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table = table
        panel.body.addWidget(table)

        self.files_footer = QLabel("")
        self.files_footer.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        panel.body.addWidget(self.files_footer)
        layout.addWidget(panel, stretch=1)
        return page

    def _build_file_cell(self, artifact) -> QWidget:
        """Ikon + hedef yol (kalin) + kaynak yol (soluk, ikinci satir) --
        custody tablosundaki _build_event_cell ile ayni gorsel dil."""
        cell = QWidget()
        row_layout = QHBoxLayout(cell)
        row_layout.setContentsMargins(0, 9, 0, 9)
        row_layout.setSpacing(10)

        icon_box = QLabel()
        icon_box.setFixedSize(28, 28)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_box.setPixmap(icons.icon("files", color=t.TEXT_SECONDARY, size=14).pixmap(14, 14))
        icon_box.setStyleSheet(f"background-color:{t.BG_LAYER2}; border-radius:{t.RADIUS_SM}px;")
        row_layout.addWidget(icon_box)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)
        name = QLabel(artifact.dest_path)
        name.setStyleSheet(f"color:{t.TEXT_MAIN}; font-weight:500; font-size:13px;")
        text_col.addWidget(name)
        detail = QLabel(f"{artifact.artifact_type_id} · kaynak: {artifact.source_path}")
        detail.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:11px;")
        text_col.addWidget(detail)
        row_layout.addLayout(text_col)
        row_layout.addStretch()
        return cell

    def _refresh_files(self) -> None:
        snap = self.snapshot
        if self.config is None:
            self.files_subtitle.setText("Henüz bir vaka yüklenmedi.")
        else:
            self.files_subtitle.setText(f"{self.config.case.case_id} · {len(snap.artifacts)} dosya")

        self.files_table.setRowCount(len(snap.artifacts))
        for row, artifact in enumerate(snap.artifacts):
            self.files_table.setCellWidget(row, 0, self._build_file_cell(artifact))
            self.files_table.setItem(row, 1, QTableWidgetItem(_human_size(artifact.size_bytes)))
            stamp = artifact.collected_at_utc.strftime("%Y-%m-%d %H:%M:%S")
            self.files_table.setItem(row, 2, QTableWidgetItem(stamp))
            hash_label = MonoLabel(artifact.hash_value)
            hash_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.files_table.setCellWidget(row, 3, hash_label)
        _fit_rows_to_cell_widgets(self.files_table)

        if not snap.has_manifest:
            self.files_footer.setText("Henüz bir toplama çalıştırılmadı.")
        elif snap.collection_errors:
            self.files_footer.setText(
                f"{len(snap.artifacts)} dosya toplandı, "
                f"{len(snap.collection_errors)} artefakt alınamadı."
            )
        else:
            self.files_footer.setText(f"{len(snap.artifacts)} dosya toplandı, hepsi doğrulandı.")

    # -- Delil Zinciri --------------------------------------------------------
    def _build_custody_page(self) -> QWidget:
        """Dashboard'daki mini deftere ayni fikir ama TAM liste -- 50 satir
        sinirlamasi yok, _build_event_cell'i AYNEN yeniden kullanir (ikinci
        bir hucre-cizim yolu yok)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(t.CARD_GAP)

        head = QHBoxLayout()
        title = QLabel("Delil Zinciri")
        title.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:{t.SIZE_TITLE}px; "
            f"font-weight:600; color:{t.TEXT_MAIN};"
        )
        head.addWidget(title)
        head.addStretch()
        self.custody_badge = StatusBadge()
        head.addWidget(self.custody_badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(head)

        self.custody_subtitle = QLabel("Henüz bir vaka yüklenmedi.")
        self.custody_subtitle.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        layout.addWidget(self.custody_subtitle)

        panel = Card()
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["OLAY", "ZAMAN DAMGASI", "SHA-256 HASH", "DURUM"])
        _style_ledger_table(table)
        header = table.horizontalHeader()
        # Sutun 0 ozel bir widget tasiyor (_build_event_cell) -- Qt'nin
        # ResizeToContents'i widget genisligini olcemiyor (satir yuksekligi
        # hesabindaki ayni sinirlama, bkz. _fit_rows_to_cell_widgets), bu
        # yuzden metin kirpilmasin diye Stretch kullaniliyor.
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        # Sutun 3 de ozel bir widget (StatusBadge) tasiyor -- ayni gerekce.
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.custody_table = table
        panel.body.addWidget(table)
        layout.addWidget(panel, stretch=1)
        return page

    def _refresh_custody(self) -> None:
        snap = self.snapshot
        if self.config is None:
            self.custody_subtitle.setText("Henüz bir vaka yüklenmedi.")
            self.custody_badge.set_status(t.TEXT_SECONDARY, "Henüz vaka yüklenmedi")
        else:
            self.custody_subtitle.setText(f"{self.config.case.case_id} · {len(snap.events)} olay")
            if snap.chain_valid is None:
                self.custody_badge.set_status(t.TEXT_SECONDARY, "Defter henüz yok")
            elif snap.chain_valid:
                self.custody_badge.set_status(
                    t.SUCCESS, f"Zincir Geçerli · {snap.chain_total} olay"
                )
            else:
                self.custody_badge.set_status(
                    t.ERROR, f"Zincir GEÇERSİZ · {snap.chain_total}. olayda kırılma"
                )

        events = snap.events
        self.custody_table.setRowCount(len(events))
        for row, event in enumerate(events):
            order = row + 1
            self.custody_table.setCellWidget(row, 0, self._build_event_cell(event))
            stamp = event.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S")
            self.custody_table.setItem(row, 1, QTableWidgetItem(stamp))
            hash_label = MonoLabel(event.entry_hash)
            hash_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.custody_table.setCellWidget(row, 2, hash_label)

            badge = StatusBadge()
            broken = snap.broken_at_index
            if broken is not None and order >= broken:
                badge.set_status(t.ERROR, "Şüpheli")
            else:
                badge.set_status(t.SUCCESS, "Doğrulandı")
            self.custody_table.setCellWidget(row, 3, badge)
        _fit_rows_to_cell_widgets(self.custody_table)

    # -- Bulgular -------------------------------------------------------------
    def _build_findings_page(self) -> QWidget:
        """Tespit manifestindeki TAM bulgu listesi -- Dashboard'daki 'Şüpheli
        Bulgu Sayısı' kartinin ozetledigi sayinin acilimi."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(t.CARD_GAP)

        title = QLabel("Bulgular")
        title.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:{t.SIZE_TITLE}px; "
            f"font-weight:600; color:{t.TEXT_MAIN};"
        )
        layout.addWidget(title)

        self.findings_subtitle = QLabel("Henüz bir vaka yüklenmedi.")
        self.findings_subtitle.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;"
        )
        layout.addWidget(self.findings_subtitle)

        panel = Card()
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["BULGU", "SEVİYE", "OLAY ZAMANI", "KAYNAK DOSYA"])
        _style_ledger_table(table)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        # Sutun 1 (StatusBadge) ve 3 (MonoLabel) ozel widget tasiyor -- diger
        # tablolardaki ayni gerekce (bkz. custody_table yorumu).
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings_table = table
        panel.body.addWidget(table)
        layout.addWidget(panel, stretch=1)

        yara_panel = Card("YARA Eşleşmeleri")
        self.yara_correlation_note = QLabel("")
        self.yara_correlation_note.setStyleSheet(
            f"color:{t.ACCENT_TEXT}; font-size:{t.SIZE_HELPER}px; font-weight:600;"
        )
        self.yara_correlation_note.setWordWrap(True)
        self.yara_correlation_note.setVisible(False)
        yara_panel.body.addWidget(self.yara_correlation_note)

        yara_table = QTableWidget(0, 3)
        yara_table.setHorizontalHeaderLabels(["KURAL", "ETİKETLER", "DOSYA"])
        _style_ledger_table(yara_table)
        yara_header = yara_table.horizontalHeader()
        yara_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        yara_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        yara_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.yara_table = yara_table
        yara_panel.body.addWidget(yara_table)

        self.yara_empty_note = QLabel(
            "Henüz YARA taraması çalıştırılmadı. Dashboard'daki \"YARA Tara\" "
            "butonuyla başlatabilirsiniz."
        )
        self.yara_empty_note.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_BODY}px;")
        self.yara_empty_note.setWordWrap(True)
        yara_panel.body.addWidget(self.yara_empty_note)

        self.yara_panel = yara_panel
        layout.addWidget(yara_panel, stretch=1)

        chainsaw_panel = Card("Chainsaw Bulguları")
        self.chainsaw_agreement_note = QLabel("")
        self.chainsaw_agreement_note.setStyleSheet(
            f"color:{t.ACCENT_TEXT}; font-size:{t.SIZE_HELPER}px; font-weight:600;"
        )
        self.chainsaw_agreement_note.setWordWrap(True)
        self.chainsaw_agreement_note.setVisible(False)
        chainsaw_panel.body.addWidget(self.chainsaw_agreement_note)

        # Chainsaw, Hayabusa ile AYNI Finding semasini uretir -- bu yuzden
        # AYNI hucre olceklerini (_build_finding_cell) ve kolon duzenini
        # kullaniyoruz, tekrar tablo tasarimi YAPILMADI.
        chainsaw_table = QTableWidget(0, 4)
        chainsaw_table.setHorizontalHeaderLabels(["BULGU", "SEVİYE", "OLAY ZAMANI", "KAYNAK DOSYA"])
        _style_ledger_table(chainsaw_table)
        chainsaw_header = chainsaw_table.horizontalHeader()
        chainsaw_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        chainsaw_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        chainsaw_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        chainsaw_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.chainsaw_table = chainsaw_table
        chainsaw_panel.body.addWidget(chainsaw_table)

        self.chainsaw_empty_note = QLabel(
            "Henüz Chainsaw taraması çalıştırılmadı. Dashboard'daki \"Chainsaw Tara\" "
            "butonuyla başlatabilirsiniz."
        )
        self.chainsaw_empty_note.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_BODY}px;"
        )
        self.chainsaw_empty_note.setWordWrap(True)
        chainsaw_panel.body.addWidget(self.chainsaw_empty_note)

        self.chainsaw_panel = chainsaw_panel
        layout.addWidget(chainsaw_panel, stretch=1)

        # capa YARA ile AYNI YaraMatch semasini uretir -- bu yuzden AYNI
        # tablo tasarimini (KURAL/ETIKETLER/DOSYA) kullaniyoruz. Korelasyon
        # notu YOK: capa risk/korelasyona KATILMAZ (bkz. reporting/
        # executive.py, aldigim_kararlar.md -> "capa entegrasyonu").
        capa_panel = Card("capa Yetenek Eşleşmeleri")
        capa_table = QTableWidget(0, 3)
        capa_table.setHorizontalHeaderLabels(["YETENEK", "MITRE ATT&CK", "DOSYA"])
        _style_ledger_table(capa_table)
        capa_header = capa_table.horizontalHeader()
        capa_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        capa_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        capa_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.capa_table = capa_table
        capa_panel.body.addWidget(capa_table)

        self.capa_empty_note = QLabel(
            "Henüz capa taraması çalıştırılmadı. Dashboard'daki \"capa Tara\" "
            "butonuyla başlatabilirsiniz."
        )
        self.capa_empty_note.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_BODY}px;")
        self.capa_empty_note.setWordWrap(True)
        capa_panel.body.addWidget(self.capa_empty_note)

        self.capa_panel = capa_panel
        layout.addWidget(capa_panel, stretch=1)
        return page

    def _build_finding_cell(self, finding) -> QWidget:
        """Ikon + kural adi (kalin) + bilgisayar/kanal/olay-id detayi (soluk,
        ikinci satir) -- diger tablo hucreleriyle ayni gorsel dil."""
        is_severe = finding.level.lower() in ("high", "critical")
        cell = QWidget()
        row_layout = QHBoxLayout(cell)
        row_layout.setContentsMargins(0, 9, 0, 9)
        row_layout.setSpacing(10)

        icon_color = t.ERROR if is_severe else t.TEXT_SECONDARY
        icon_box = QLabel()
        icon_box.setFixedSize(28, 28)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_box.setPixmap(icons.icon("alert-triangle", color=icon_color, size=14).pixmap(14, 14))
        icon_box.setStyleSheet(
            f"background-color:{tint(icon_color, 36) if is_severe else t.BG_LAYER2}; "
            f"border-radius:{t.RADIUS_SM}px;"
        )
        row_layout.addWidget(icon_box)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)
        name_row = QHBoxLayout()
        name_row.setContentsMargins(0, 0, 0, 0)
        name_row.setSpacing(8)
        name = QLabel(finding.rule_title)
        name.setStyleSheet(f"color:{t.TEXT_MAIN}; font-weight:500; font-size:13px;")
        name_row.addWidget(name)
        # MITRE ATT&CK etiketi Sigma kuralinin KENDI metadatasindan geliyor
        # (bkz. Finding.mitre_tags dokstring'i) -- Hayabusa ciktisinda yoksa
        # bos kalir, bu durumda rozet hic gosterilmez (uydurma etiket yok).
        if finding.mitre_tags:
            mitre_badge = QLabel(finding.mitre_tags)
            mitre_badge.setStyleSheet(f"""
                color: {t.ACCENT_TEXT};
                background-color: {tint(t.ACCENT, 30)};
                font-family: "{t.FONT_MONO}";
                font-size: 10.5px;
                font-weight: 600;
                border-radius: 9px;
                padding: 2px 8px;
            """)
            name_row.addWidget(mitre_badge)
        name_row.addStretch()
        text_col.addLayout(name_row)
        detail = QLabel(f"{finding.computer} · {finding.channel} · olay {finding.event_id}")
        detail.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:11px;")
        text_col.addWidget(detail)
        row_layout.addLayout(text_col)
        row_layout.addStretch()
        return cell

    def _refresh_findings(self) -> None:
        snap = self.snapshot
        if self.config is None:
            self.findings_subtitle.setText("Henüz bir vaka yüklenmedi.")
        else:
            self.findings_subtitle.setText(
                f"{self.config.case.case_id} · {len(snap.findings)} bulgu"
            )

        self.findings_table.setRowCount(len(snap.findings))
        for row, finding in enumerate(snap.findings):
            is_severe = finding.level.lower() in ("high", "critical")
            self.findings_table.setCellWidget(row, 0, self._build_finding_cell(finding))

            level_badge = StatusBadge()
            level_badge.set_status(t.ERROR if is_severe else t.TEXT_SECONDARY, finding.level)
            self.findings_table.setCellWidget(row, 1, level_badge)

            self.findings_table.setItem(row, 2, QTableWidgetItem(finding.timestamp))
            source_label = MonoLabel(finding.source_path)
            source_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.findings_table.setCellWidget(row, 3, source_label)
        _fit_rows_to_cell_widgets(self.findings_table)

        has_yara_run = bool(snap.yara_matches) or (
            self.config is not None and resolve_yara_manifest_path(self.config).is_file()
        )
        self.yara_panel.setVisible(has_yara_run)
        self.yara_empty_note.setVisible(not has_yara_run)

        correlated_paths = {item.source_path for item in snap.correlated_artifacts}
        if correlated_paths:
            self.yara_correlation_note.setText(
                f"{len(correlated_paths)} dosya HEM Sigma HEM YARA tarafından işaretlendi "
                "(aşağıda vurgulanmış)."
            )
            self.yara_correlation_note.setVisible(True)
        else:
            self.yara_correlation_note.setVisible(False)

        self.yara_table.setRowCount(len(snap.yara_matches))
        for row, match in enumerate(snap.yara_matches):
            is_correlated = match.source_path in correlated_paths
            name = QTableWidgetItem(match.rule_name)
            if is_correlated:
                name.setForeground(QColor(t.ACCENT_TEXT))
                font = name.font()
                font.setBold(True)
                name.setFont(font)
            self.yara_table.setItem(row, 0, name)
            self.yara_table.setItem(row, 1, QTableWidgetItem(match.tags or "—"))
            source_label = MonoLabel(match.source_path)
            source_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.yara_table.setCellWidget(row, 2, source_label)
        self.yara_table.resizeRowsToContents()

        has_chainsaw_run = bool(snap.chainsaw_findings) or (
            self.config is not None and resolve_chainsaw_manifest_path(self.config).is_file()
        )
        self.chainsaw_panel.setVisible(has_chainsaw_run)
        self.chainsaw_empty_note.setVisible(not has_chainsaw_run)

        agreement_paths = {item.source_path for item in snap.engine_agreements}
        if agreement_paths:
            self.chainsaw_agreement_note.setText(
                f"{len(agreement_paths)} dosyada Hayabusa VE Chainsaw AYNI kuralı buldu "
                "(aşağıda vurgulanmış) -- iki bağımsız motorun anlaşması."
            )
            self.chainsaw_agreement_note.setVisible(True)
        else:
            self.chainsaw_agreement_note.setVisible(False)

        self.chainsaw_table.setRowCount(len(snap.chainsaw_findings))
        for row, finding in enumerate(snap.chainsaw_findings):
            is_severe = finding.level.lower() in ("high", "critical")
            self.chainsaw_table.setCellWidget(row, 0, self._build_finding_cell(finding))

            level_badge = StatusBadge()
            level_badge.set_status(t.ERROR if is_severe else t.TEXT_SECONDARY, finding.level)
            self.chainsaw_table.setCellWidget(row, 1, level_badge)

            self.chainsaw_table.setItem(row, 2, QTableWidgetItem(finding.timestamp))
            is_agreed = finding.source_path in agreement_paths
            source_label = MonoLabel(finding.source_path)
            source_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            if is_agreed:
                source_label.setStyleSheet(
                    source_label.styleSheet()
                    + f"QLabel {{ color: {t.ACCENT_TEXT}; font-weight: 600; }}"
                )
            self.chainsaw_table.setCellWidget(row, 3, source_label)
        _fit_rows_to_cell_widgets(self.chainsaw_table)

        has_capa_run = bool(snap.capa_matches) or (
            self.config is not None and resolve_capa_manifest_path(self.config).is_file()
        )
        self.capa_panel.setVisible(has_capa_run)
        self.capa_empty_note.setVisible(not has_capa_run)

        self.capa_table.setRowCount(len(snap.capa_matches))
        for row, match in enumerate(snap.capa_matches):
            self.capa_table.setItem(row, 0, QTableWidgetItem(match.rule_name))
            self.capa_table.setItem(row, 1, QTableWidgetItem(match.tags or "—"))
            source_label = MonoLabel(match.source_path)
            source_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.capa_table.setCellWidget(row, 2, source_label)
        self.capa_table.resizeRowsToContents()

    # -- Raporlar ---------------------------------------------------------
    def _stat_row(self, label_text: str) -> QLabel:
        """Rapor sayfasindaki 'etiket: deger' satirlarindan biri -- deger
        sonradan _refresh_reports() ile doldurulacagi icin QLabel dondurur."""
        row = QHBoxLayout()
        label = QLabel(label_text)
        label.setFixedWidth(180)
        label.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        value = QLabel("—")
        value.setStyleSheet(f"color:{t.TEXT_MAIN}; font-size:13px; font-weight:500;")
        value.setWordWrap(True)
        row.addWidget(label)
        row.addWidget(value, stretch=1)
        self._reports_card_body.addLayout(row)
        return value

    def _exec_tile(self, label_text: str) -> QLabel:
        """Yonetici Raporu sekmesindeki kucuk istatistik kutularindan biri --
        Dashboard'daki metrik kartlariyla ayni gorsel dil (kucuk gri etiket +
        buyuk deger), sadece ikonsuz/sadelestirilmis."""
        tile = Card()
        tile.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        label = QLabel(label_text)
        label.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        value = QLabel("—")
        value.setStyleSheet(
            f"font-family:'{t.FONT_MONO}'; font-size:22px; font-weight:700; color:{t.TEXT_MAIN};"
        )
        tile.body.addWidget(label)
        tile.body.addWidget(value)
        self._exec_tiles_row.addWidget(tile)
        return value

    def _build_reports_page(self) -> QWidget:
        """En son uretilmis report.json'un ozeti -- tek bir rapor (bkz.
        CaseSnapshot.report dokstring'i). Iki sekme: Yonetici Raporu (teknik
        olmayan, risk seviyesi + duz metin -- bkz. reporting/executive.py) ve
        Uzman Raporu (teknik alan listesi, eskiden beri var olan icerik)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(t.CARD_GAP)

        head = QHBoxLayout()
        title = QLabel("Raporlar")
        title.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:{t.SIZE_TITLE}px; "
            f"font-weight:600; color:{t.TEXT_MAIN};"
        )
        head.addWidget(title)
        head.addStretch()
        self.report_chain_badge = StatusBadge()
        head.addWidget(self.report_chain_badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(head)

        self.reports_subtitle = QLabel("Henüz bir vaka yüklenmedi.")
        self.reports_subtitle.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        layout.addWidget(self.reports_subtitle)

        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: none; }}
            QTabBar::tab {{
                background: transparent; color: {t.TEXT_SECONDARY};
                padding: 8px 16px; margin-right: 4px;
                border-top-left-radius: {t.RADIUS_SM}px; border-top-right-radius: {t.RADIUS_SM}px;
                font-family: "{t.FONT_UI}"; font-size: 13px; font-weight: 500;
            }}
            QTabBar::tab:selected {{ background: {t.BG_SURFACE}; color: {t.TEXT_MAIN}; font-weight: 600; }}
            QTabBar::tab:hover {{ color: {t.TEXT_MAIN}; }}
        """)

        # -- Sekme 1: Yonetici Raporu ----------------------------------------
        exec_tab = QWidget()
        exec_layout = QVBoxLayout(exec_tab)
        exec_layout.setContentsMargins(0, 16, 0, 0)
        exec_layout.setSpacing(t.CARD_GAP)

        self.exec_risk_banner = Card()
        self.exec_risk_level = QLabel("—")
        self.exec_risk_level.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:18px; font-weight:700; color:{t.TEXT_MAIN};"
        )
        self.exec_risk_reason = QLabel("")
        self.exec_risk_reason.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_BODY}px;")
        self.exec_risk_reason.setWordWrap(True)
        self.exec_risk_banner.body.addWidget(self.exec_risk_level)
        self.exec_risk_banner.body.addWidget(self.exec_risk_reason)
        exec_layout.addWidget(self.exec_risk_banner)

        narrative_card = Card()
        self.exec_narrative = QLabel("")
        self.exec_narrative.setStyleSheet(f"color:{t.TEXT_MAIN}; font-size:15px; line-height:1.5;")
        self.exec_narrative.setWordWrap(True)
        narrative_card.body.addWidget(self.exec_narrative)
        exec_layout.addWidget(narrative_card)

        self._exec_tiles_row = QHBoxLayout()
        self._exec_tiles_row.setSpacing(t.CARD_GAP)
        self.exec_tile_artifacts = self._exec_tile("İncelenen Dosya")
        self.exec_tile_findings = self._exec_tile("Güvenlik Bulgusu")
        self.exec_tile_high = self._exec_tile("Yüksek/Kritik Bulgu")
        self.exec_tile_chain = self._exec_tile("Kanıt Bütünlüğü")
        exec_layout.addLayout(self._exec_tiles_row)
        exec_layout.addStretch()
        tabs.addTab(exec_tab, "Yönetici Raporu")

        # -- Sekme 2: Uzman Raporu --------------------------------------------
        expert_tab = QWidget()
        expert_layout = QVBoxLayout(expert_tab)
        expert_layout.setContentsMargins(0, 16, 0, 0)
        expert_layout.setSpacing(t.CARD_GAP)

        panel = Card()
        self.reports_card = panel
        self._reports_card_body = panel.body
        self.report_field_generated = self._stat_row("Üretilme zamanı (UTC)")
        self.report_field_operator = self._stat_row("Operatör")
        self.report_field_collection = self._stat_row("Toplama")
        self.report_field_routing = self._stat_row("Yönlendirme")
        self.report_field_detection = self._stat_row("Tarama")
        self.report_field_location = self._stat_row("Dosya konumu")
        expert_layout.addWidget(panel)
        expert_layout.addStretch()
        tabs.addTab(expert_tab, "Uzman Raporu")

        self.reports_tabs = tabs
        layout.addWidget(tabs, stretch=1)

        self.reports_empty_note = QLabel(
            "Henüz rapor üretilmedi. Dashboard'daki \"Rapor Üret\" butonuyla oluşturabilirsiniz."
        )
        self.reports_empty_note.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_BODY}px;")
        self.reports_empty_note.setWordWrap(True)
        layout.addWidget(self.reports_empty_note)
        return page

    def _refresh_reports(self) -> None:
        snap = self.snapshot
        report = snap.report
        has_report = report is not None
        self.reports_tabs.setVisible(has_report)
        self.reports_card.setVisible(has_report)
        self.reports_empty_note.setVisible(not has_report)

        if self.config is None:
            self.reports_subtitle.setText("Henüz bir vaka yüklenmedi.")
            self.report_chain_badge.set_status(t.TEXT_SECONDARY, "Henüz vaka yüklenmedi")
            return
        self.reports_subtitle.setText(self.config.case.case_id)

        if not has_report:
            self.report_chain_badge.set_status(t.TEXT_SECONDARY, "Henüz rapor yok")
            return

        summary = build_executive_summary(report)
        risk_color = t.RISK_COLORS[summary.risk_level]
        self.exec_risk_banner.setStyleSheet(f"""
            Card {{
                background-color: {tint(risk_color, 26)};
                border: 1px solid {tint(risk_color, 90)};
                border-radius: {t.RADIUS}px;
            }}
        """)
        self.exec_risk_level.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:18px; font-weight:700; color:{risk_color};"
        )
        self.exec_risk_level.setText(f"Risk Seviyesi: {summary.risk_level}")
        self.exec_risk_reason.setText(summary.risk_reason)
        self.exec_narrative.setText(summary.narrative)
        self.exec_tile_artifacts.setText(str(summary.artifact_count))
        self.exec_tile_findings.setText(str(summary.finding_count))
        self.exec_tile_high.setText(str(summary.high_severity_count))
        self.exec_tile_chain.setText("Doğrulandı" if summary.chain_is_valid else "BOZULMUŞ")
        self.exec_tile_chain.setStyleSheet(
            f"font-family:'{t.FONT_MONO}'; font-size:18px; font-weight:700; "
            f"color:{t.SUCCESS if summary.chain_is_valid else t.ERROR};"
        )

        self.report_field_generated.setText(
            report.report_generated_at_utc.strftime("%Y-%m-%d %H:%M:%S")
        )
        self.report_field_operator.setText(f"{report.operator} · {report.case_id}")
        c = report.collection
        self.report_field_collection.setText(
            f"{c.artifact_count} dosya, {c.error_count} hata "
            f"({_duration_text(c.started_at_utc, c.ended_at_utc) or '—'})"
        )
        if report.routing is not None:
            r = report.routing
            self.report_field_routing.setText(
                f"{r.processed_count} işlendi, {r.skipped_count} atlandı, {r.error_count} hata"
            )
        else:
            self.report_field_routing.setText("Bu vaka için henüz çalıştırılmadı")
        if report.detection is not None:
            d = report.detection
            self.report_field_detection.setText(
                f"{d.scanned_count} dosya tarandı, {d.finding_count} bulgu"
            )
        else:
            self.report_field_detection.setText("Bu vaka için henüz çalıştırılmadı")
        self.report_field_location.setText(snap.report_path_note)

        cs = report.chain_status
        if cs.is_valid:
            self.report_chain_badge.set_status(t.SUCCESS, f"Zincir Geçerli · {cs.total_events} olay")
        else:
            self.report_chain_badge.set_status(t.ERROR, f"Zincir GEÇERSİZ · {cs.message}")

    # -- Vakalar --------------------------------------------------------------
    def _build_cases_page(self) -> QWidget:
        """`collection.output_dir` altinda diskte bulunan HER vaka klasoru --
        su an yuklu olan tek config'in bilgisiyle sinirli degil (bkz.
        list_case_summaries)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(t.CARD_GAP)

        title = QLabel("Vakalar")
        title.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:{t.SIZE_TITLE}px; "
            f"font-weight:600; color:{t.TEXT_MAIN};"
        )
        layout.addWidget(title)

        self.cases_subtitle = QLabel("Henüz bir vaka yüklenmedi.")
        self.cases_subtitle.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        self.cases_subtitle.setWordWrap(True)
        layout.addWidget(self.cases_subtitle)

        panel = Card()
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["VAKA", "TOPLANAN DOSYA", "ZİNCİR DURUMU", "BULGU"])
        _style_ledger_table(table)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        # Sutun 2 ozel bir widget (StatusBadge) tasiyor -- diger tablolardaki
        # ayni gerekce (bkz. custody_table yorumu).
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.cases_table = table
        panel.body.addWidget(table)
        layout.addWidget(panel, stretch=1)
        return page

    def _build_case_cell(self, item: CaseListItem) -> QWidget:
        """Ikon + vaka kimligi (kalin) -- aktif olan yaninda kucuk bir
        yesil 'AKTİF' rozeti tasir."""
        cell = QWidget()
        row_layout = QHBoxLayout(cell)
        row_layout.setContentsMargins(0, 9, 0, 9)
        row_layout.setSpacing(10)

        icon_box = QLabel()
        icon_box.setFixedSize(28, 28)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_box.setPixmap(icons.icon("folder", color=t.TEXT_SECONDARY, size=14).pixmap(14, 14))
        icon_box.setStyleSheet(f"background-color:{t.BG_LAYER2}; border-radius:{t.RADIUS_SM}px;")
        row_layout.addWidget(icon_box)

        name = QLabel(item.case_id)
        name.setObjectName("case_id_label")  # testlerin/cagiranin bulabilmesi icin
        name.setStyleSheet(f"color:{t.TEXT_MAIN}; font-weight:500; font-size:13px;")
        row_layout.addWidget(name)

        if item.is_active:
            active_tag = StatusBadge()
            active_tag.set_status(t.ACCENT_TEXT, "AKTİF")
            row_layout.addWidget(active_tag)

        row_layout.addStretch()
        return cell

    def _refresh_cases(self) -> None:
        if self.config is None:
            self.cases_subtitle.setText("Vaka listesini görmek için önce bir vaka konfigürasyonu yükleyin.")
            self.cases_table.setRowCount(0)
            return

        cases = list_case_summaries(self.config)
        self.cases_subtitle.setText(
            f"{self.config.collection.output_dir} altında {len(cases)} vaka klasörü bulundu."
        )
        self.cases_table.setRowCount(len(cases))
        for row, item in enumerate(cases):
            self.cases_table.setCellWidget(row, 0, self._build_case_cell(item))

            files_text = "—" if item.artifact_count is None else str(item.artifact_count)
            self.cases_table.setItem(row, 1, QTableWidgetItem(files_text))

            chain_badge = StatusBadge()
            if item.chain_valid is None:
                chain_badge.set_status(t.TEXT_SECONDARY, "Defter yok")
            elif item.chain_valid:
                chain_badge.set_status(t.SUCCESS, f"Geçerli · {item.chain_total} olay")
            else:
                chain_badge.set_status(t.ERROR, "GEÇERSİZ")
            self.cases_table.setCellWidget(row, 2, chain_badge)

            findings_text = "—" if item.finding_count is None else str(item.finding_count)
            self.cases_table.setItem(row, 3, QTableWidgetItem(findings_text))
        _fit_rows_to_cell_widgets(self.cases_table)

    # -- Dashboard ----------------------------------------------------------
    def _build_dashboard(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(t.CARD_GAP)

        # Baslik seridi: sayfa adi + vaka bilgisi + zincir rozeti
        head = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("Dashboard")
        title.setStyleSheet(
            f"font-family:'{t.FONT_UI}'; font-size:{t.SIZE_TITLE}px; "
            f"font-weight:600; color:{t.TEXT_MAIN};"
        )
        self.case_subtitle = QLabel("Henüz bir vaka yüklenmedi.")
        self.case_subtitle.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;"
        )
        titles.addWidget(title)
        titles.addWidget(self.case_subtitle)
        head.addLayout(titles)
        head.addStretch()

        # Operator avatari: gercek vaka operatorunun bas harfleri (uydurma
        # bir kullanici resmi degil -- yuklenen konfigurasyondan geliyor).
        self.operator_avatar = QLabel("—")
        self.operator_avatar.setFixedSize(30, 30)
        self.operator_avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.operator_avatar.setToolTip("Henüz vaka yüklenmedi.")
        self.operator_avatar.setStyleSheet(
            f"background-color:{tint(t.ACCENT, 46)}; color:{t.ACCENT_TEXT}; "
            f"border-radius:15px; font-weight:600; font-size:12px;"
        )
        head.addWidget(self.operator_avatar, alignment=Qt.AlignmentFlag.AlignVCenter)
        head.addSpacing(10)

        self.chain_badge = StatusBadge()
        head.addWidget(self.chain_badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(head)

        # Aksiyon seridi
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.load_button = SecondaryButton("Vaka Konfigürasyonu Yükle")
        self.load_button.clicked.connect(self._on_load_config)
        actions.addWidget(self.load_button)
        actions.addSpacing(12)

        self.collect_button = PrimaryButton("Toplamayı Başlat")
        self.route_button = SecondaryButton("Yönlendir")
        self.detect_button = SecondaryButton("Tara")
        self.yara_button = SecondaryButton("YARA Tara")
        self.chainsaw_button = SecondaryButton("Chainsaw Tara")
        self.capa_button = SecondaryButton("capa Tara")
        self.report_button = SecondaryButton("Rapor Üret")
        for button, action in (
            (self.collect_button, _action_collect),
            (self.route_button, _action_route),
            (self.detect_button, _action_detect),
            (self.yara_button, _action_yara_scan),
            (self.chainsaw_button, _action_chainsaw_scan),
            (self.capa_button, _action_capa_scan),
            (self.report_button, _action_report),
        ):
            button.clicked.connect(
                lambda _checked=False, b=button, a=action: self._run_action(b, a)
            )
            actions.addWidget(button)
        actions.addStretch()
        layout.addLayout(actions)

        self.progress = ProgressBar()
        layout.addWidget(self.progress)
        self.status_label = QLabel("Başlamak için bir vaka konfigürasyonu (.yaml) yükleyin.")
        self.status_label.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;"
        )
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Metrik kartlari
        metrics = QHBoxLayout()
        metrics.setSpacing(t.CARD_GAP)
        self.metric_files = self._metric_card("Toplanan Dosya Sayısı", "files")
        self.metric_duration = self._metric_card("İşlem Süresi", "clock")
        self.metric_findings = self._metric_card(
            "Şüpheli Bulgu Sayısı", "alert-triangle", warning=True
        )
        for card_tuple in (self.metric_files, self.metric_duration, self.metric_findings):
            metrics.addWidget(card_tuple[0])
        layout.addLayout(metrics)

        # Defter tablosu
        panel = Card("Delil Zinciri Defteri")
        note = QLabel(
            "Her satır, bir önceki kaydın hash'ine zincirlenmiş bir entry_hash taşır."
        )
        note.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        panel.body.addWidget(note)
        panel.body.addWidget(self._build_table())
        self.table_footer = QLabel("")
        self.table_footer.setStyleSheet(
            f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;"
        )
        panel.body.addWidget(self.table_footer)
        layout.addWidget(panel, stretch=1)
        return page

    def _metric_card(self, label_text: str, icon_name: str, warning: bool = False) -> tuple:
        """Bir metrik karti kurar; (kart, deger etiketi) dondurur.

        Ikon gercek bir SVG'den geliyor (bkz. icons.py) -- tek bir Unicode
        glif/emoji KULLANILMIYOR: chameleon'un kendi gecmisinde (bkz.
        docs/ogrenilenler.md) bu tur glifler headless/bazi ortamlarda kutu
        (tofu) olarak render olabiliyordu, sistemin emoji fontuna dusme
        garantisi yok.
        """
        card = Card()
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        top = QHBoxLayout()
        label = QLabel(label_text)
        label.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        icon_color = t.ERROR if warning else t.TEXT_SECONDARY
        icon_box = QLabel()
        icon_box.setFixedSize(32, 32)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_box.setPixmap(icons.icon(icon_name, color=icon_color, size=16).pixmap(16, 16))
        icon_box.setStyleSheet(
            f"background-color:{tint(icon_color, 36) if warning else t.BG_LAYER2}; "
            f"border-radius:{t.RADIUS_SM}px;"
        )
        top.addWidget(label)
        top.addStretch()
        top.addWidget(icon_box)

        # Uc nokta fazla-secenek menusu: sadece susleme degil, gercek bir
        # eylemi var (deferi panoya kopyalar) -- "etkilesimli gorunen her
        # sey gercekten etkilesimli olmali" ilkesi.
        overflow = QToolButton()
        overflow.setText("⋯")
        overflow.setCursor(Qt.CursorShape.PointingHandCursor)
        overflow.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        overflow.setFixedSize(22, 22)
        overflow.setStyleSheet(f"""
            QToolButton {{
                color: {t.TEXT_SECONDARY};
                background: transparent;
                border: none;
                border-radius: {t.RADIUS_SM}px;
                font-size: 14px;
            }}
            QToolButton:hover {{ background-color: {t.BG_LAYER2}; color: {t.TEXT_MAIN}; }}
            QToolButton::menu-indicator {{ image: none; width: 0; }}
        """)
        menu = QMenu(overflow)
        copy_action = menu.addAction("Değeri Panoya Kopyala")
        overflow.setMenu(menu)
        top.addWidget(overflow)
        card.body.addLayout(top)

        value_row = QHBoxLayout()
        value_row.setSpacing(10)
        value = QLabel("—")
        value.setStyleSheet(
            f"font-family:'{t.FONT_MONO}'; font-size:{t.SIZE_METRIC_VALUE}px; "
            f"font-weight:{t.WEIGHT_METRIC_VALUE}; "
            f"color:{t.ERROR if warning else t.TEXT_MAIN};"
        )
        value_row.addWidget(value)
        delta = QLabel("")
        delta.setStyleSheet(
            f"color:{t.ERROR if warning else t.SUCCESS}; font-size:12px; font-weight:600;"
        )
        value_row.addWidget(delta)
        value_row.addStretch()
        card.body.addLayout(value_row)

        spark_color = t.ERROR if warning else t.ACCENT
        sparkline = Sparkline(spark_color)
        card.body.addWidget(sparkline)

        copy_action.triggered.connect(
            lambda: QGuiApplication.clipboard().setText(value.text())
        )

        return card, value, delta, sparkline

    def _build_table(self) -> QTableWidget:
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["OLAY", "ZAMAN DAMGASI", "SHA-256 HASH", "DURUM"])
        _style_ledger_table(table)
        header = table.horizontalHeader()
        # Sutun 0 ozel bir widget tasiyor -- custody_table'daki ayni gerekce
        # (bkz. yorum orada): ResizeToContents widget genisligini olcemiyor.
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        # Hash sutunu KESILMEMELI: 64 karakterlik entry_hash tam gorunsun.
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        # Sutun 3 de ozel bir widget (StatusBadge) tasiyor -- ayni gerekce.
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table = table
        return table

    # -- Konfigurasyon yukleme ---------------------------------------------
    def _on_load_config(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, "Vaka konfigürasyonu seç", "", "YAML (*.yaml *.yml);;Tüm dosyalar (*.*)"
        )
        if not path:
            return
        self.load_config_file(Path(path))

    def load_config_file(self, path: Path) -> None:
        """Konfigurasyonu yukler ve Dashboard'u tazeler.

        Testler de bunu cagirir (dosya secme diyalogunu atlamak icin).
        """
        try:
            self.config = load_config(path)
        except TriageChainError as exc:
            self.config = None
            self._set_status(str(exc), error=True)
            self._refresh()
            return
        except Exception as exc:  # ham traceback ASLA gosterilmez
            self.config = None
            self._set_status(f"Bir şeyler ters gitti: {exc}", error=True)
            self._refresh()
            return

        self.config_path = Path(path)
        self._set_status(f"Vaka yüklendi: {self.config.case.case_id}")
        self._refresh()

    # -- Aksiyonlar ---------------------------------------------------------
    def _run_action(self, button: QPushButton, action: Callable[[Any], str]) -> None:
        if self.config is None or (self._worker is not None and self._worker.isRunning()):
            return
        self._set_buttons_enabled(False)
        self.progress.set_indeterminate()
        self._set_status(f"{button.text()} çalışıyor...")

        self._worker = ActionWorker(action, self.config, parent=self)
        self._worker.done.connect(self._on_action_done)
        self._worker.failed.connect(self._on_action_failed)
        self._worker.start()

    def _on_action_done(self, message: str) -> None:
        self.progress.set_determinate(100)
        self._set_status(message)
        self._refresh()

    def _on_action_failed(self, message: str) -> None:
        self.progress.set_determinate(0)
        self._set_status(message, error=True)
        self._refresh()

    def _set_status(self, message: str, error: bool = False) -> None:
        self.status_label.setText(message)
        color = t.ERROR if error else t.TEXT_SECONDARY
        self.status_label.setStyleSheet(f"color:{color}; font-size:{t.SIZE_HELPER}px;")

    def _set_buttons_enabled(self, enabled: bool) -> None:
        """Aksiyon butonlarinin acik/kapali halini kurallara gore ayarlar.

        enabled=False (kosu suruyor) her seyi kapatir; True ise vaka yuklu
        olmasi sarti, route/detect/report icin ayrica manifest sarti aranir.
        """
        has_config = enabled and self.config is not None
        needs_manifest = has_config and self.snapshot.has_manifest
        self.load_button.setEnabled(enabled)
        self.collect_button.setEnabled(has_config)
        # Neden kapali oldugu buton uzerinde de yazsin -- yoksa kullanici
        # "neden tiklanmiyor" diye kalir.
        tip = "" if needs_manifest else "Önce toplama çalışmalı (manifest.json yok)."
        for button in (
            self.route_button, self.detect_button, self.yara_button,
            self.chainsaw_button, self.capa_button, self.report_button,
        ):
            button.setEnabled(needs_manifest)
            button.setToolTip(tip)

    # -- Tazeleme -----------------------------------------------------------
    def _refresh(self) -> None:
        """Diskteki dosyalari yeniden okuyup butun Dashboard'u gunceller."""
        self.snapshot = read_snapshot(self.config) if self.config is not None else CaseSnapshot()
        self._set_buttons_enabled(True)
        self._refresh_header()
        self._refresh_metrics()
        self._refresh_table()
        self._refresh_files()
        self._refresh_custody()
        self._refresh_findings()
        self._refresh_reports()
        self._refresh_cases()
        if self.snapshot.warning:
            self._set_status(self.snapshot.warning, error=True)

    def _refresh_header(self) -> None:
        if self.config is None:
            self.case_pill.setText("Vaka yüklenmedi")
            self.case_subtitle.setText("Henüz bir vaka yüklenmedi.")
            self.chain_badge.set_status(t.TEXT_SECONDARY, "Henüz vaka yüklenmedi")
            self.operator_avatar.setText("—")
            self.operator_avatar.setToolTip("Henüz vaka yüklenmedi.")
            self.load_button.setText("Vaka Konfigürasyonu Yükle")
            return

        case = self.config.case
        self.case_pill.setText(case.case_id)
        self.case_subtitle.setText(f"{case.case_id} · operatör: {case.operator}")
        # Avatar UYDURULMUS bir profil resmi degil: gercek operator adinin
        # bas harfleri (2+ kelime varsa ilk ikisinin ilk harfi, tek kelimeyse
        # o kelimenin ilk iki karakteri, bos ise "?").
        parts = case.operator.split()
        if len(parts) >= 2:
            initials = (parts[0][0] + parts[1][0]).upper()
        elif parts:
            initials = parts[0][:2].upper()
        else:
            initials = "?"
        self.operator_avatar.setText(initials)
        self.operator_avatar.setToolTip(f"Operatör: {case.operator}")
        self.load_button.setText("Vaka Değiştir")

        if self.snapshot.chain_valid is None:
            self.chain_badge.set_status(t.TEXT_SECONDARY, "Defter henüz yok")
        elif self.snapshot.chain_valid:
            self.chain_badge.set_status(
                t.SUCCESS, f"Zincir Geçerli · {self.snapshot.chain_total} olay"
            )
        else:
            self.chain_badge.set_status(
                t.ERROR, f"Zincir GEÇERSİZ · {self.snapshot.chain_total}. olayda kırılma"
            )

    def _refresh_metrics(self) -> None:
        def as_text(value) -> str:
            return "—" if value is None else str(value)

        snap = self.snapshot
        for (card, value, delta, sparkline), text, delta_text, trend in (
            (self.metric_files, as_text(snap.artifact_count), snap.files_delta, snap.files_trend),
            (
                self.metric_duration,
                as_text(snap.duration_text),
                snap.duration_delta,
                snap.duration_trend,
            ),
            (
                self.metric_findings,
                as_text(snap.finding_count),
                snap.findings_delta,
                snap.findings_trend,
            ),
        ):
            value.setText(text)
            # "~" oneki referans tasarimdaki kucuk trend isaretiyle ayni
            # gorsel dili tasir (bkz. aldigim_kararlar.md) -- CaseSnapshot'daki
            # ham delta_text degismiyor (testler/mantik hala onu kullanir),
            # "~" SADECE bu gosterim katmaninda ekleniyor.
            delta.setText(f"~ {delta_text}" if delta_text else "")
            delta.setVisible(bool(delta_text))
            sparkline.set_values(trend)

    def _build_event_cell(self, event) -> QWidget:
        """Ikon + olay adi (kalin) + detay (soluk, ikinci satir) -- HTML
        maketteki `.event-cell`/`.event-name`/`.event-detail` yapisiyla ayni."""
        cell = QWidget()
        row_layout = QHBoxLayout(cell)
        row_layout.setContentsMargins(0, 9, 0, 9)
        row_layout.setSpacing(10)

        icon_box = QLabel()
        icon_box.setFixedSize(28, 28)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_name = _EVENT_ICONS.get(event.event_type, "check-circle")
        icon_box.setPixmap(
            icons.icon(icon_name, color=t.TEXT_SECONDARY, size=14).pixmap(14, 14)
        )
        icon_box.setStyleSheet(f"background-color:{t.BG_LAYER2}; border-radius:{t.RADIUS_SM}px;")
        row_layout.addWidget(icon_box)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)
        name = QLabel(EVENT_LABELS.get(event.event_type, event.event_type))
        name.setObjectName("event_name")  # testlerin/cagiranin bulabilmesi icin
        name.setStyleSheet(f"color:{t.TEXT_MAIN}; font-weight:500; font-size:13px;")
        text_col.addWidget(name)
        detail_text = _event_detail(event)
        if detail_text:
            detail = QLabel(detail_text)
            detail.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:11px;")
            text_col.addWidget(detail)
        row_layout.addLayout(text_col)
        row_layout.addStretch()
        return cell

    def _refresh_table(self) -> None:
        events = self.snapshot.events
        shown = events[-MAX_TABLE_ROWS:]
        first_index = len(events) - len(shown) + 1  # 1'den baslayan sira no
        self.table.setRowCount(len(shown))

        for row, event in enumerate(shown):
            order = first_index + row
            self.table.setCellWidget(row, 0, self._build_event_cell(event))
            stamp = event.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S")
            self.table.setItem(row, 1, QTableWidgetItem(stamp))
            hash_label = MonoLabel(event.entry_hash)
            hash_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.table.setCellWidget(row, 2, hash_label)

            badge = StatusBadge()
            # Per-event dogrulama YAPILMIYOR: verify_chain zincirin tamamina
            # bakip ilk kirilmayi bildiriyor, o noktadan SONRAKI her kayit
            # supheli sayiliyor.
            broken = self.snapshot.broken_at_index
            if broken is not None and order >= broken:
                badge.set_status(t.ERROR, "Şüpheli")
            else:
                badge.set_status(t.SUCCESS, "Doğrulandı")
            self.table.setCellWidget(row, 3, badge)

        _fit_rows_to_cell_widgets(self.table)
        if not events:
            self.table_footer.setText("Defterde henüz olay yok.")
        elif len(shown) < len(events):
            self.table_footer.setText(
                f"toplam {len(events)} olay, son {len(shown)} gösteriliyor"
            )
        else:
            self.table_footer.setText(f"{len(events)} olay gösteriliyor")
