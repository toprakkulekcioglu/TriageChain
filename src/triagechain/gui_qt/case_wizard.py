"""KAPE tarzi 'Yeni Vaka' sihirbazi -- YAML'i kullanici gormeden uretir.

Onceki akis (kullanicinin elle bir YAML dosyasi hazirlayip 'Vaka
Konfigurasyonu Yukle' ile secmesi) gercek kullanicilar icin gecerli bir
arayuz DEGIL -- herkes YAML duzenlemeyi bilmez. Bu sihirbaz KAPE'nin kendi
GUI'sindeki (gkape) "target source" + "target destination" ikilisini
taklit eder: kullanici sadece dosya/klasor secer, TriageChain arka planda
gecerli bir TriageChainConfig insa edip diske yazar; cagiran taraf
(main_window.py) bunu hemen yukler -- kullanici hicbir zaman ham YAML
gormez (bkz. docs/aldigim_kararlar.md).

TOPLU VAKA OLUSTURMA: gercek KAPE `--zip` ciktisi (kullanicinin kendi test
verisiyle dogrulandi) TEK bir arsivin icinde BIRDEN FAZLA makine icerebilir
(orn. '<zaman-damgasi>_user/', '<zaman-damgasi>_server/', '..._domain/' --
her biri kendi 'C/' surucu kokunu tasir). Kullanici bunlari TEK TEK sihirbazi
3 kez calistirarak elle sececek olsaydi bu da YAML'i elle yazmak kadar
sikici olurdu -- bu yuzden kaynak kok klasorunde 2+ alt klasor bulunursa
sihirbaz bunlari otomatik "aday makine" olarak listeler, kullanici hangilerinin
ayri birer vaka olarak toplanacagini onay kutulariyla secer ve HEPSI TEK
SEFERDE (ayri vaka kimlikleriyle) uretilir.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Optional

import yaml
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from triagechain.collection import catalog as catalog_module
from triagechain.collection.selector import load_catalog
from triagechain.config.schema import TriageChainConfig
from triagechain.core.case import validate_case_id
from triagechain.core.errors import ConfigError
from triagechain.gui_qt import theme as t
from triagechain.gui_qt.widgets import Card, Input, MonoInput, MonoLabel, PrimaryButton, SecondaryButton

# router/detection katmanlarinin aradigi .exe adlari -- "Arac Klasoru"
# secilince bu klasor altinda REKURSIF aranir. Sadece dosya ADI biliniyor
# (EricZimmerman ve Yamato-Security/WithSecure araclarinin resmi dagitim
# adlari); hangi surumun kurulu oldugu varsayilmiyor.
_TOOL_FILENAMES = {
    "mftecmd": "MFTECmd.exe",
    "recmd": "RECmd.exe",
    "evtxecmd": "EvtxECmd.exe",
    "pecmd": "PECmd.exe",
}
_HAYABUSA_GLOB = "hayabusa*.exe"
_YARA_GLOB = "yara64.exe"
_CHAINSAW_GLOB = "chainsaw*.exe"
_CAPA_GLOB = "capa.exe"

# KAPE --zip klasor adlari '<ISO-zaman-damgasi>_<rol>' bicimindedir (orn.
# '2026-06-07T220139_user'); vaka kimligi eki turetilirken zaman damgasi
# kismi atilir, sadece rol (anlamli kisim) kalir.
_TIMESTAMP_PREFIX = re.compile(r"^\d{4}-?\d{2}-?\d{2}T?\d{2}:?\d{2}:?\d{2}_?")


def _find_first(root: Path, filename_glob: str) -> Optional[str]:
    matches = list(root.rglob(filename_glob))
    return str(matches[0]) if matches else None


def autodetect_tools(root: Path) -> dict:
    """Verilen klasor altinda bilinen arac ikililerini arar.

    Bulunamayan arac hata DEGIL -- router/detection katmanlari zaten
    tanimsiz araci "atlandi" olarak ele aliyor (bkz. config/schema.py'deki
    Optional alanlar). Bu fonksiyon sadece kullaniciyi elle yol yazmaktan
    kurtarir; hicbir sey bulamazsa bos sozlukler doner, config yine gecerli
    kalir.
    """
    router_tools: dict[str, str] = {}
    for name, filename in _TOOL_FILENAMES.items():
        path = _find_first(root, filename)
        if path:
            router_tools[name] = path

    detection: dict[str, str] = {}
    hayabusa = _find_first(root, _HAYABUSA_GLOB)
    if hayabusa:
        detection["hayabusa_path"] = hayabusa
        rules_dirs = [p for p in root.rglob("rules") if p.is_dir()]
        if rules_dirs:
            detection["rules_dir"] = str(rules_dirs[0])

    yara = _find_first(root, _YARA_GLOB)
    if yara:
        detection["yara_path"] = yara

    chainsaw = _find_first(root, _CHAINSAW_GLOB)
    if chainsaw:
        detection["chainsaw_path"] = chainsaw
        mapping = list(root.rglob("sigma-event-logs-all.yml"))
        if mapping:
            detection["chainsaw_mapping_file"] = str(mapping[0])

    capa = _find_first(root, _CAPA_GLOB)
    if capa:
        detection["capa_path"] = capa

    return {"router_tools": router_tools, "detection": detection}


def detect_machine_roots(root: Path) -> list[Path]:
    """root altindaki dogrudan alt klasorleri dondurur (gizli klasorler haric).

    Cagiran taraf bunu yalnizca 2+ sonuc doneceginde "birden fazla makine"
    olarak yorumlar -- gercek KAPE --zip ciktisinda zip koku birden fazla
    '<zaman-damgasi>_<rol>' klasoru icerdiginde tam olarak bu sekle sahip.
    """
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))


def resolve_drive_root(path: Path) -> Path:
    """Bir makine kokunun altinda tek harfli bir surucu klasoru varsa onu dondurur.

    Gercek KAPE --zip ciktisinin katman yapisi budur: '<zaman-damgasi>_<rol>\\C\\...'
    -- katalogdaki tum hedef yollari '%SystemDrive%\\...' (yani 'C:\\...')
    seklinde tanimli oldugu icin source_root'un tam olarak bu 'C' klasorunu
    gostermesi gerekir, bir ust klasoru degil. Boyle bir klasor yoksa (ornegin
    kullanici zaten doğrudan 'C' klasorunu secmisse) path'in kendisi donuyor.
    """
    if not path.is_dir():
        return path
    drive_dirs = [p for p in path.iterdir() if p.is_dir() and re.fullmatch(r"[A-Za-z]", p.name)]
    if len(drive_dirs) == 1:
        return drive_dirs[0]
    return path


def derive_case_suffix(folder_name: str) -> str:
    """Bir makine klasor adindan vaka kimligi eki turetir (bkz. modul basi notu)."""
    stripped = _TIMESTAMP_PREFIX.sub("", folder_name)
    candidate = stripped or folder_name
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "-", candidate).strip("-").upper()
    return sanitized or "VAKA"


class NewCaseDialog(QDialog):
    """Vaka bilgisi + kaynak/hedef secimini alir, YAML'i sessizce uretip yukler.

    Kabul edildiginde (exec() == Accepted) `generated_config_paths` uretilen
    YAML dosyalarinin (bir veya toplu modda birden fazla) yollarini tasir --
    cagiran taraf ilkini load_config_file()'a verir.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Yeni Vaka Oluştur")
        self.setMinimumSize(660, 700)
        self.setStyleSheet(f"QDialog {{ background-color: {t.BG_DARKEST}; }}")

        self._source_root: Optional[Path] = None
        self._output_dir: Optional[Path] = None
        self._tools_root: Optional[Path] = None
        self._autodetected: dict = {"router_tools": {}, "detection": {}}
        self._batch_roots: list[Path] = []
        self._machine_checkboxes: dict[Path, QCheckBox] = {}
        self.generated_config_paths: list[Path] = []
        # Geriye donuk: eski cagiranlar tek yol bekleyebilir.
        self.generated_config_path: Optional[Path] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        heading = QLabel("Yeni Vaka Oluştur")
        heading.setStyleSheet(
            f"color:{t.TEXT_MAIN}; font-size:{t.SIZE_TITLE}px; font-weight:700;"
        )
        outer.addWidget(heading)
        subheading = QLabel(
            "Dosya/klasör seçin -- konfigürasyon dosyası arka planda üretilir, "
            "elle YAML yazmanız gerekmez. Seçtiğiniz kaynak birden fazla makine "
            "içeriyorsa (örn. bir KAPE arşivinin kökü) her biri ayrı bir vaka "
            "olarak tek seferde oluşturulabilir."
        )
        subheading.setWordWrap(True)
        subheading.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        outer.addWidget(subheading)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(t.CARD_GAP)
        content_layout.setContentsMargins(0, 0, 0, 4)

        content_layout.addWidget(self._build_case_card())
        content_layout.addWidget(self._build_source_card())
        content_layout.addWidget(self._build_output_card())
        content_layout.addWidget(self._build_targets_card())
        content_layout.addWidget(self._build_tools_card())
        content_layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet(f"color:{t.ERROR}; font-size:{t.SIZE_HELPER}px;")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        outer.addWidget(self.error_label)

        footer = QHBoxLayout()
        footer.addStretch()
        cancel_btn = SecondaryButton("Vazgeç")
        cancel_btn.clicked.connect(self.reject)
        create_btn = PrimaryButton("Vakayı Oluştur")
        create_btn.clicked.connect(self._on_create)
        footer.addWidget(cancel_btn)
        footer.addWidget(create_btn)
        outer.addLayout(footer)

    # -- Kart insaatcilari ---------------------------------------------------
    def _labeled(self, text: str, widget: QWidget) -> QWidget:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        label = QLabel(text)
        label.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        layout.addWidget(label)
        layout.addWidget(widget)
        return wrap

    def _build_case_card(self) -> Card:
        card = Card("Vaka Bilgisi")
        self.case_id_input = MonoInput("örn. FINAL-LAB")
        self.operator_input = Input("örn. yasar")
        self.description_input = Input("Kısa açıklama (opsiyonel)")
        card.body.addWidget(self._labeled("Vaka Kimliği (toplu modda önek olur)", self.case_id_input))
        card.body.addWidget(self._labeled("Operatör", self.operator_input))
        card.body.addWidget(self._labeled("Açıklama", self.description_input))
        return card

    def _build_source_card(self) -> Card:
        card = Card("Kaynak")
        hint = QLabel(
            "Canlı sistem: TriageChain bu makinenin kendi diskinden toplar (VSS ile).\n"
            "Önceden toplanmış veri: KAPE gibi başka bir araçla ZATEN toplanmış bir "
            "klasörü ya da ZIP'i içe aktarır -- canlı sisteme gerek kalmaz. Seçilen "
            "klasörün altında birden fazla alt klasör bulunursa (örn. birden fazla "
            "makinenin KAPE çıktısı), aşağıda hangilerinin ayrı vaka olacağını "
            "seçebilirsiniz."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        card.body.addWidget(hint)

        self.mode_group = QButtonGroup(card)
        self.live_radio = QRadioButton("Canlı sistem")
        self.import_radio = QRadioButton("Önceden toplanmış veri (klasör veya ZIP)")
        for radio in (self.live_radio, self.import_radio):
            radio.setStyleSheet(f"color:{t.TEXT_MAIN}; font-size:{t.SIZE_BODY}px;")
            self.mode_group.addButton(radio)
        self.import_radio.setChecked(True)
        card.body.addWidget(self.live_radio)
        card.body.addWidget(self.import_radio)

        picker_row = QHBoxLayout()
        self._pick_folder_btn = SecondaryButton("Kök Klasör Seç…")
        self._pick_folder_btn.clicked.connect(self._on_pick_source_folder)
        self._pick_zip_btn = SecondaryButton("ZIP Seç…")
        self._pick_zip_btn.clicked.connect(self._on_pick_source_zip)
        picker_row.addWidget(self._pick_folder_btn)
        picker_row.addWidget(self._pick_zip_btn)
        picker_row.addStretch()
        card.body.addLayout(picker_row)

        self.source_path_label = MonoLabel("Henüz kaynak seçilmedi.")
        self.source_path_label.setWordWrap(True)
        card.body.addWidget(self.source_path_label)

        # Toplu mod onay kutulari -- bos baslar, kaynak seciminde doldurulur.
        self._batch_box = QWidget()
        self._batch_layout = QGridLayout(self._batch_box)
        self._batch_layout.setHorizontalSpacing(16)
        self._batch_layout.setVerticalSpacing(4)
        card.body.addWidget(self._batch_box)

        self.live_radio.toggled.connect(self._on_mode_toggled)
        return card

    def _on_mode_toggled(self, live_checked: bool) -> None:
        self._pick_folder_btn.setEnabled(not live_checked)
        self._pick_zip_btn.setEnabled(not live_checked)
        if live_checked:
            self.source_path_label.setText("Canlı sistem seçildi -- ek bir kaynak gerekmez.")
        elif self._source_root is None:
            self.source_path_label.setText("Henüz kaynak seçilmedi.")
        else:
            self.source_path_label.setText(str(self._source_root))

    def _on_pick_source_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Toplanmış veri kök klasörünü seç")
        if not path:
            return
        self._set_source_root(Path(path))

    def _on_pick_source_zip(self) -> None:
        zip_path, _filter = QFileDialog.getOpenFileName(
            self, "ZIP arşivi seç", "", "ZIP arşivleri (*.zip)"
        )
        if not zip_path:
            return
        dest = QFileDialog.getExistingDirectory(self, "ZIP nereye çıkartılsın?")
        if not dest:
            return
        dest_path = Path(dest)
        try:
            with zipfile.ZipFile(zip_path) as archive:
                archive.extractall(dest_path)
        except (zipfile.BadZipFile, OSError) as exc:
            self._show_error(f"ZIP çıkartılamadı: {exc}")
            return
        self._set_source_root(dest_path)

    def _set_source_root(self, root: Path) -> None:
        self._source_root = root
        machine_roots = detect_machine_roots(root)
        self._clear_batch_checkboxes()
        if len(machine_roots) >= 2:
            self._batch_roots = machine_roots
            self.source_path_label.setText(
                f"{root}\n{len(machine_roots)} alt klasör tespit edildi -- aşağıdan "
                "ayrı vaka olarak toplanacakları seçin."
            )
            self._populate_batch_checkboxes(machine_roots)
        else:
            self._batch_roots = []
            self.source_path_label.setText(str(resolve_drive_root(root)))

    def _clear_batch_checkboxes(self) -> None:
        while self._batch_layout.count():
            item = self._batch_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._machine_checkboxes = {}

    def _populate_batch_checkboxes(self, machine_roots: list[Path]) -> None:
        for index, machine_root in enumerate(machine_roots):
            box = QCheckBox(machine_root.name)
            box.setChecked(True)
            box.setStyleSheet(f"color:{t.TEXT_MAIN}; font-size:{t.SIZE_HELPER}px;")
            suffix = derive_case_suffix(machine_root.name)
            box.setToolTip(f"Vaka kimliği: <temel>-{suffix}")
            self._machine_checkboxes[machine_root] = box
            self._batch_layout.addWidget(box, index // 2, index % 2)

    def _build_output_card(self) -> Card:
        card = Card("Çıktı Dizini")
        row = QHBoxLayout()
        self.output_dir_label = MonoLabel("Henüz seçilmedi.")
        self.output_dir_label.setWordWrap(True)
        pick_btn = SecondaryButton("Klasör Seç…")
        pick_btn.clicked.connect(self._on_pick_output_dir)
        row.addWidget(self.output_dir_label, stretch=1)
        row.addWidget(pick_btn)
        card.body.addLayout(row)
        return card

    def _on_pick_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Çıktı dizinini seç")
        if not path:
            return
        self._output_dir = Path(path)
        self.output_dir_label.setText(str(self._output_dir))

    def _build_targets_card(self) -> Card:
        card = Card("Toplanacak Artefaktlar")
        catalog = load_catalog(catalog_module.default_catalog_path())
        self.target_checkboxes: dict[str, QCheckBox] = {}
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(6)
        for index, (target_id, entry) in enumerate(catalog.items()):
            box = QCheckBox(entry.get("description", target_id))
            box.setChecked(True)
            box.setStyleSheet(f"color:{t.TEXT_MAIN}; font-size:{t.SIZE_HELPER}px;")
            box.setToolTip(target_id)
            self.target_checkboxes[target_id] = box
            grid.addWidget(box, index // 2, index % 2)
        wrap = QWidget()
        wrap.setLayout(grid)
        card.body.addWidget(wrap)
        return card

    def _build_tools_card(self) -> Card:
        card = Card("Araçlar (opsiyonel)")
        hint = QLabel(
            "MFTECmd/RECmd/EvtxECmd/PECmd/Hayabusa/YARA/Chainsaw/capa gibi "
            "araçları kurduğunuz bir klasör varsa seçin -- TriageChain bu "
            "klasör altında bilinen araç isimlerini otomatik arar. Boş "
            "bırakılırsa o araca bağlı adımlar atlanır, sonradan konfigürasyon "
            "dosyası düzenlenerek de eklenebilir."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{t.TEXT_SECONDARY}; font-size:{t.SIZE_HELPER}px;")
        card.body.addWidget(hint)

        row = QHBoxLayout()
        self.tools_dir_label = MonoLabel("Henüz seçilmedi.")
        self.tools_dir_label.setWordWrap(True)
        pick_btn = SecondaryButton("Araç Klasörü Seç…")
        pick_btn.clicked.connect(self._on_pick_tools_dir)
        row.addWidget(self.tools_dir_label, stretch=1)
        row.addWidget(pick_btn)
        card.body.addLayout(row)
        return card

    def _on_pick_tools_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Araç klasörünü seç")
        if not path:
            return
        self._tools_root = Path(path)
        self._autodetected = autodetect_tools(self._tools_root)
        found = len(self._autodetected["router_tools"]) + len(self._autodetected["detection"])
        if found:
            self.tools_dir_label.setText(f"{self._tools_root}  ({found} araç/ayar bulundu)")
        else:
            self.tools_dir_label.setText(f"{self._tools_root}  (bilinen araç bulunamadı)")

    # -- Olusturma ------------------------------------------------------------
    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.show()

    def _on_create(self) -> None:
        self.error_label.hide()

        base_case_id = self.case_id_input.text().strip()
        operator = self.operator_input.text().strip()
        description = self.description_input.text().strip()
        try:
            validate_case_id(base_case_id)
        except ConfigError as exc:
            self._show_error(str(exc))
            return
        if not operator:
            self._show_error("Operatör alanı boş bırakılamaz.")
            return

        if self._output_dir is None:
            self._show_error("Çıktı dizini seçilmedi.")
            return

        is_import = self.import_radio.isChecked()
        if is_import and self._source_root is None:
            self._show_error("İçe aktarma modu seçildi ama kaynak (klasör/ZIP) seçilmedi.")
            return

        targets = [tid for tid, box in self.target_checkboxes.items() if box.isChecked()]
        if not targets:
            self._show_error("En az bir artefakt seçilmeli.")
            return

        # (vaka_kimligi, source_root veya None) listesi -- toplu modda birden
        # fazla, tekli modda tek eleman.
        selected_machine_roots = [
            root for root, box in self._machine_checkboxes.items() if box.isChecked()
        ] if is_import else []

        if is_import and self._batch_roots and not selected_machine_roots:
            self._show_error("En az bir alt klasör (vaka) seçilmeli.")
            return

        plan: list[tuple[str, Optional[Path]]] = []
        if selected_machine_roots:
            for machine_root in selected_machine_roots:
                case_id = f"{base_case_id}-{derive_case_suffix(machine_root.name)}"
                try:
                    validate_case_id(case_id)
                except ConfigError as exc:
                    self._show_error(str(exc))
                    return
                plan.append((case_id, resolve_drive_root(machine_root)))
        else:
            source_root = resolve_drive_root(self._source_root) if is_import else None
            plan.append((base_case_id, source_root))

        case_ids = [case_id for case_id, _ in plan]
        if len(set(case_ids)) != len(case_ids):
            self._show_error(
                "Seçilen alt klasörler aynı vaka kimliğini üretiyor -- vaka "
                "kimliğini değiştirin veya farklı bir klasör seçin."
            )
            return

        # Once TUMUNU dogrula, sonra TUMUNU yaz -- yarim/tutarsiz bir vaka
        # kumesi diske yazilmasin.
        planned_configs: list[tuple[str, Path, dict]] = []
        for case_id, source_root in plan:
            collection: dict = {"targets": targets, "output_dir": str(self._output_dir)}
            if source_root is not None:
                collection["source_root"] = str(source_root)
            config_dict: dict = {
                "case": {"case_id": case_id, "operator": operator, "description": description},
                "collection": collection,
                "router": {"tools": self._autodetected["router_tools"]},
                "detection": self._autodetected["detection"],
            }
            try:
                TriageChainConfig(**config_dict)
            except Exception as exc:  # pydantic ValidationError -- ham traceback gosterilmez
                self._show_error(f"'{case_id}' için konfigürasyon geçersiz: {exc}")
                return
            config_path = self._output_dir / f"{case_id}_config.generated.yaml"
            planned_configs.append((case_id, config_path, config_dict))

        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            for _case_id, config_path, config_dict in planned_configs:
                config_path.write_text(
                    yaml.safe_dump(config_dict, allow_unicode=True, sort_keys=False),
                    encoding="utf-8",
                )
        except OSError as exc:
            self._show_error(f"Konfigürasyon dosyası yazılamadı: {exc}")
            return

        self.generated_config_paths = [path for _cid, path, _cfg in planned_configs]
        self.generated_config_path = self.generated_config_paths[0]
        self.accept()
