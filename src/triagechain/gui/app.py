"""TriageChain icin basit calistirma arayuzu.

Bilincli olarak sade: sadece mevcut CLI islevlerini (collect, verify-custody)
bir form + log panelinden calistirir. Gorsel tasarim ilerleyen bir asamada
profesyonellestirilecek - burada oncelik islevsellik ve dogruluk.

Sadece stdlib kullanir (tkinter); projenin bagimlilik listesine bir sey
eklemez.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

import yaml

from triagechain.collection import catalog as catalog_module
from triagechain.collection.collector import run_collection
from triagechain.collection.selector import load_catalog
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.core.errors import ConfigError, CustodyLedgerError, IntegrityError, TriageChainError
from triagechain.custody.ledger import CustodyLedger, verify_chain

HASH_ALGORITHMS = ("sha256", "sha1", "md5")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class _QueueLogHandler(logging.Handler):
    """Logging kayitlarini arka plan is parcacigindan ana is parcacigina tasir.

    Tkinter widget'lari sadece ana (GUI) is parcacigindan guncellenebilir;
    toplama arka planda ayri bir thread'de calistigi icin logger mesajlari
    dogrudan widget'a yazilamaz, once bu kuyruga konur.
    """

    def __init__(self, message_queue: "queue.Queue[str]") -> None:
        super().__init__()
        self._queue = message_queue

    def emit(self, record: logging.LogRecord) -> None:
        self._queue.put(self.format(record))


class TriageChainApp:
    """Vaka bilgisi + hedef secimi + calistir/dogrula panelinden olusan basit arayuz."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("TriageChain - Basit Calistirma Araci")
        self.root.geometry("760x640")

        self._message_queue: "queue.Queue[str]" = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        self._target_vars: dict[str, tk.BooleanVar] = {}

        self._build_widgets()
        self._load_catalog_checkboxes()
        self.root.after(100, self._poll_queue)

    # ------------------------------------------------------------------ UI kurulumu

    def _build_widgets(self) -> None:
        pad = {"padx": 8, "pady": 4}

        case_frame = ttk.LabelFrame(self.root, text="Vaka Bilgileri")
        case_frame.pack(fill="x", **pad)

        self.case_id_var = tk.StringVar(value="CASE-0001")
        self.operator_var = tk.StringVar()
        self.description_var = tk.StringVar()

        self._labeled_entry(case_frame, "Vaka No (case_id):", self.case_id_var, 0)
        self._labeled_entry(case_frame, "Operator:", self.operator_var, 1)
        self._labeled_entry(case_frame, "Aciklama:", self.description_var, 2)

        targets_frame = ttk.LabelFrame(self.root, text="Toplanacak Hedefler")
        targets_frame.pack(fill="x", **pad)
        self._targets_container = ttk.Frame(targets_frame)
        self._targets_container.pack(fill="x", padx=4, pady=4)

        settings_frame = ttk.LabelFrame(self.root, text="Ayarlar")
        settings_frame.pack(fill="x", **pad)

        ttk.Label(settings_frame, text="Hash algoritmasi:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.hash_algo_var = tk.StringVar(value="sha256")
        ttk.Combobox(
            settings_frame, textvariable=self.hash_algo_var, values=HASH_ALGORITHMS,
            state="readonly", width=10,
        ).grid(row=0, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(settings_frame, text="Log seviyesi:").grid(row=0, column=2, sticky="w", padx=6, pady=4)
        self.log_level_var = tk.StringVar(value="INFO")
        ttk.Combobox(
            settings_frame, textvariable=self.log_level_var, values=LOG_LEVELS,
            state="readonly", width=10,
        ).grid(row=0, column=3, sticky="w", padx=6, pady=4)

        ttk.Label(settings_frame, text="Cikti dizini:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.output_dir_var = tk.StringVar(value=str(Path.home() / "TriageChain" / "output"))
        ttk.Entry(settings_frame, textvariable=self.output_dir_var, width=48).grid(
            row=1, column=1, columnspan=2, sticky="we", padx=6, pady=4
        )
        ttk.Button(settings_frame, text="Sec...", command=self._browse_output_dir).grid(
            row=1, column=3, sticky="w", padx=6, pady=4
        )

        ttk.Label(settings_frame, text="Custody log (bos = otomatik):").grid(
            row=2, column=0, sticky="w", padx=6, pady=4
        )
        self.custody_log_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.custody_log_var, width=48).grid(
            row=2, column=1, columnspan=2, sticky="we", padx=6, pady=4
        )
        ttk.Button(settings_frame, text="Sec...", command=self._browse_custody_log).grid(
            row=2, column=3, sticky="w", padx=6, pady=4
        )

        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill="x", **pad)
        ttk.Button(button_frame, text="Konfigurasyon Yukle", command=self._on_load_config).pack(
            side="left", padx=4
        )
        ttk.Button(button_frame, text="Konfigurasyonu Kaydet", command=self._on_save_config).pack(
            side="left", padx=4
        )
        self.collect_button = ttk.Button(
            button_frame, text="Toplamayi Baslat", command=self._on_collect
        )
        self.collect_button.pack(side="left", padx=4)
        ttk.Button(button_frame, text="Zinciri Dogrula", command=self._on_verify).pack(
            side="left", padx=4
        )

        self.status_var = tk.StringVar(value="Hazir.")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w").pack(fill="x", padx=8)

        log_frame = ttk.LabelFrame(self.root, text="Islem Gunlugu")
        log_frame.pack(fill="both", expand=True, **pad)
        self.log_text = scrolledtext.ScrolledText(log_frame, state="disabled", height=16)
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

    def _labeled_entry(self, parent: ttk.LabelFrame, label: str, var: tk.StringVar, row: int) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(parent, textvariable=var, width=50).grid(row=row, column=1, sticky="we", padx=6, pady=4)

    def _load_catalog_checkboxes(self) -> None:
        """Gomulu katalogdaki her hedef icin bir onay kutusu olusturur."""
        try:
            catalog = load_catalog(catalog_module.default_catalog_path())
        except TriageChainError as exc:
            self._append_log(f"Katalog okunamadi: {exc}")
            return

        for index, (target_id, entry) in enumerate(sorted(catalog.items())):
            var = tk.BooleanVar(value=True)
            self._target_vars[target_id] = var
            text = f"{target_id}  -  {entry.get('description', '')}"
            ttk.Checkbutton(self._targets_container, text=text, variable=var).grid(
                row=index // 2, column=index % 2, sticky="w", padx=6, pady=2
            )

    # ------------------------------------------------------------------ Dosya secimleri

    def _browse_output_dir(self) -> None:
        chosen = filedialog.askdirectory(title="Cikti dizinini sec")
        if chosen:
            self.output_dir_var.set(chosen)

    def _browse_custody_log(self) -> None:
        chosen = filedialog.asksaveasfilename(
            title="Custody log dosyasi",
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("Tum dosyalar", "*.*")],
        )
        if chosen:
            self.custody_log_var.set(chosen)

    # ------------------------------------------------------------------ Konfigurasyon yukle/kaydet

    def _selected_targets(self) -> list[str]:
        return [target_id for target_id, var in self._target_vars.items() if var.get()]

    def _build_config_dict(self) -> dict:
        return {
            "case": {
                "case_id": self.case_id_var.get().strip(),
                "operator": self.operator_var.get().strip(),
                "description": self.description_var.get().strip(),
            },
            "collection": {
                "targets": self._selected_targets(),
                "hash_algorithm": self.hash_algo_var.get(),
                "output_dir": self.output_dir_var.get().strip(),
            },
            "custody": {
                "log_path": self.custody_log_var.get().strip() or None,
            },
            "logging": {
                "level": self.log_level_var.get(),
            },
        }

    def _on_save_config(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Konfigurasyonu kaydet",
            defaultextension=".yaml",
            filetypes=[("YAML", "*.yaml *.yml"), ("Tum dosyalar", "*.*")],
        )
        if not path:
            return
        try:
            Path(path).write_text(
                yaml.safe_dump(self._build_config_dict(), sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror("Hata", f"Konfigurasyon yazilamadi: {exc}")
            return
        self._append_log(f"Konfigurasyon kaydedildi: {path}")

    def _on_load_config(self) -> None:
        path = filedialog.askopenfilename(
            title="Konfigurasyon yukle",
            filetypes=[("YAML", "*.yaml *.yml"), ("Tum dosyalar", "*.*")],
        )
        if not path:
            return
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            messagebox.showerror("Hata", f"Konfigurasyon okunamadi: {exc}")
            return

        case = raw.get("case", {})
        collection = raw.get("collection", {})
        custody = raw.get("custody", {})
        logging_cfg = raw.get("logging", {})

        self.case_id_var.set(case.get("case_id", ""))
        self.operator_var.set(case.get("operator", ""))
        self.description_var.set(case.get("description", ""))
        self.output_dir_var.set(collection.get("output_dir", ""))
        self.hash_algo_var.set(collection.get("hash_algorithm", "sha256"))
        self.custody_log_var.set(custody.get("log_path") or "")
        self.log_level_var.set(logging_cfg.get("level", "INFO"))

        wanted = set(collection.get("targets", []))
        for target_id, var in self._target_vars.items():
            var.set(target_id in wanted)

        self._append_log(f"Konfigurasyon yuklendi: {path}")

    # ------------------------------------------------------------------ Toplama

    def _on_collect(self) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showwarning("Mesgul", "Bir toplama zaten calisiyor.")
            return
        if not self._selected_targets():
            messagebox.showwarning("Eksik", "En az bir hedef secmelisiniz.")
            return

        # Form degerlerini gecici bir YAML'e yazip mevcut, test edilmis
        # load_config() dogrulamasindan geciriyoruz - CLI ile ayni yolu izler.
        try:
            temp_config_path = Path(self.output_dir_var.get().strip() or ".") .expanduser()
            temp_config_path.mkdir(parents=True, exist_ok=True)
        except OSError:
            temp_config_path = Path.cwd()
        temp_config_path = temp_config_path / "_gui_config_gecici.yaml"
        try:
            temp_config_path.write_text(
                yaml.safe_dump(self._build_config_dict(), sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror("Hata", f"Gecici konfigurasyon yazilamadi: {exc}")
            return

        self.collect_button.state(["disabled"])
        self.status_var.set("Calisiyor...")
        self._clear_log()
        self._worker = threading.Thread(
            target=self._collect_worker, args=(temp_config_path,), daemon=True
        )
        self._worker.start()

    def _collect_worker(self, config_path: Path) -> None:
        handler = _QueueLogHandler(self._message_queue)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        try:
            config = load_config(config_path)
            root_logger.setLevel(getattr(logging, config.logging.level, logging.INFO))

            log_path = resolve_custody_log_path(config)
            ledger = CustodyLedger(log_path, config.case.case_id)
            manifest = run_collection(config, ledger)

            manifest_path = Path(config.collection.output_dir) / config.case.case_id / "manifest.json"
            manifest.to_json_file(manifest_path)

            self._message_queue.put(f"Toplanan dosya  : {len(manifest.artifacts)}")
            self._message_queue.put(f"Hatali artefakt : {len(manifest.errors)}")
            for err in manifest.errors:
                self._message_queue.put(f"  - [{err['artifact_type_id']}] {err['message']}")
            self._message_queue.put(f"Manifest        : {manifest_path}")
            self._message_queue.put(f"Custody log     : {log_path}")
            self._message_queue.put("__STATUS__Tamamlandi.")
        except (ConfigError, IntegrityError, CustodyLedgerError) as exc:
            self._message_queue.put(f"HATA: {exc}")
            self._message_queue.put("__STATUS__Hata olustu.")
        except Exception as exc:  # beklenmeyen hata da kullaniciya gosterilmeli
            self._message_queue.put(f"BEKLENMEYEN HATA: {exc}")
            self._message_queue.put("__STATUS__Beklenmeyen hata.")
        finally:
            root_logger.removeHandler(handler)
            self._message_queue.put("__DONE__")

    # ------------------------------------------------------------------ Dogrulama

    def _on_verify(self) -> None:
        log_path = filedialog.askopenfilename(
            title="Dogrulanacak custody defterini sec",
            filetypes=[("JSON Lines", "*.jsonl"), ("Tum dosyalar", "*.*")],
        )
        if not log_path:
            return
        case_id = self.case_id_var.get().strip()
        if not case_id:
            messagebox.showwarning("Eksik", "Once vaka no (case_id) girin.")
            return
        try:
            result = verify_chain(Path(log_path), case_id)
        except CustodyLedgerError as exc:
            messagebox.showerror("Hata", str(exc))
            return

        self._append_log(f"Defter    : {log_path}")
        self._append_log(f"Vaka      : {case_id}")
        self._append_log(f"Olay      : {result.total_events}")
        self._append_log(f"Durum     : {'GECERLI' if result.is_valid else 'GECERSIZ'}")
        self._append_log(f"Aciklama  : {result.message}")
        if result.is_valid:
            messagebox.showinfo("Zincir gecerli", result.message)
        else:
            messagebox.showerror("Zincir gecersiz", result.message)

    # ------------------------------------------------------------------ Log paneli / kuyruk

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _poll_queue(self) -> None:
        try:
            while True:
                message = self._message_queue.get_nowait()
                if message.startswith("__STATUS__"):
                    self.status_var.set(message[len("__STATUS__"):])
                elif message == "__DONE__":
                    self.collect_button.state(["!disabled"])
                else:
                    self._append_log(message)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)


def main() -> None:
    """GUI giris noktasi (`triagechain-gui` konsol komutu bunu cagirir)."""
    root = tk.Tk()
    TriageChainApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
