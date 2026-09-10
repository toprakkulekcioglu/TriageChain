"""Vakanin GENELINE ait, tek bir bulguya BAGLI OLMAYAN serbest metin notu --
Oxygen Forensic Detective'in vaka notlari fikrinden esinlenildi (bkz.
docs/aldigim_kararlar.md).

tag_store.py ile AYNI gerekce: gozetim zincirine (custody.jsonl) YAZILMAZ
(analistin subjektif yorumu, delilin kendisi degil) ve *_manifest.json
dosyalarinin da PARCASI DEGIL (o dosyalar her kosuda YENIDEN uretilir) --
ayri bir dosya (bkz. config/loader.py::resolve_case_note_path). tag_store.py
gibi kilitleme YOK: sadece GUI'nin kendi is parcacigindan, tek surecten
yazilir.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class CaseNote:
    text: str
    updated_by: str
    updated_at_utc: str


def load_case_note(path: Path) -> Optional[CaseNote]:
    """Diskteki notu okur. Dosya yoksa/bosaysa None doner -- bu bir hata degil."""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    text = raw.get("text", "")
    if not text:
        return None
    return CaseNote(
        text=text,
        updated_by=raw.get("updated_by", ""),
        updated_at_utc=raw.get("updated_at_utc", ""),
    )


def save_case_note(path: Path, text: str, operator: str) -> CaseNote:
    """Notu diske yazar (ustune yazar) ve yazilan kaydi dondurur."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    note = CaseNote(
        text=text,
        updated_by=operator,
        updated_at_utc=datetime.now(timezone.utc).isoformat(),
    )
    path.write_text(
        json.dumps(
            {"text": note.text, "updated_by": note.updated_by, "updated_at_utc": note.updated_at_utc},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return note
