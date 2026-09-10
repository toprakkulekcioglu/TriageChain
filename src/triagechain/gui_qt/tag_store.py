"""Analistin bulgu isaretleme (tag/bookmark) notlari -- Cellebrite Physical
Analyzer'daki "Tags" sekmesinden esinlenildi (bkz. docs/aldigim_kararlar.md).

Bir isaret SADECE iki alan tasir: kisa bir not + kim/ne zaman isaretledigi.
Kategori/renk gibi bir siniflandirma YOK -- Cellebrite'in kendi Tags'i
boyle bir tipoloji sunuyor ama TriageChain'in analistinin asil ihtiyaci
"bunu rapora/takibe alacagim, neden onemli oldugunu hatirlayayim" -- daha
fazlasi bu asamada spekulatif ozellik olurdu.

BILEREK gozetim zincirine (custody.jsonl) YAZILMAZ: zincir SADECE toplama/
yonlendirme/tespit OLAYLARINI tasir, analistin subjektif yorumunu degil.
BILEREK *_manifest.json dosyalarinin da PARCASI DEGIL: o dosyalar her kosuda
(orn. 'Tara' tekrar tiklaninca) YENIDEN uretilir, isaretler bir kosudan
digerine KALICI olmali -- bu yuzden ayri bir dosya (bkz. config/loader.py::
resolve_tags_path).

Kilitleme YOK: custody.jsonl'in aksine (bkz. custody/ledger.py::storage.
locked(), coklu-YAZICI/coklu-surec senaryosu icin) bu dosyaya SADECE GUI'nin
kendi is parcacigindan, tek surecten yazilir -- es zamanli yazici riski yok.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class TagRecord:
    """Tek bir isaretin kendisi -- hedefin ne oldugunu TASIMAZ (dict anahtari
    zaten target_id), sadece isaretin icerigini tasir."""

    note: str
    tagged_by: str
    tagged_at_utc: str


def target_id_for_finding(finding) -> str:
    """Bir Finding'i (Hayabusa/Chainsaw -- ayni sema) kararli bicimde
    tanimlayan bir anahtar uretir.

    Finding'in kendi bir ID alani YOK (bkz. detection/models.py) -- CSV'den
    en iyi caba ile ayristirilan bir kayit, ID uretmek arac katmaninin degil
    bu katmanin isi. source_path + rule_title + timestamp + event_id
    birlikte AYNI tespiti iki farkli kosuda da AYNI ID'ye getirir (kosular
    arasi kararlilik onemli: isaret, ikinci bir 'Tara' sonrasi da KAYBOLMAMALI).
    """
    composite = f"{finding.source_path}|{finding.rule_title}|{finding.timestamp}|{finding.event_id}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()[:16]


def target_id_for_yara_match(match) -> str:
    """target_id_for_finding ile ayni gerekce -- YaraMatch (YARA/capa, ayni
    sema) icin. Bir olay baglami (timestamp/event_id) YOK, source_path +
    rule_name + meta zaten tek bir dosyadaki tek bir kural eslesmesini
    kararli bicimde tanimliyor."""
    composite = f"{match.source_path}|{match.rule_name}|{match.meta}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()[:16]


def load_tags(path: Path) -> dict[str, TagRecord]:
    """Diskteki isaretleri okur. Dosya yoksa (henuz hic isaretlenmemis vaka)
    bos sozluk doner -- bu bir hata degil."""
    path = Path(path)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # Bozuk/okunamayan bir dosya isaretleme ozelligini TAMAMEN dusurmemeli
        # -- kullanici hala calisabilsin, sadece eski isaretler kaybolur.
        return {}
    return {
        target_id: TagRecord(**record)
        for target_id, record in raw.get("tags", {}).items()
    }


def _write_tags(path: Path, tags: dict[str, TagRecord]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tags": {
            target_id: {
                "note": record.note,
                "tagged_by": record.tagged_by,
                "tagged_at_utc": record.tagged_at_utc,
            }
            for target_id, record in tags.items()
        }
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def set_tag(path: Path, target_id: str, note: str, operator: str) -> None:
    """Bir hedefi isaretler/notunu gunceller (varsa ustune yazar)."""
    tags = load_tags(path)
    tags[target_id] = TagRecord(
        note=note,
        tagged_by=operator,
        tagged_at_utc=datetime.now(timezone.utc).isoformat(),
    )
    _write_tags(path, tags)


def remove_tag(path: Path, target_id: str) -> None:
    """Bir isareti kaldirir. Isaretlenmemis bir hedef icin sessizce hicbir
    sey yapmaz (cagiran taraf zaten UI durumuna gore cagiriyor, bu bir
    yaris durumu degil -- tek surecli GUI)."""
    tags = load_tags(path)
    if target_id in tags:
        del tags[target_id]
        _write_tags(path, tags)
