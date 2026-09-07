"""Birlesik zaman cizelgesi: router'in zaten urettigi EZ Tools CSV
ciktilarini ($MFT/registry/olay gunlugu/prefetch) TEK bir kronolojik
listede birlestirir.

Bu, Plaso/log2timeline'in "super zaman cizelgesi" fikrinin BYO-arac
mimarisiyle tutarli, YENI BIR DIS BAGIMLILIK gerektirmeyen halidir: Plaso
bu makinede gercek bir C++ derleme zinciri gerektirdigi icin kurulamadi
(bkz. aldigim_kararlar.md), ama TriageChain zaten MFTECmd/RECmd/EvtxECmd/
PECmd'yi calistirip CSV uretiyor -- bu katman sadece o CSV'leri OKUYUP
normallestiriyor, hicbir yeni subprocess/arac cagirmiyor.

Diger reporting/ modulleriyle AYNI ilke: salt-okunur, dis program
CALISTIRMAZ, custody'ye YAZMAZ. router.py'nin ZATEN urettigi dosyalari
okur; router calismamissa (routing_manifest.json yok) veya bir aracin
ciktisi eksikse bu OLUMCUL degildir -- o kaynaktan hic olay gelmez,
digerleri etkilenmez (Hayabusa/YARA ayristirmasindaki "en iyi caba"
ilkesiyle ayni, bkz. detection/runner.py).

Her ayristirici GERCEK bir EZ Tools ciktisina karsi DOGRULANDI (surum
2026.5.0, net9): gercek bir $MFT/SAM+NTUSER.DAT registry kovanlari/
UACME_59_Sysmon.evtx/NOTEPAD.EXE prefetch ornegi calistirilip CSV
sutunlari BIREBIR buradan alindi (bkz. aldigim_kararlar.md -> "Birlesik
zaman cizelgesi").
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from triagechain.router.models import ProcessedArtifact, RoutingManifest

logger = logging.getLogger(__name__)

# Her aracin varsayilan (--csvf VERILMEDIGINDE) dosya adi
# "<yyyyMMddHHmmss>_<Arac>..._Output.csv" bicimindedir -- zaman damgasi
# onceden bilinemedigi icin isim yerine bu GLOB DESENIYLE bulunuyor
# (gercek ikililerle dogrulandi, bkz. modul dokstring'i).
_OUTPUT_CSV_GLOB = "*_Output.csv"
_PECMD_TIMELINE_GLOB = "*_Output_Timeline.csv"


@dataclass
class TimelineEvent:
    """Tek bir kronolojik olay -- hangi aractan geldigine gore anlami degisir
    (MFT icin bir MACB zaman damgasi, registry icin bir anahtarin son yazma
    zamani, olay gunlugu icin bir Windows olayi, prefetch icin bir calistirma)."""

    timestamp: str
    tool: str
    activity: str
    description: str
    source_path: str
    detail: str = ""


def build_timeline(routing: RoutingManifest) -> list[TimelineEvent]:
    """`routing_manifest.json`'daki HER islenmis artefaktin CSV ciktisini
    okuyup normallestirilmis olaylari kronolojik sirayla dondurur.

    Bir aracin ciktisi eksik/bozuksa o artefakttan hic olay gelmez (uyari
    loglanir), digerleri etkilenmez -- "en iyi caba" ilkesi.
    """
    parsers = {
        "mftecmd": _parse_mftecmd,
        "recmd": _parse_recmd,
        "evtxecmd": _parse_evtxecmd,
        "pecmd": _parse_pecmd,
    }
    events: list[TimelineEvent] = []
    for artifact in routing.processed:
        parser = parsers.get(artifact.tool)
        if parser is None:
            continue
        events.extend(parser(artifact))
    return sorted(events, key=lambda e: e.timestamp)


def _find_output_csv(output_dir: Path, pattern: str = _OUTPUT_CSV_GLOB) -> Optional[Path]:
    """Aracin varsayilan adla yazdigi CSV'yi glob ile bulur -- dosya adi
    zaman damgasi icerdigi icin tahmin edilemez (bkz. modul dokstring'i)."""
    matches = sorted(output_dir.glob(pattern))
    return matches[0] if matches else None


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    """En iyi caba ile CSV'yi okur; okunamazsa bos liste + uyari log'u."""
    try:
        with path.open(encoding="utf-8-sig", newline="") as fh:
            return list(csv.DictReader(fh))
    except (OSError, csv.Error) as exc:
        logger.warning("[timeline] %s okunamadi: %s", path, exc)
        return []


def _parse_mftecmd(artifact: ProcessedArtifact) -> list[TimelineEvent]:
    """MFTECmd CSV'sinden MACB (Modified/Accessed/Changed/Born) zaman
    damgalarini ayiklar -- her dolu zaman damgasi AYRI bir olay olur, klasik
    super-zaman-cizelgesi deseni (Plaso'nun da yaptigi ayni sey)."""
    csv_path = _find_output_csv(Path(artifact.output_dir))
    if csv_path is None:
        logger.info("[timeline] MFTECmd cikti CSV'si bulunamadi: %s", artifact.output_dir)
        return []

    # (sutun adi, MACB harfi) -- gercek MFTECmd 2026.5.0 CSV basligindan
    # dogrulandi (bkz. modul dokstring'i).
    macb_columns = (
        ("LastModified0x10", "M"),
        ("LastAccess0x10", "A"),
        ("LastRecordChange0x10", "C"),
        ("Created0x10", "B"),
    )
    events: list[TimelineEvent] = []
    for row in _read_csv_rows(csv_path):
        name = row.get("FileName", "")
        parent = row.get("ParentPath", "")
        full_path = f"{parent}\\{name}" if parent else name
        for column, letter in macb_columns:
            timestamp = (row.get(column) or "").strip()
            if not timestamp:
                continue
            events.append(
                TimelineEvent(
                    timestamp=timestamp,
                    tool="mftecmd",
                    activity=letter,
                    description=f"Dosya {_MACB_LABELS[letter]}",
                    source_path=artifact.source_path,
                    detail=full_path,
                )
            )
    return events


_MACB_LABELS = {"M": "değiştirildi", "A": "erişildi", "C": "kaydı değişti", "B": "oluşturuldu"}


def _parse_pecmd(artifact: ProcessedArtifact) -> list[TimelineEvent]:
    """PECmd'nin KENDI urettigi `*_Output_Timeline.csv` dosyasini okur --
    PECmd her calistirma zamanini zaten TEK BASINA bir satir olarak
    urettigi icin (RunTime,ExecutableName) ayrica ayiklama gerekmiyor."""
    csv_path = _find_output_csv(Path(artifact.output_dir), _PECMD_TIMELINE_GLOB)
    if csv_path is None:
        logger.info("[timeline] PECmd Timeline CSV'si bulunamadi: %s", artifact.output_dir)
        return []

    events: list[TimelineEvent] = []
    for row in _read_csv_rows(csv_path):
        timestamp = (row.get("RunTime") or "").strip()
        if not timestamp:
            continue
        events.append(
            TimelineEvent(
                timestamp=timestamp,
                tool="pecmd",
                activity="çalıştırma",
                description="Program çalıştırıldı",
                source_path=artifact.source_path,
                detail=row.get("ExecutableName", ""),
            )
        )
    return events


def _parse_evtxecmd(artifact: ProcessedArtifact) -> list[TimelineEvent]:
    """EvtxECmd CSV'sinden her olay kaydini tek bir zaman cizelgesi olayina
    cevirir -- Hayabusa/Chainsaw'in AKSINE burada Sigma kural eslesmesi
    ARANMAZ, ham olay gunlugu kaydinin kendisi (MapDescription'in insan-
    okur ozeti ile) zaman cizelgesine giriyor."""
    csv_path = _find_output_csv(Path(artifact.output_dir))
    if csv_path is None:
        logger.info("[timeline] EvtxECmd cikti CSV'si bulunamadi: %s", artifact.output_dir)
        return []

    events: list[TimelineEvent] = []
    for row in _read_csv_rows(csv_path):
        timestamp = (row.get("TimeCreated") or "").strip()
        if not timestamp:
            continue
        description = row.get("MapDescription") or f"Olay {row.get('EventId', '')}"
        detail = f"{row.get('Provider', '')} · {row.get('Channel', '')}".strip(" ·")
        events.append(
            TimelineEvent(
                timestamp=timestamp,
                tool="evtxecmd",
                activity=row.get("EventId", ""),
                description=description,
                source_path=artifact.source_path,
                detail=detail,
            )
        )
    return events


def _parse_recmd(artifact: ProcessedArtifact) -> list[TimelineEvent]:
    """RECmd (DFIRBatch) CSV'sinden her anahtarin son yazma zamanini
    ayiklar -- BIR anahtarin ALTINDAKI onlarca deger AYNI LastWriteTimestamp'i
    tasidigi icin (kayit anahtar duzeyinde tutulur, deger duzeyinde degil),
    (KeyPath, LastWriteTimestamp) ciftine gore TEKILLESTIRILIR; aksi halde
    zaman cizelgesi neredeyse ozdes satirlarla tasardi (gercek NTUSER.DAT
    kovaniyla dogrulandi: 2.759 deger satiri, cok daha az benzersiz anahtar
    yazma olayina karsilik geliyor)."""
    csv_path = _find_output_csv(Path(artifact.output_dir))
    if csv_path is None:
        logger.info("[timeline] RECmd cikti CSV'si bulunamadi: %s", artifact.output_dir)
        return []

    seen: set[tuple[str, str]] = set()
    events: list[TimelineEvent] = []
    for row in _read_csv_rows(csv_path):
        timestamp = (row.get("LastWriteTimestamp") or "").strip()
        key_path = row.get("KeyPath") or ""
        if not timestamp:
            continue
        dedup_key = (key_path, timestamp)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        description = row.get("Description") or "Registry anahtarı değişti"
        events.append(
            TimelineEvent(
                timestamp=timestamp,
                tool="recmd",
                activity=row.get("Category", ""),
                description=description,
                source_path=artifact.source_path,
                detail=key_path,
            )
        )
    return events
