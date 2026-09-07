"""Custody defteri: zincir kurulumu, dogrulama ve kurcalama tespiti."""

import json
import threading

import pytest

from triagechain.core.errors import CustodyLedgerError
from triagechain.custody.ledger import (
    CustodyLedger,
    genesis_hash,
    read_events,
    verify_chain,
)

CASE_ID = "CASE-TEST-001"


def _ledger_with_three_events(tmp_path):
    log_path = tmp_path / "custody.jsonl"
    ledger = CustodyLedger(log_path, CASE_ID)
    ledger.append_event("case_opened", "test.operator", {"run_id": "r1"})
    ledger.append_event("artifact_collected", "test.operator", {"artifact_type_id": "demo"})
    ledger.append_event("case_closed", "test.operator", {"artifact_count": 1})
    return log_path, ledger


def test_chain_is_valid_after_three_appends(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)

    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid
    assert result.total_events == 3
    assert result.broken_at_event_id is None


def test_first_event_links_to_genesis_and_chain_is_linked(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)
    events = list(read_events(log_path))

    assert events[0].prev_hash == genesis_hash(CASE_ID)
    assert events[1].prev_hash == events[0].entry_hash
    assert events[2].prev_hash == events[1].entry_hash
    # tsa_token her olayda var ve su an null.
    assert all(event.payload["tsa_token"] is None for event in events)


def test_tampered_line_is_detected_and_located(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)
    events = list(read_events(log_path))
    tampered_event_id = events[1].event_id

    # Ikinci satirin payload'ini diskte dogrudan degistiriyoruz (entry_hash aynen kaliyor).
    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["payload"]["artifact_type_id"] = "sahte_artefakt"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(log_path, CASE_ID)
    assert not result.is_valid
    assert result.broken_at_event_id == tampered_event_id
    assert "entry_hash" in result.message


def test_wrong_case_id_is_rejected(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)

    result = verify_chain(log_path, "CASE-BASKA-VAKA")
    assert not result.is_valid
    assert result.total_events == 1


def test_missing_log_raises_custody_error(tmp_path):
    with pytest.raises(CustodyLedgerError):
        verify_chain(tmp_path / "yok.jsonl", CASE_ID)


def test_concurrent_writers_do_not_fork_the_chain(tmp_path):
    """Birden fazla 'surec' (burada: thread + AYRI CustodyLedger ornekleri,
    ayni dosyaya yazan gercek isletim sistemi kilidini test eder) ayni deftere
    ayni anda yazarsa zincir CATALLAMAMALI -- bkz. storage.locked() dokstring'i.

    Kilit olmadan bu test guvenilir sekilde basarisiz olurdu: iki thread ayni
    prev_hash'i okuyup ekleyebilir, verify_chain sonraki olayda kirilma
    bildirir. Her thread KENDI CustodyLedger'ini kullaniyor (gercek ayri
    surecleri simule etmek icin - paylasilan bir Python nesnesi/kilidi degil,
    dosya sistemi seviyesindeki kilit test ediliyor)."""
    log_path = tmp_path / "custody.jsonl"
    writer_count = 8
    events_per_writer = 10
    errors: list[Exception] = []

    def write_many(writer_index: int) -> None:
        ledger = CustodyLedger(log_path, CASE_ID)
        try:
            for i in range(events_per_writer):
                ledger.append_event(
                    "artifact_collected", "test.operator",
                    {"writer": writer_index, "seq": i},
                )
        except Exception as exc:  # noqa: BLE001 - ana thread'de degerlendirilecek
            errors.append(exc)

    threads = [
        threading.Thread(target=write_many, args=(i,)) for i in range(writer_count)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid, result.message
    assert result.total_events == writer_count * events_per_writer
