"""hash_file davranisi: bilinen icerik -> bilinen ozet."""

from pathlib import Path

from triagechain.collection.hashing import hash_file

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "fake_artifacts"

# tests/fixtures/fake_artifacts/notes.txt icin elle hesaplanmis degerler.
NOTES_SIZE = 29
NOTES_SHA256 = "72c6f82825532438968540aae9551a97c3cae8d9cbbb6c836f152dd0d28b2241"


def test_hash_known_fixture_file():
    notes = FIXTURES / "notes.txt"
    # Boyut kontrolu: satir sonu normalizasyonu olursa hata mesaji anlasilir olsun.
    assert notes.stat().st_size == NOTES_SIZE
    assert hash_file(notes) == NOTES_SHA256


def test_hash_accepts_open_stream():
    notes = FIXTURES / "notes.txt"
    with open(notes, "rb") as stream:
        assert hash_file(stream) == NOTES_SHA256


def test_small_chunk_size_gives_same_digest():
    notes = FIXTURES / "notes.txt"
    assert hash_file(notes, chunk_size=3) == NOTES_SHA256


def test_other_algorithms(tmp_path):
    sample = tmp_path / "abc.bin"
    sample.write_bytes(b"abc")
    assert hash_file(sample, "sha1") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hash_file(sample, "md5") == "900150983cd24fb0d6963f7d28e17f72"
