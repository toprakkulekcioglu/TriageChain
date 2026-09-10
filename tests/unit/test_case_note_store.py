"""gui_qt/case_note_store.py'nin testleri -- Qt gerektirmez."""

from triagechain.gui_qt import case_note_store


def test_load_case_note_dosya_yoksa_none_doner(tmp_path):
    assert case_note_store.load_case_note(tmp_path / "yok.json") is None


def test_save_ve_load_round_trip(tmp_path):
    path = tmp_path / "case_note.json"
    saved = case_note_store.save_case_note(path, "Şüpheli IP: 10.0.0.5, takip edilecek.", "yasar")

    assert saved.text == "Şüpheli IP: 10.0.0.5, takip edilecek."
    assert saved.updated_by == "yasar"
    assert saved.updated_at_utc

    loaded = case_note_store.load_case_note(path)
    assert loaded is not None
    assert loaded.text == saved.text
    assert loaded.updated_by == "yasar"


def test_save_var_olan_notun_ustune_yazar(tmp_path):
    path = tmp_path / "case_note.json"
    case_note_store.save_case_note(path, "ilk not", "yasar")
    case_note_store.save_case_note(path, "güncellenmiş not", "yasar")

    loaded = case_note_store.load_case_note(path)
    assert loaded.text == "güncellenmiş not"


def test_load_case_note_bos_metin_none_doner(tmp_path):
    path = tmp_path / "case_note.json"
    case_note_store.save_case_note(path, "", "yasar")

    assert case_note_store.load_case_note(path) is None


def test_load_case_note_bozuk_dosyada_patlamiyor_none_doner(tmp_path):
    path = tmp_path / "case_note.json"
    path.write_text("gecerli json degil {{{", encoding="utf-8")

    assert case_note_store.load_case_note(path) is None
