"""gui_qt/tag_store.py'nin testleri -- Qt gerektirmez, saf dosya sistemi
mantigi."""

from triagechain.detection.models import Finding, YaraMatch
from triagechain.gui_qt import tag_store


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        artifact_type_id="event_logs",
        source_path="C:/case/artifacts/event_logs/Security.evtx",
        rule_title="Şüpheli Oturum Açma",
        level="high",
        timestamp="2026-06-07T22:10:00Z",
        computer="WORKSTATION-1",
        channel="Security",
        event_id="4625",
        details="LogonType=3",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_yara_match(**overrides) -> YaraMatch:
    defaults = dict(
        artifact_type_id="suspicious_binary",
        source_path="C:/case/artifacts/suspicious_binary/notepad.exe",
        rule_name="Mimikatz_Strings",
        tags="malware,mimikatz",
        meta="author=test",
    )
    defaults.update(overrides)
    return YaraMatch(**defaults)


def test_target_id_for_finding_kararli():
    """Ayni verilerle iki ayri cagri AYNI ID'yi vermeli -- isaret ikinci bir
    'Tara' kosusundan sonra da kaybolmamali."""
    finding = _make_finding()
    assert tag_store.target_id_for_finding(finding) == tag_store.target_id_for_finding(finding)


def test_target_id_for_finding_farkli_bulgular_farkli_id():
    a = _make_finding()
    b = _make_finding(event_id="4624")
    assert tag_store.target_id_for_finding(a) != tag_store.target_id_for_finding(b)


def test_target_id_for_yara_match_kararli_ve_ayirt_edici():
    a = _make_yara_match()
    b = _make_yara_match()
    c = _make_yara_match(rule_name="Baska_Kural")
    assert tag_store.target_id_for_yara_match(a) == tag_store.target_id_for_yara_match(b)
    assert tag_store.target_id_for_yara_match(a) != tag_store.target_id_for_yara_match(c)


def test_load_tags_dosya_yoksa_bos_sozluk_doner(tmp_path):
    assert tag_store.load_tags(tmp_path / "yok.json") == {}


def test_set_tag_ve_load_tags_round_trip(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "abc123", "Şüpheli - rapora eklenecek", "yasar")

    tags = tag_store.load_tags(path)

    assert "abc123" in tags
    assert tags["abc123"].note == "Şüpheli - rapora eklenecek"
    assert tags["abc123"].tagged_by == "yasar"
    assert tags["abc123"].tagged_at_utc


def test_set_tag_var_olani_gunceller(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "abc123", "ilk not", "yasar")
    tag_store.set_tag(path, "abc123", "güncellenmiş not", "yasar")

    tags = tag_store.load_tags(path)

    assert len(tags) == 1
    assert tags["abc123"].note == "güncellenmiş not"


def test_remove_tag(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "abc123", "not", "yasar")

    tag_store.remove_tag(path, "abc123")

    assert tag_store.load_tags(path) == {}


def test_remove_tag_olmayan_hedef_sessizce_gecer(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.remove_tag(path, "hic-yok")  # patlamamali
    assert not path.exists()


def test_load_tags_bozuk_dosyada_patlamiyor_bos_doner(tmp_path):
    path = tmp_path / "tags.json"
    path.write_text("bu gecerli bir json degil {{{", encoding="utf-8")

    assert tag_store.load_tags(path) == {}


def test_birden_fazla_hedef_bagimsiz_calisir(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "id1", "not1", "yasar")
    tag_store.set_tag(path, "id2", "not2", "yasar")

    tags = tag_store.load_tags(path)

    assert set(tags.keys()) == {"id1", "id2"}
    assert tags["id1"].note == "not1"
    assert tags["id2"].note == "not2"
