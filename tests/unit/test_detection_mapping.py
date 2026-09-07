"""Hayabusa cagri sablonu katalogu: yer tutucular ve CSV sutun eslemesi tutarli mi."""

from triagechain.detection import catalog as detection_catalog
from triagechain.detection.runner import SCANNED_ARTIFACT_TYPE, load_profile

# Bir bulguyu (Finding) anlamli kilan, eslemede karsiligi bulunmasi ZORUNLU
# alanlar. Katalogdan biri dususe test kirilir.
REQUIRED_COLUMNS = {"timestamp", "rule_title", "level", "computer", "channel", "event_id"}


def test_arg_template_uses_all_placeholders():
    profile = load_profile(detection_catalog.default_catalog_path())
    joined = " ".join(profile.args)

    assert "{input}" in joined, "girdi yer tutucusu yok"
    assert "{rules_dir}" in joined, "kural klasoru yer tutucusu yok"
    assert "{output_csv}" in joined, "cikti yer tutucusu yok"
    # Sablonda calistirilabilirin kendisi durmaz; argv'nin basina kosu ekler.
    assert not any(arg.lower().endswith(".exe") for arg in profile.args)


def test_output_filename_is_derived_from_the_scanned_file():
    profile = load_profile(detection_catalog.default_catalog_path())

    # Ayni klasore yazilan ciktilar birbirinin ustune binmemeli.
    assert "{stem}" in profile.output_filename
    assert profile.output_filename.format(stem="Security.evtx").endswith(".csv")


def test_every_required_finding_field_has_column_candidates():
    profile = load_profile(detection_catalog.default_catalog_path())

    assert REQUIRED_COLUMNS <= set(profile.csv_columns)
    for field_name, candidates in profile.csv_columns.items():
        assert candidates, f"{field_name}: aday baslik listesi bos"


def test_scanned_artifact_type_matches_the_collection_catalog():
    # Taranan tip, toplama katalogundaki olay gunlugu hedefiyle ayni kimlik olmali;
    # yoksa tespit katmani hicbir dosya bulamaz.
    from triagechain.collection import catalog as collection_catalog
    from triagechain.collection.selector import load_catalog

    assert SCANNED_ARTIFACT_TYPE in load_catalog(collection_catalog.default_catalog_path())
