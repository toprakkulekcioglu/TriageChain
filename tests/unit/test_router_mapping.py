"""Arac esleme katalogu: her toplama hedefinin bir rotasi var mi, sablonlar tutarli mi."""

from triagechain.collection import catalog as collection_catalog
from triagechain.collection.selector import load_catalog
from triagechain.router import catalog as router_catalog
from triagechain.router.runner import load_routes

# EZ araclarindan bir karsiligi olan ve bu yuzden rotasi bulunmasi ZORUNLU
# olan toplama hedefleri. Katalogda bunlardan biri rotasiz kalirsa test kirilir.
EXPECTED_TOOLS = {
    "mft": "mftecmd",
    "registry_system": "recmd",
    "registry_sam": "recmd",
    "registry_security": "recmd",
    "registry_software": "recmd",
    "registry_ntuser": "recmd",
    "registry_usrclass": "recmd",
    "event_logs": "evtxecmd",
    "prefetch": "pecmd",
}


def test_every_expected_artifact_type_has_a_route():
    routes = load_routes(router_catalog.default_catalog_path())

    for artifact_type_id, tool in EXPECTED_TOOLS.items():
        assert artifact_type_id in routes, f"{artifact_type_id} icin rota tanimli degil"
        assert routes[artifact_type_id].tool == tool


def test_routes_only_reference_known_collection_targets():
    # Ters yon: eslemede, toplama katalogunda karsiligi olmayan bir kimlik olmamali.
    routes = load_routes(router_catalog.default_catalog_path())
    collection_targets = load_catalog(collection_catalog.default_catalog_path())

    assert set(routes) <= set(collection_targets)


def test_arg_templates_use_both_placeholders():
    routes = load_routes(router_catalog.default_catalog_path())

    for artifact_type_id, route in routes.items():
        joined = " ".join(route.args)
        assert "{input}" in joined, f"{artifact_type_id}: girdi yer tutucusu yok"
        assert "{output_dir}" in joined, f"{artifact_type_id}: cikti yer tutucusu yok"
        # Sablonda calistirilabilirin kendisi durmaz; argv'nin basina runner ekler.
        assert not any(arg.lower().endswith(".exe") for arg in route.args)


def test_embedded_recmd_batch_file_is_present_and_reachable():
    """RECmd'in --bn dosyasi pakete GOMULU: kullanici hicbir sey
    konfigure etmeden de RECmd rotasi calisabilmeli."""
    batch_path = router_catalog.default_recmd_batch_path()

    assert batch_path.is_file(), f"gomulu toplu dosya yok: {batch_path}"
    assert batch_path.name == "DFIRBatch.reb"
    assert batch_path.parent == router_catalog.default_catalog_path().parent / "recmd_batch"
    # Kaynak/surum/SHA-256 kaydi da yaninda durmali (tekrarlanabilirlik).
    assert (batch_path.parent / "PROVENANCE.md").is_file()


def test_only_recmd_routes_ask_for_a_batch_file():
    """{batch_file} yalnizca RECmd rotalarinda olmali: diger EZ araclarinda
    ayri bir toplu/kural dosyasi kavrami yok."""
    routes = load_routes(router_catalog.default_catalog_path())

    for artifact_type_id, route in routes.items():
        uses_batch = "{batch_file}" in " ".join(route.args)
        assert uses_batch == (route.tool == "recmd"), artifact_type_id
        if uses_batch:
            # Yer tutucu her zaman --bn'in HEMEN ardindan gelmeli.
            assert route.args[route.args.index("--bn") + 1] == "{batch_file}"
