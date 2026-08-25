from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _stanzas(path: Path) -> set[str]:
    return {
        line.strip()[1:-1]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("[") and line.strip().endswith("]")
    }


def test_every_kv_collection_has_an_inputlookup_definition() -> None:
    collections = _stanzas(ROOT / "app/default/collections.conf")
    transforms = _stanzas(ROOT / "app/default/transforms.conf")
    assert transforms == collections


def test_kv_lookup_definitions_reference_their_same_named_collection() -> None:
    text = (ROOT / "app/default/transforms.conf").read_text(encoding="utf-8")
    for collection in _stanzas(ROOT / "app/default/collections.conf"):
        stanza = text.split(f"[{collection}]", 1)[1].split("[", 1)[0]
        assert f"collection = {collection}" in stanza
        assert "external_type = kvstore" in stanza
        assert "fields_list = " in stanza
