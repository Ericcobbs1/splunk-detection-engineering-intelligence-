import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "lab" / "telemetry"


def test_ta_replication_contracts_cover_every_dedicated_dataset():
    routing = json.loads((TELEMETRY / "dataset_routing.json").read_text())["datasets"]
    contracts = json.loads((TELEMETRY / "ta_replication_contracts.json").read_text())["datasets"]
    assert len(routing) == 26
    assert set(contracts) == set(routing)

    for dataset, route in routing.items():
        contract = contracts[dataset]
        assert contract["ta_sourcetype"]
        assert contract["wire_format"]
        assert isinstance(contract["format_verified"], bool)
        assert isinstance(contract["semantic_verified"], bool)


def test_dedicated_index_policy_remains_unique():
    routing = json.loads((TELEMETRY / "dataset_routing.json").read_text())["datasets"]
    indexes = [route["index"] for route in routing.values()]
    assert len(indexes) == len(set(indexes)) == 26
