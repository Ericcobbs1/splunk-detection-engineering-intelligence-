import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "lab" / "telemetry"


def _routing():
    return json.loads((TELEMETRY / "dataset_routing.json").read_text())["datasets"]


def _ledger():
    return json.loads((TELEMETRY / "ta_replication_contracts.json").read_text())


def test_ta_replication_contracts_cover_every_dedicated_dataset():
    routing = _routing()
    contracts = _ledger()["datasets"]
    assert len(routing) == 26
    assert set(contracts) == set(routing)
    for dataset, route in routing.items():
        contract = contracts[dataset]
        assert contract["ta_sourcetype"]
        assert contract["wire_format"]
        assert contract["format_verified"] is True
        assert contract["semantic_verified"] is True
        assert route["sourcetype"] == contract["ta_sourcetype"]


def test_runtime_splunk_validation_remains_a_premerge_gate():
    policy = _ledger()["policy"]
    assert policy["runtime_ta_validation_required"] is True
    assert policy["runtime_verified"] is False
    assert "runtime" in policy["merge_gate"].lower()


def test_dedicated_index_policy_remains_unique():
    routing = _routing()
    indexes = [route["index"] for route in routing.values()]
    assert len(indexes) == len(set(indexes)) == 26
