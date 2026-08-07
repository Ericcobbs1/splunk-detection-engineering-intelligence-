import json
from pathlib import Path


def test_dataset_routing_is_complete_and_unique():
    path = Path("lab/telemetry/dataset_routing.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    datasets = payload["datasets"]

    assert len(datasets) == 26
    indexes = [route["index"] for route in datasets.values()]
    assert len(indexes) == len(set(indexes))
    assert payload["policy"]["one_dataset_per_index"] is True


def test_ta_sourcetype_corrections_are_persisted():
    path = Path("lab/telemetry/dataset_routing.json")
    datasets = json.loads(path.read_text(encoding="utf-8"))["datasets"]

    assert datasets["microsoft_defender_endpoint"]["sourcetype"] == "m365:defender:incident:advanced_hunting"
    assert datasets["google_workspace"]["sourcetype"] == "gws:reports:admin"
    assert datasets["salesforce_event_monitoring"]["sourcetype"] == "sfdc:logfile"
