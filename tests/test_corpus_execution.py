import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TA_MANIFEST = ROOT / "lab" / "telemetry" / "ta_install_manifest.json"
MEGABATCH = ROOT / "lab" / "telemetry" / "verified_profiles_megabatch.json"
GENERATOR = ROOT / "lab" / "telemetry" / "generate_corpus.py"
WRAPPER = ROOT / "lab" / "telemetry" / "build_lab_corpus.sh"


def test_ta_manifest_has_required_apps():
    payload = json.loads(TA_MANIFEST.read_text(encoding="utf-8"))
    assert payload["policy"]["do_not_fake_ta_extractions"] is True
    required = {s for app in payload["apps"] for s in app["required_for"]}
    for sourcetype in {
        "XmlWinEventLog:Security",
        "aws:cloudtrail",
        "OktaIM2:log",
        "crowdstrike:events:sensor",
        "cisco:asa",
        "ms:defender:advancedhunting",
        "google:gcp:pubsub:message",
    }:
        assert sourcetype in required


def test_megabatch_profiles_are_verified_and_documented():
    payload = json.loads(MEGABATCH.read_text(encoding="utf-8"))
    assert payload["profiles"]
    for profile in payload["profiles"]:
        assert profile["status"] == "verified"
        assert profile["sourcetypes"]
        assert profile["raw_fields"]
        assert profile["authorities"]
        assert any(a["type"] in {"vendor_schema", "splunk_supported_addon", "vendor_supported_addon", "splunk_cim"} for a in profile["authorities"])


def test_generator_and_wrapper_are_present():
    assert GENERATOR.exists()
    assert WRAPPER.exists()
    text = GENERATOR.read_text(encoding="utf-8")
    assert 'p.get("status") == "verified"' in text
    wrapper = WRAPPER.read_text(encoding="utf-8")
    assert "TARGET_MB" in wrapper
    assert "--events-per-source" in wrapper
