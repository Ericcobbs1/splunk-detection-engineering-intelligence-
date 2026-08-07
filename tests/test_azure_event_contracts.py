import importlib.util
import random
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "lab" / "telemetry"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load("dei_test_azure_base", TELEMETRY / "generate_corpus.py")
azure = _load("dei_test_azure_contracts", TELEMETRY / "azure_event_contracts.py")


def test_entra_signin_is_azure_monitor_aad_envelope():
    random.seed(20260807)
    event = azure.entra_signin_event(base, "2026-08-07T12:00:00Z")

    assert event["category"] in azure.ENTRA_CATEGORIES
    assert event["operationName"] == "Sign-in activity"
    assert event["resourceId"].endswith("/providers/Microsoft.aadiam")
    assert event["tenantId"] == azure.TENANT_ID
    assert event["callerIpAddress"] == event["properties"]["ipAddress"]
    assert event["correlationId"] == event["properties"]["correlationId"]

    props = event["properties"]
    assert props["userPrincipalName"].endswith("@corp.example")
    assert props["conditionalAccessStatus"] in azure.CA_STATUS
    assert props["riskLevelDuringSignIn"] in azure.RISK_LEVEL
    assert props["riskState"] in azure.RISK_STATE
    assert isinstance(props["deviceDetail"], dict)
    assert isinstance(props["status"]["errorCode"], int)

    # Sign-in report fields belong inside Azure Monitor properties, not as a
    # fabricated flattened Log Analytics table row at the raw-event root.
    for flattened in (
        "UserPrincipalName",
        "IPAddress",
        "ConditionalAccessStatus",
        "RiskLevelDuringSignIn",
        "DeviceDetail",
    ):
        assert flattened not in event


def test_entra_categories_cover_interactive_and_noninteractive_sources():
    random.seed(20260807)
    events = [azure.entra_signin_event(base, "2026-08-07T12:00:00Z") for _ in range(1000)]
    categories = {event["category"] for event in events}
    assert categories == set(azure.ENTRA_CATEGORIES)

    for event in events:
        expected_interactive = event["category"] == "SignInLogs"
        assert event["properties"]["isInteractive"] is expected_interactive


def test_azure_activity_uses_activity_log_envelope():
    random.seed(20260807)
    event = azure.azure_activity_event(base, "2026-08-07T12:00:00Z")
    assert event["category"] == "Administrative"
    assert event["operationName"].startswith("Microsoft.")
    assert event["resourceId"].startswith("/subscriptions/")
    assert event["resultType"] in {"Success", "Failure"}
    assert event["resultSignature"] in {"Succeeded", "Failed"}
    assert event["identity"]["claims"]["name"].endswith("@corp.example")
    assert event["properties"]["statusCode"] in {"OK", "Forbidden"}


def test_azure_contract_metadata_declares_ta_sourcetypes():
    metadata = azure.contract_metadata()
    assert metadata["version"] >= 1
    assert metadata["entra_sourcetype"] == "azure:monitor:aad"
    assert metadata["activity_sourcetype"] == "azure:monitor:activity"
    assert metadata["authorities"]["signin_schema"].startswith("https://learn.microsoft.com/")
