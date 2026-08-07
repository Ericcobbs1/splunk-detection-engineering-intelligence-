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


base = _load("dei_test_base_generator", TELEMETRY / "generate_corpus.py")
windows = _load("dei_test_windows_contracts", TELEMETRY / "windows_event_contracts.py")


def test_windows_security_contracts_are_event_specific():
    random.seed(20260807)
    events = [windows.security_event(base) for _ in range(3000)]
    observed = {event["EventCode"] for event in events}
    assert observed == set(windows.SECURITY_EVENT_CODES)

    logon_only = {
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort",
    }

    for event in events:
        code = event["EventCode"]
        assert event["Computer"].endswith(".corp.example")
        assert event["SubjectUserSid"].startswith("S-1-5-21-")
        assert event["SubjectUserName"]

        if code in {4624, 4625}:
            assert logon_only <= event.keys()
            assert event["LogonType"] in windows.LOGON_TYPES
            assert event["AuthenticationPackageName"] in windows.AUTH_PACKAGES
            assert event["IpAddress"].startswith("10.")
            assert event["ProcessName"] in windows.PROCESS_NAMES
            if code == 4625:
                assert event["Status"].startswith("0x")
                assert event["SubStatus"].startswith("0x")
                assert event["FailureReason"].startswith("%%")
            else:
                assert "Status" not in event
                assert "FailureReason" not in event
        else:
            assert not (logon_only & event.keys())
            assert event["TargetUserName"]
            assert event["TargetSid"].startswith("S-1-5-21-")

        if code == 4720:
            assert event["SamAccountName"] == event["TargetUserName"]
            assert event["UserPrincipalName"].endswith("@corp.example")
            assert event["PrimaryGroupId"] == 513
            assert event["OldUacValue"] == "0x0"

        if code in {4728, 4729, 4756, 4757}:
            assert event["TargetUserName"] in {"Domain Admins", "SOC Analysts", "Server Operators"}
            assert event["MemberName"].startswith("CN=")
            assert event["MemberId"].startswith("S-1-5-21-")


def test_powershell_contracts_are_event_specific():
    random.seed(20260807)
    events = [windows.powershell_event(base) for _ in range(1000)]
    assert {event["EventCode"] for event in events} == {4103, 4104}

    for event in events:
        assert event["Computer"].endswith(".corp.example")
        assert event["UserId"].startswith("S-1-5-21-")
        assert event["Message"]

        if event["EventCode"] == 4104:
            assert event["ScriptBlockText"]
            assert event["ScriptBlockId"]
            assert event["MessageNumber"] == 1
            assert event["MessageTotal"] == 1
            assert "Creating Scriptblock text" in event["Message"]
        else:
            assert "ScriptBlockText" not in event
            assert "ScriptBlockId" not in event
            assert "CommandInvocation(" in event["Message"]


def test_windows_contract_metadata_is_versioned_and_documented():
    metadata = windows.contract_metadata()
    assert metadata["version"] >= 1
    assert set(metadata["security_event_codes"]) == set(windows.SECURITY_EVENT_CODES)
    assert set(metadata["powershell_event_codes"]) == {4103, 4104}
    for code in windows.SECURITY_EVENT_CODES:
        assert metadata["authorities"][str(code)].endswith(f"event-{code}")
