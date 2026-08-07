import csv
import importlib.util
import io
import random
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "lab" / "telemetry"
TS = "2026-08-07T12:00:00Z"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load("tf_base", T / "generate_corpus.py")
windows = _load("tf_windows", T / "windows_event_contracts.py")
microsoft = _load("tf_microsoft", T / "microsoft_event_contracts.py")
network = _load("tf_network", T / "network_event_contracts.py")
cloud = _load("tf_cloud", T / "cloud_saas_event_contracts.py")


def test_windows_serializes_real_event_xml():
    random.seed(1)
    for profile in ("windows_security", "windows_powershell"):
        event = windows.make_windows_event(profile, base)
        raw = windows.serialize_windows_event(profile, event, TS)
        root = ET.fromstring(raw)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        assert root.find("e:System/e:EventID", ns).text == str(event["EventCode"])
        channel = root.find("e:System/e:Channel", ns).text
        expected = (
            "Security"
            if profile == "windows_security"
            else "Microsoft-Windows-PowerShell/Operational"
        )
        assert channel == expected
        names = {x.attrib.get("Name") for x in root.findall("e:EventData/e:Data", ns)}
        assert "Computer" not in names
        if event["EventCode"] == 4104:
            assert "ScriptBlockText" in names


def test_m365_management_workload_operations_are_coherent():
    random.seed(2)
    for _ in range(500):
        event = microsoft.management_activity_event(base, TS)
        assert event["UserId"].endswith("@corp.example")
        assert event["ResultStatus"] in {"Succeeded", "Failed"}
        if event["Workload"] == "Exchange":
            assert event["Operation"] in {
                "Set-Mailbox",
                "New-InboxRule",
                "UpdateInboxRules",
                "MailItemsAccessed",
            }
        if event["Workload"] in {"SharePoint", "OneDrive"}:
            assert "SiteUrl" in event


def test_message_trace_and_defender_are_family_specific():
    trace = microsoft.message_trace_event(base, TS)
    assert trace["Received"] == TS
    assert trace["MessageTraceId"]
    assert trace["SenderAddress"]
    assert trace["RecipientAddress"]
    random.seed(3)
    rows = [microsoft.defender_advanced_hunting_event(base, TS) for _ in range(500)]
    actions = {row["ActionType"] for row in rows}
    assert "ProcessCreated" in actions
    assert any(action.startswith(("Connection", "Inbound")) for action in actions)
    assert any(action.startswith("Logon") for action in actions)
    for row in rows:
        if row["ActionType"] == "ProcessCreated":
            assert "ProcessCommandLine" in row
            assert "RemotePort" not in row
        if row["ActionType"].startswith(("Connection", "Inbound")):
            assert "RemoteIP" in row
            assert "ProcessCommandLine" not in row


def test_pan_zscaler_suricata_auditd_and_asa_formats():
    assert len(network.pan_traffic_record(base, TS).split(",")) >= 45
    assert len(network.pan_threat_record(base, TS).split(",")) >= 50
    zscaler = network.zscaler_web_event(base, TS)
    for field in ("ClientIP", "user", "url", "action", "status", "hostname", "urlclass"):
        assert field in zscaler
    suricata = network.suricata_alert_event(base, TS)
    assert suricata["event_type"] == "alert"
    assert "signature" in suricata["alert"]
    audit = network.auditd_record(base, TS)
    assert audit.startswith("type=")
    assert "msg=audit(" in audit
    asa = network.cisco_asa_record(base, TS)
    assert "%ASA-6-30201" in asa


def test_okta_target_semantics_are_not_actor_aliases():
    random.seed(4)
    events = [cloud.okta_event(base, TS) for _ in range(1000)]
    grant_types = {
        "user.account.privilege.grant",
        "group.user_membership.add",
        "application.user_membership.add",
    }
    grants = [event for event in events if event["eventType"] in grant_types]
    assert grants
    for event in grants:
        assert event["target"]
        user_targets = [target for target in event["target"] if target["type"] == "User"]
        assert user_targets
        assert user_targets[0]["alternateId"]
        assert event["actor"]["alternateId"]


def test_gcp_workspace_kubernetes_github_cloudflare_shapes():
    gcp = cloud.gcp_admin_audit_event(base, TS)
    assert gcp["logName"].endswith("activity")
    assert gcp["protoPayload"]["authenticationInfo"]["principalEmail"]
    assert gcp["protoPayload"]["methodName"]
    workspace = cloud.workspace_admin_event(base, TS)
    assert workspace["id"]["applicationName"] == "admin"
    assert workspace["events"][0]["name"]
    kubernetes = cloud.kubernetes_audit_event(base, TS)
    assert kubernetes["apiVersion"] == "audit.k8s.io/v1"
    assert kubernetes["kind"] == "Event"
    assert kubernetes["sourceIPs"]
    github = cloud.github_audit_event(base, TS)
    assert github["action"]
    assert github["actor"]
    assert github["org"]
    assert github["created_at"] == TS
    cloudflare = cloud.cloudflare_http_event(base, TS)
    assert cloudflare["ClientRequestURI"].startswith(
        "https://" + cloudflare["ClientRequestHost"]
    )
    assert cloudflare["RayID"]


def test_salesforce_is_csv_and_crowdstrike_fields_follow_event_family():
    row = cloud.salesforce_event(base, TS)
    raw = (
        cloud.header("salesforce_event_monitoring")
        + "\n"
        + cloud.serialize("salesforce_event_monitoring", row)
    )
    parsed = list(csv.DictReader(io.StringIO(raw)))
    assert len(parsed) == 1
    assert parsed[0]["EVENT_TYPE"] == row["EVENT_TYPE"]
    random.seed(5)
    events = [cloud.crowdstrike_event(base, TS) for _ in range(1000)]
    families = {event["event_simpleName"] for event in events}
    assert families == {"InjectedThread", "ProcessRollup2", "NetworkConnectIP4", "DnsRequest"}
    for event in events:
        if event["event_simpleName"] == "DnsRequest":
            assert "DomainName" in event
            assert "RemotePort" not in event
        if event["event_simpleName"] == "NetworkConnectIP4":
            assert "RemoteAddressIP4" in event
            assert "RemotePort" in event
        if event["event_simpleName"] == "ProcessRollup2":
            assert "CommandLine" in event
            assert "SHA256HashData" in event
