"""Production-shaped Microsoft 365 and Defender event contracts."""
from __future__ import annotations

import json
import random
import uuid
from typing import Any, Dict

TENANT = "00000000-0000-0000-0000-000000000001"


def management_activity_event(base: Any, ts: str) -> Dict[str, Any]:
    workload = random.choice(["Exchange", "SharePoint", "OneDrive", "MicrosoftTeams"])
    operations = {
        "Exchange": ["Set-Mailbox", "New-InboxRule", "UpdateInboxRules", "MailItemsAccessed"],
        "SharePoint": ["FileAccessed", "FileDownloaded", "SharingSet", "AnonymousLinkCreated"],
        "OneDrive": ["FileAccessed", "FileDownloaded", "FileDeleted", "SharingInvitationCreated"],
        "MicrosoftTeams": ["MemberAdded", "MemberRemoved", "TeamCreated", "MessageSent"],
    }
    operation = random.choice(operations[workload])
    user = base.email()
    event: Dict[str, Any] = {
        "Id": str(uuid.uuid4()),
        "RecordType": random.choice([1, 2, 4, 6, 25]),
        "CreationTime": ts,
        "Operation": operation,
        "OrganizationId": TENANT,
        "UserType": random.choice([0, 2, 4, 5, 6]),
        "UserKey": user,
        "Workload": workload,
        "ResultStatus": random.choice(["Succeeded", "Failed"]),
        "ObjectId": f"https://tenant.sharepoint.com/sites/security/{base.hex_digest(8)}" if workload in {"SharePoint", "OneDrive"} else base.username(),
        "UserId": user,
        "ClientIP": base.public_ip(),
        "Scope": 0,
    }
    if workload == "Exchange":
        event.update({"ClientIPAddress": event["ClientIP"], "ClientInfoString": "Client=REST;Outlook-iOS/2.0", "ExternalAccess": False})
    if workload in {"SharePoint", "OneDrive"}:
        event.update({"SiteUrl": "https://tenant.sharepoint.com/sites/security", "SourceFileName": "quarterly-report.docx"})
    return event


def message_trace_event(base: Any, ts: str) -> Dict[str, Any]:
    sender = base.email()
    recipient = base.email()
    return {
        "Organization": "corp.example",
        "MessageId": f"<{uuid.uuid4()}@corp.example>",
        "Received": ts,
        "SenderAddress": sender,
        "RecipientAddress": recipient,
        "Subject": random.choice(["Quarterly report", "Password reset", "Invoice review", "Security notification"]),
        "Status": random.choice(["Delivered", "Failed", "Pending", "FilteredAsSpam"]),
        "ToIP": base.private_ip(),
        "FromIP": base.public_ip(),
        "Size": random.randint(1024, 5_000_000),
        "MessageTraceId": str(uuid.uuid4()),
    }


def defender_advanced_hunting_event(base: Any, ts: str) -> Dict[str, Any]:
    """Generate one coherent result row from a Defender Advanced Hunting table."""
    table = random.choice(["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceLogonEvents"])
    common: Dict[str, Any] = {
        "Timestamp": ts,
        "DeviceId": base.hex_digest(40),
        "DeviceName": base.hostname(),
        "ReportId": random.randint(1000000, 999999999),
    }
    if table == "DeviceProcessEvents":
        common.update({
            "ActionType": "ProcessCreated",
            "FileName": random.choice(["powershell.exe", "cmd.exe", "rundll32.exe", "msedge.exe"]),
            "FolderPath": r"C:\Windows\System32",
            "SHA1": base.hex_digest(40),
            "SHA256": base.hex_digest(64),
            "ProcessCommandLine": random.choice(["powershell.exe -NoProfile Get-Process", "cmd.exe /c whoami", "rundll32.exe shell32.dll,Control_RunDLL"]),
            "AccountName": base.username(),
            "AccountDomain": "CORP",
            "InitiatingProcessFileName": random.choice(["explorer.exe", "services.exe", "winword.exe"]),
            "InitiatingProcessCommandLine": "explorer.exe",
            "ProcessId": random.randint(1000, 65000),
            "InitiatingProcessId": random.randint(1000, 65000),
        })
    elif table == "DeviceNetworkEvents":
        common.update({
            "ActionType": random.choice(["ConnectionSuccess", "ConnectionFailed", "InboundConnectionAccepted"]),
            "RemoteIP": base.public_ip(),
            "RemotePort": random.choice([22, 53, 80, 443, 3389]),
            "LocalIP": base.private_ip(),
            "LocalPort": random.randint(1024, 65535),
            "Protocol": random.choice(["Tcp", "Udp"]),
            "InitiatingProcessFileName": random.choice(["powershell.exe", "chrome.exe", "svchost.exe"]),
            "InitiatingProcessCommandLine": "powershell.exe -NoProfile",
            "InitiatingProcessAccountName": base.username(),
        })
    else:
        common.update({
            "ActionType": random.choice(["LogonSuccess", "LogonFailed"]),
            "AccountName": base.username(),
            "AccountDomain": "CORP",
            "LogonType": random.choice(["Interactive", "Network", "RemoteInteractive"]),
            "RemoteIP": base.public_ip(),
            "RemoteDeviceName": base.hostname(),
            "Protocol": random.choice(["NTLM", "Kerberos", "Negotiate"]),
        })
    return common


def make_microsoft_event(profile_id: str, base: Any, ts: str) -> Dict[str, Any]:
    if profile_id == "m365_management_activity":
        return management_activity_event(base, ts)
    if profile_id == "m365_message_trace":
        return message_trace_event(base, ts)
    if profile_id == "microsoft_defender_endpoint":
        return defender_advanced_hunting_event(base, ts)
    raise ValueError(f"Unsupported Microsoft profile: {profile_id}")


def serialize(event: Dict[str, Any]) -> str:
    return json.dumps(event, separators=(",", ":"))


def contract_metadata() -> Dict[str, Any]:
    return {
        "version": 1,
        "profiles": ["m365_management_activity", "m365_message_trace", "microsoft_defender_endpoint"],
        "authorities": {
            "management_activity": "https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema",
            "message_trace": "https://splunk.github.io/splunk-add-on-for-microsoft-office-365/ConfigureMessageTraceInput/",
            "defender": "https://splunk.github.io/splunk-add-on-for-microsoft-365-defender/Sourcetypes/",
        },
    }
