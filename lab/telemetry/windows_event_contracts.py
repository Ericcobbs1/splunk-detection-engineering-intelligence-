"""Event-specific semantic and XML contracts for DEI Windows lab telemetry."""
from __future__ import annotations

import random
import uuid
from typing import Any, Dict, Optional
from xml.sax.saxutils import escape

CONTRACT_VERSION = 2
MICROSOFT_EVENT_DOC = (
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/"
    "security/threat-protection/auditing/event-{}"
)
SECURITY_EVENT_CODES = (4624, 4625, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4756, 4757)
POWERSHELL_EVENT_CODES = (4103, 4104)
LOGON_TYPES = (2, 3, 4, 5, 7, 8, 9, 10, 11)
AUTH_PACKAGES = ("Kerberos", "Negotiate", "NTLM")
LOGON_PROCESSES = ("User32", "Advapi", "NtLmSsp", "Kerberos")
PROCESS_NAMES = (
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
)
FAILURE_STATUS = (
    ("0xC000006D", "0xC000006A", "%%2313"),
    ("0xC0000064", "0x0", "%%2313"),
    ("0xC0000234", "0x0", "%%2307"),
)


def _sid(rid: Optional[int] = None) -> str:
    rid = rid if rid is not None else random.randint(1000, 9999)
    return f"S-1-5-21-3457937927-2839227994-823803824-{rid}"


def _subject(base: Any) -> Dict[str, Any]:
    return {
        "SubjectUserSid": _sid(random.randint(1000, 2000)),
        "SubjectUserName": base.username(),
        "SubjectDomainName": "CORP",
        "SubjectLogonId": f"0x{random.randint(0x10000, 0xFFFFF):x}",
    }


def _target(base: Any, group: bool = False) -> Dict[str, Any]:
    name = random.choice(["Domain Admins", "SOC Analysts", "Server Operators"]) if group else base.username()
    return {"TargetUserName": name, "TargetDomainName": "CORP", "TargetSid": _sid(random.randint(2000, 9000))}


def _base_event(event_code: int, base: Any) -> Dict[str, Any]:
    return {"EventCode": event_code, "Computer": base.hostname()}


def security_event(base: Any) -> Dict[str, Any]:
    code = random.choice(SECURITY_EVENT_CODES)
    event = _base_event(code, base)
    event.update(_subject(base))
    if code in {4624, 4625}:
        event.update({
            "TargetUserSid": _sid(random.randint(2000, 9000)), "TargetUserName": base.username(), "TargetDomainName": "CORP",
            "LogonType": random.choice(LOGON_TYPES), "LogonProcessName": random.choice(LOGON_PROCESSES),
            "AuthenticationPackageName": random.choice(AUTH_PACKAGES), "WorkstationName": base.hostname().split(".")[0].upper(),
            "ProcessId": f"0x{random.randint(0x100, 0xFFFF):x}", "ProcessName": random.choice(PROCESS_NAMES),
            "IpAddress": base.private_ip(), "IpPort": random.choice([0, 445, 3389, random.randint(1024, 65535)]),
        })
        if code == 4625:
            status, substatus, reason = random.choice(FAILURE_STATUS)
            event.update({"Status": status, "SubStatus": substatus, "FailureReason": reason})
        return event
    if code == 4720:
        event.update(_target(base))
        event.update({
            "SamAccountName": event["TargetUserName"], "DisplayName": event["TargetUserName"].replace("_", " ").title(),
            "UserPrincipalName": f"{event['TargetUserName'].replace('_', '.')}@corp.example", "PrimaryGroupId": 513,
            "OldUacValue": "0x0", "NewUacValue": random.choice(["0x15", "0x210"]), "PrivilegeList": "-",
        })
        return event
    if code in {4722, 4723, 4724, 4725, 4726}:
        event.update(_target(base)); return event
    if code in {4728, 4729, 4756, 4757}:
        event.update(_target(base, group=True))
        member = base.username()
        event.update({"MemberName": f"CN={member},OU=Users,DC=corp,DC=example", "MemberId": _sid(random.randint(2000, 9000)), "PrivilegeList": "-"})
        return event
    raise AssertionError(f"Unhandled Windows Security EventCode: {code}")


def powershell_event(base: Any) -> Dict[str, Any]:
    code = random.choice(POWERSHELL_EVENT_CODES)
    event = _base_event(code, base)
    event["UserId"] = _sid(random.randint(1000, 9000))
    if code == 4104:
        script = random.choice([
            "Get-Process | Where-Object {$_.CPU -gt 100}",
            "Get-ChildItem C:\\Windows\\System32 | Select-Object -First 20",
            "$svc = Get-Service; $svc | Where-Object {$_.Status -eq 'Running'}",
            "Get-WinEvent -LogName Security -MaxEvents 25",
        ])
        event.update({"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": script, "ScriptBlockId": str(uuid.uuid4()),
                      "Path": random.choice(["", r"C:\ProgramData\Corp\Scripts\inventory.ps1"]),
                      "Message": f"Creating Scriptblock text (1 of 1):\n{script}"})
        return event
    event["Message"] = random.choice([
        "CommandInvocation(Get-Process): ParameterBinding(Get-Process)",
        "CommandInvocation(Get-Service): ParameterBinding(Get-Service)",
        "CommandInvocation(Get-ChildItem): ParameterBinding(Get-ChildItem)",
    ])
    return event


def make_windows_event(profile_id: str, base: Any) -> Dict[str, Any]:
    if profile_id == "windows_security": return security_event(base)
    if profile_id == "windows_powershell": return powershell_event(base)
    raise ValueError(f"Unsupported Windows profile: {profile_id}")


def serialize_windows_event(profile_id: str, event: Dict[str, Any], ts: str) -> str:
    """Render a Windows Event XML record consumed by XmlWinEventLog parsers."""
    security = profile_id == "windows_security"
    provider = "Microsoft-Windows-Security-Auditing" if security else "Microsoft-Windows-PowerShell"
    channel = "Security" if security else "Microsoft-Windows-PowerShell/Operational"
    event_id = int(event["EventCode"])
    computer = escape(str(event["Computer"]))
    event_data = []
    for key, value in event.items():
        if key in {"EventCode", "Computer"}: continue
        text = "" if value is None else escape(str(value))
        event_data.append(f'<Data Name="{escape(str(key))}">{text}</Data>')
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        f'<Provider Name="{provider}"/>'
        f'<EventID>{event_id}</EventID><Version>{2 if security else 1}</Version><Level>0</Level><Task>0</Task><Opcode>0</Opcode>'
        '<Keywords>0x8020000000000000</Keywords>'
        f'<TimeCreated SystemTime="{escape(ts)}"/><EventRecordID>{random.randint(100000,99999999)}</EventRecordID>'
        f'<Channel>{channel}</Channel><Computer>{computer}</Computer><Security/>'
        '</System><EventData>' + ''.join(event_data) + '</EventData></Event>'
    )


def contract_metadata() -> Dict[str, Any]:
    return {
        "version": CONTRACT_VERSION,
        "wire_format": "windows_event_xml",
        "security_event_codes": list(SECURITY_EVENT_CODES),
        "powershell_event_codes": list(POWERSHELL_EVENT_CODES),
        "authorities": {str(code): MICROSOFT_EVENT_DOC.format(code) for code in SECURITY_EVENT_CODES},
        "powershell": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent",
    }
