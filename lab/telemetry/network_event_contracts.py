"""TA-facing PAN, Zscaler, Suricata, Linux auditd, and Cisco ASA contracts."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime
from typing import Any


def _pan_time(ts: str) -> str:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y/%m/%d %H:%M:%S")


def pan_traffic_record(base: Any, ts: str) -> str:
    # PAN-OS documented ordered Traffic record through Session End Reason.
    t = _pan_time(ts)
    src, dst = base.private_ip(), base.public_ip()
    sport, dport = random.randint(1024, 65535), random.choice([22, 53, 80, 443, 3389])
    app = random.choice(["ssl", "web-browsing", "dns", "ssh", "ms-rdp"])
    action = random.choice(["allow", "deny", "drop"])
    values = [
        "1", t, "012345678901", "TRAFFIC", random.choice(["start", "end", "deny", "drop"]), "", t,
        src, dst, "0.0.0.0", "0.0.0.0", "corp-egress", base.username(), "", app, "vsys1",
        "trust", "untrust", "ethernet1/1", "ethernet1/2", "default", "", random.randint(10000, 999999),
        1, sport, dport, 0, 0, "0x19", random.choice(["tcp", "udp"]), action,
        random.randint(500, 5_000_000), random.randint(250, 2_500_000), random.randint(250, 2_500_000),
        random.randint(1, 5000), t, random.randint(1, 3600), "any", "", random.randint(1, 999999999),
        "0x0", "10.0.0.0-10.255.255.255", "United States", "", random.randint(1, 2500), random.randint(1, 2500),
        random.choice(["tcp-fin", "aged-out", "policy-deny", "tcp-rst-from-server"]),
    ]
    return ",".join(str(v) for v in values)


def pan_threat_record(base: Any, ts: str) -> str:
    # PAN-OS documented ordered Threat record through Report ID.
    t = _pan_time(ts)
    src, dst = base.private_ip(), base.public_ip()
    subtype = random.choice(["virus", "vulnerability", "spyware", "wildfire", "url"])
    threat_id = random.choice(["Suspicious PowerShell User-Agent(92001)", "Generic Exploit Attempt(40001)", "Malware Download(60001)"])
    severity = random.choice(["informational", "low", "medium", "high", "critical"])
    digest = base.hex_digest(64) if subtype in {"virus", "wildfire"} else ""
    values = [
        "1", t, "012345678901", "THREAT", subtype, "", t,
        src, dst, "0.0.0.0", "0.0.0.0", "corp-egress", base.username(), "", random.choice(["ssl", "web-browsing", "dns"]),
        "vsys1", "trust", "untrust", "ethernet1/1", "ethernet1/2", "default", "", random.randint(10000, 999999),
        1, random.randint(1024, 65535), random.choice([53, 80, 443]), 0, 0, "0x80000000", random.choice(["tcp", "udp"]),
        random.choice(["alert", "deny", "drop", "reset-both"]), "https://downloads.example/payload.bin", threat_id,
        random.choice(["malware", "phishing", "command-and-control", "unknown"]), severity, "client-to-server",
        random.randint(1, 999999999), "0x0", "10.0.0.0-10.255.255.255", "United States", "", "application/octet-stream",
        "0", digest, "public", 1, "Mozilla/5.0", "PE", "", "https://referrer.example/", base.email(), "Security notice",
        base.email(), base.hex_digest(16),
    ]
    return ",".join(str(v) for v in values)


def zscaler_web_event(base: Any, ts: str) -> dict:
    # Fields follow the Zscaler Splunk custom JSON feed guidance.
    action = random.choice(["Allowed", "Blocked"])
    status = "403" if action == "Blocked" else random.choice(["200", "206", "302"])
    host = random.choice(["portal.corp.example", "downloads.example", "login.example"])
    return {
        "datetime": ts,
        "reason": random.choice(["Allowed by policy", "URL category blocked", "Advanced threat protection"]),
        "event_id": random.randint(10**12, 10**15),
        "protocol": random.choice(["HTTP", "HTTPS"]),
        "action": action,
        "transactionsize": random.randint(500, 5_000_000),
        "responsesize": random.randint(250, 4_000_000),
        "requestsize": random.randint(100, 100_000),
        "urlcategory": random.choice(["Business and Economy", "Online Storage", "Phishing", "Malware Sites"]),
        "serverip": base.public_ip(),
        "clienttranstime": random.randint(1, 5000),
        "requestmethod": random.choice(["GET", "POST", "CONNECT"]),
        "refererURL": "https://portal.corp.example/",
        "useragent": random.choice(["Mozilla/5.0", "curl/8.7.1", "Microsoft Office/16.0"]),
        "product": "NSS",
        "location": "Corporate HQ",
        "ClientIP": base.private_ip(),
        "status": status,
        "user": base.email(),
        "url": f"https://{host}/download",
        "vendor": "Zscaler",
        "hostname": host,
        "clientpublicIP": base.public_ip(),
        "threatcategory": "None" if action == "Allowed" else random.choice(["Phishing", "Virus", "Spyware Callback"]),
        "threatname": "None" if action == "Allowed" else "Generic Web Threat",
        "filetype": random.choice(["None", "PDF", "Windows Executables", "ZIP"]),
        "appname": random.choice(["General Browsing", "Microsoft 365", "GitHub"]),
        "pagerisk": random.randint(0, 100),
        "department": random.choice(["IT", "Finance", "Security", "Engineering"]),
        "urlsupercategory": random.choice(["Business", "Security", "Information Technology"]),
        "appclass": random.choice(["Business", "Webmail", "File Sharing"]),
        "dlpengine": "None",
        "urlclass": random.choice(["Business Use", "General Surfing", "Privacy Risk"]),
        "threatclass": "None" if action == "Allowed" else "Malware",
        "contenttype": random.choice(["text/html", "application/pdf", "application/octet-stream"]),
        "deviceowner": base.email(),
        "devicehostname": base.hostname(),
        "servertranstime": random.randint(1, 5000),
    }


def suricata_alert_event(base: Any, ts: str) -> dict:
    return {
        "timestamp": ts,
        "flow_id": random.randint(10**12, 10**15),
        "event_type": "alert",
        "src_ip": base.private_ip(),
        "src_port": random.randint(1024, 65535),
        "dest_ip": base.public_ip(),
        "dest_port": random.choice([22, 53, 80, 443, 3389]),
        "proto": random.choice(["TCP", "UDP"]),
        "app_proto": random.choice(["http", "tls", "dns", "ssh"]),
        "alert": {
            "action": random.choice(["allowed", "blocked"]),
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": random.randint(1, 10),
            "signature": random.choice(["ET MALWARE Suspicious Download", "ET SCAN Potential SSH Scan", "ET POLICY Suspicious TLS"]),
            "category": random.choice(["A Network Trojan was detected", "Attempted Information Leak", "Potentially Bad Traffic"]),
            "severity": random.choice([1, 2, 3]),
        },
    }


def auditd_record(base: Any, ts: str) -> str:
    epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    serial = random.randint(100000, 999999)
    if random.random() < 0.75:
        user = random.randint(1000, 1100)
        return (
            f'type=SYSCALL msg=audit({epoch:.3f}:{serial}): arch=c000003e syscall={random.choice([59,257,105,106])} '
            f'success={random.choice(["yes","no"])} exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={random.randint(1,5000)} '
            f'pid={random.randint(1000,65000)} auid={user} uid={user} gid={user} euid={user} suid={user} fsuid={user} '
            f'egid={user} sgid={user} fsgid={user} tty=pts0 ses={random.randint(1,50)} comm="{random.choice(["sudo","bash","ssh","curl"])}" '
            f'exe="{random.choice(["/usr/bin/sudo","/usr/bin/bash","/usr/bin/ssh","/usr/bin/curl"])}" key="privileged"'
        )
    return (
        f'type=USER_AUTH msg=audit({epoch:.3f}:{serial}): pid={random.randint(1000,65000)} uid=0 auid={random.randint(1000,1100)} '
        f'ses={random.randint(1,50)} msg=\'op=PAM:authentication acct="{base.username()}" exe="/usr/sbin/sshd" '
        f'hostname={base.public_ip()} addr={base.public_ip()} terminal=ssh res={random.choice(["success","failed"])}\''
    )


def cisco_asa_record(base: Any, ts: str) -> str:
    src, dst = base.private_ip(), base.public_ip()
    sport, dport = random.randint(1024, 65535), random.choice([22, 53, 80, 443, 3389])
    conn = random.randint(1, 999999)
    stamp = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%b %d %Y %H:%M:%S")
    if random.random() < 0.6:
        return f"{stamp}: %ASA-6-302013: Built outbound TCP connection {conn} for outside:{dst}/{dport} ({dst}/{dport}) to inside:{src}/{sport} ({src}/{sport})"
    return f"{stamp}: %ASA-6-302014: Teardown TCP connection {conn} for outside:{dst}/{dport} to inside:{src}/{sport} duration 0:00:{random.randint(1,59):02d} bytes {random.randint(0,5000000)} TCP FINs"


def make_network_event(profile_id: str, base: Any, ts: str) -> Any:
    if profile_id == "palo_alto_traffic": return pan_traffic_record(base, ts)
    if profile_id == "palo_alto_threat": return pan_threat_record(base, ts)
    if profile_id == "zscaler_zia_web": return zscaler_web_event(base, ts)
    if profile_id == "suricata_eve_alert": return suricata_alert_event(base, ts)
    if profile_id == "linux_auditd": return auditd_record(base, ts)
    if profile_id == "cisco_asa": return cisco_asa_record(base, ts)
    raise ValueError(f"Unsupported network profile: {profile_id}")


def serialize(profile_id: str, event: Any) -> str:
    if isinstance(event, str): return event
    return json.dumps(event, separators=(",", ":"))


def extension(profile_id: str) -> str:
    if profile_id in {"palo_alto_traffic", "palo_alto_threat"}: return ".csv"
    if profile_id in {"linux_auditd", "cisco_asa"}: return ".log"
    return ".ndjson"


def contract_metadata() -> dict:
    return {
        "version": 1,
        "profiles": ["palo_alto_traffic", "palo_alto_threat", "zscaler_zia_web", "suricata_eve_alert", "linux_auditd", "cisco_asa"],
        "authorities": {
            "pan_traffic": "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields",
            "pan_threat": "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields",
            "zscaler": "https://help.zscaler.com/unified/nss-feed-output-format-web-logs",
            "cisco": "https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html",
            "suricata": "https://docs.suricata.io/en/latest/output/eve/eve-json-format.html",
            "auditd": "https://man7.org/linux/man-pages/man8/auditd.8.html",
        },
    }
