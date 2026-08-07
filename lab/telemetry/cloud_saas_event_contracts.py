"""Production-shaped Okta, GCP, Workspace, Kubernetes, GitHub, Cloudflare, Salesforce, and CrowdStrike contracts."""
from __future__ import annotations

import csv
import io
import json
import random
import uuid
from typing import Any, Dict


def okta_event(base: Any, ts: str) -> Dict[str, Any]:
    event_type = random.choice([
        "user.session.start",
        "user.authentication.auth_via_mfa",
        "user.account.privilege.grant",
        "group.user_membership.add",
        "application.user_membership.add",
    ])
    actor = base.email()
    target_user = base.email()
    outcome = random.choice(["SUCCESS", "FAILURE"]) if event_type in {"user.session.start", "user.authentication.auth_via_mfa"} else "SUCCESS"
    event: Dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "published": ts,
        "eventType": event_type,
        "version": "0",
        "severity": random.choice(["INFO", "WARN"]),
        "legacyEventType": "core.user_auth.login_success" if outcome == "SUCCESS" else "core.user_auth.login_failed",
        "displayMessage": event_type.replace(".", " "),
        "actor": {"id": "00u" + base.hex_digest(17), "type": "User", "alternateId": actor, "displayName": actor.split("@")[0]},
        "client": {"ipAddress": base.public_ip(), "userAgent": {"rawUserAgent": "Mozilla/5.0"}},
        "outcome": {"result": outcome, "reason": None if outcome == "SUCCESS" else "INVALID_CREDENTIALS"},
        "target": [],
    }
    if event_type in {"user.account.privilege.grant", "group.user_membership.add", "application.user_membership.add"}:
        event["target"].append({"id": "00u" + base.hex_digest(17), "type": "User", "alternateId": target_user, "displayName": target_user.split("@")[0]})
    if event_type == "group.user_membership.add":
        event["target"].append({"id": "00g" + base.hex_digest(17), "type": "UserGroup", "alternateId": "", "displayName": "Security Administrators"})
    if event_type == "application.user_membership.add":
        event["target"].append({"id": "0oa" + base.hex_digest(17), "type": "AppInstance", "alternateId": "", "displayName": "AWS IAM Identity Center"})
    return event


def gcp_admin_audit_event(base: Any, ts: str) -> Dict[str, Any]:
    service, method, resource_type, resource_name = random.choice([
        ("cloudresourcemanager.googleapis.com", "SetIamPolicy", "project", "projects/dei-lab-project"),
        ("compute.googleapis.com", "v1.compute.instances.insert", "gce_instance", "projects/dei-lab-project/zones/us-central1-a/instances/vm01"),
        ("storage.googleapis.com", "storage.setIamPermissions", "gcs_bucket", "projects/_/buckets/security-evidence"),
    ])
    return {
        "logName": "projects/dei-lab-project/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": resource_type, "labels": {"project_id": "dei-lab-project", "location": "us-central1"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authenticationInfo": {"principalEmail": base.email()},
            "authorizationInfo": [{"resource": resource_name, "permission": method, "granted": True}],
            "methodName": method,
            "resourceName": resource_name,
            "serviceName": service,
            "requestMetadata": {"callerIp": base.public_ip(), "callerSuppliedUserAgent": "google-cloud-sdk gcloud/500.0.0"},
        },
        "insertId": base.hex_digest(16),
        "severity": random.choice(["NOTICE", "WARNING"]),
        "timestamp": ts,
    }


def workspace_admin_event(base: Any, ts: str) -> Dict[str, Any]:
    event_name, params = random.choice([
        ("CREATE_USER", [{"name": "USER_EMAIL", "value": base.email()}]),
        ("SUSPEND_USER", [{"name": "USER_EMAIL", "value": base.email()}]),
        ("ADD_GROUP_MEMBER", [{"name": "USER_EMAIL", "value": base.email()}, {"name": "GROUP_EMAIL", "value": "security-admins@corp.example"}]),
        ("AUTHORIZE_API_CLIENT_ACCESS", [{"name": "CLIENT_ID", "value": base.hex_digest(24)}, {"name": "SCOPES", "value": "https://www.googleapis.com/auth/admin.directory.user"}]),
    ])
    return {
        "id": {"time": ts, "uniqueQualifier": str(random.randint(10**18, 10**19 - 1)), "applicationName": "admin"},
        "actor": {"email": base.email(), "profileId": str(random.randint(10**18, 10**19 - 1))},
        "ipAddress": base.public_ip(),
        "events": [{"name": event_name, "type": "USER_SETTINGS" if "USER" in event_name else "GROUP_SETTINGS", "parameters": params}],
    }


def kubernetes_audit_event(base: Any, ts: str) -> Dict[str, Any]:
    verb, resource, code = random.choice([
        ("create", "pods", 201), ("delete", "pods", 200), ("patch", "clusterrolebindings", 200),
        ("create", "secrets", 201), ("get", "secrets", 200), ("create", "serviceaccounts", 201),
    ])
    name = random.choice(["api-server", "payments", "cluster-admin-binding", "registry-secret", "automation"])
    return {
        "apiVersion": "audit.k8s.io/v1",
        "kind": "Event",
        "level": "RequestResponse",
        "auditID": str(uuid.uuid4()),
        "stage": "ResponseComplete",
        "requestURI": f"/api/v1/namespaces/default/{resource}/{name}",
        "verb": verb,
        "user": {"username": random.choice([base.email(), "system:serviceaccount:default:automation"]), "groups": ["system:authenticated"]},
        "sourceIPs": [base.public_ip()],
        "userAgent": random.choice(["kubectl/v1.31.0", "kube-controller-manager/v1.31.0"]),
        "objectRef": {"resource": resource, "namespace": "default", "name": name, "apiVersion": "v1"},
        "responseStatus": {"metadata": {}, "code": code},
        "requestReceivedTimestamp": ts,
        "stageTimestamp": ts,
    }


def github_audit_event(base: Any, ts: str) -> Dict[str, Any]:
    action = random.choice(["org.add_member", "org.invite_member", "repo.add_member", "org.enable_saml", "org.audit_log_export"])
    actor = base.username()
    user = base.username()
    event: Dict[str, Any] = {
        "@timestamp": int(ts.replace("-", "").replace(":", "").replace("T", "").replace("Z", "")[:14]),
        "action": action,
        "actor": actor,
        "actor_id": random.randint(1000000, 99999999),
        "org": "corp-security",
        "org_id": random.randint(1000000, 99999999),
        "repo": "corp-security/detection-content",
        "user": user,
        "user_id": random.randint(1000000, 99999999),
        "user_agent": "Mozilla/5.0",
        "created_at": ts,
        "operation_type": "modify",
    }
    if action == "org.invite_member":
        event["invitee_email"] = base.email()
    if action == "repo.add_member":
        event["permission"] = random.choice(["read", "write", "admin"])
    if action == "org.enable_saml":
        event.update({"issuer": "https://idp.corp.example", "sso_url": "https://idp.corp.example/sso"})
    if action == "org.audit_log_export":
        event["query_phrase"] = "action:repo.add_member"
    return event


def cloudflare_http_event(base: Any, ts: str) -> Dict[str, Any]:
    host = random.choice(["portal.corp.example", "api.corp.example", "files.corp.example"])
    path = random.choice(["/", "/login", "/api/v1/users", "/download"])
    security_action = random.choice(["", "allow", "block", "challenge", "jschallenge", "managed_challenge"])
    return {
        "ClientIP": base.public_ip(),
        "ClientRequestHost": host,
        "ClientRequestMethod": random.choice(["GET", "POST", "PUT", "DELETE"]),
        "ClientRequestPath": path,
        "ClientRequestProtocol": "HTTP/2",
        "ClientRequestURI": f"https://{host}{path}",
        "ClientRequestUserAgent": random.choice(["Mozilla/5.0", "curl/8.7.1"]),
        "EdgeResponseStatus": random.choice([200, 201, 301, 403, 429, 500]),
        "EdgeStartTimestamp": ts,
        "RayID": base.hex_digest(16),
        "SecurityAction": security_action,
        "SecurityRuleID": base.hex_digest(32) if security_action else "",
        "SecurityRuleDescription": "WAF managed rule" if security_action else "",
    }


SALESFORCE_FIELDS = ["EVENT_TYPE", "TIMESTAMP", "REQUEST_ID", "ORGANIZATION_ID", "USER_ID", "RUN_TIME", "CLIENT_IP", "URI", "USER_AGENT", "SESSION_KEY", "LOGIN_KEY"]


def salesforce_event(base: Any, ts: str) -> Dict[str, Any]:
    event_type = random.choice(["Login", "Logout", "ReportExport", "API", "LightningPageView"])
    return {
        "EVENT_TYPE": event_type,
        "TIMESTAMP": ts,
        "REQUEST_ID": base.hex_digest(32),
        "ORGANIZATION_ID": "00D" + base.hex_digest(15).upper(),
        "USER_ID": "005" + base.hex_digest(15).upper(),
        "RUN_TIME": random.randint(1, 5000),
        "CLIENT_IP": base.public_ip(),
        "URI": random.choice(["/login.jsp", "/services/data/v61.0/query", "/lightning/r/Report/00O/view"]),
        "USER_AGENT": random.choice(["Mozilla/5.0", "SalesforceMobileSDK/12.0", "python-requests/2.32"]),
        "SESSION_KEY": base.hex_digest(32),
        "LOGIN_KEY": base.hex_digest(32),
    }


def crowdstrike_event(base: Any, ts: str) -> Dict[str, Any]:
    family = random.choice(["InjectedThread", "ProcessRollup2", "NetworkConnectIP4", "DnsRequest"])
    common: Dict[str, Any] = {
        "event_simpleName": family,
        "event_platform": "Win",
        "aid": base.hex_digest(32),
        "aip": base.public_ip(),
        "cid": base.hex_digest(32),
        "timestamp": str(int(random.random() * 10**6 + 1786110000000)),
        "id": str(uuid.uuid4()),
        "name": family,
    }
    if family == "InjectedThread":
        common.update({"ContextProcessId": random.randint(1000, 65000), "ContextThreadId": random.randint(1000, 65000), "TargetProcessId": random.randint(1000, 65000), "TargetThreadId": random.randint(1000, 65000), "RawProcessId": random.randint(1000, 65000), "RawThreadId": random.randint(1000, 65000), "ThreadStartAddress": random.randint(100000, 999999999), "InjectedThreadFlag": 1})
    elif family == "ProcessRollup2":
        common.update({"ImageFileName": r"\Device\HarddiskVolume3\Windows\System32\powershell.exe", "CommandLine": "powershell.exe -NoProfile Get-Process", "ParentBaseFileName": "explorer.exe", "RawProcessId": random.randint(1000, 65000), "UserName": base.username(), "SHA256HashData": base.hex_digest(64)})
    elif family == "NetworkConnectIP4":
        common.update({"LocalAddressIP4": base.private_ip(), "LocalPort": random.randint(1024, 65535), "RemoteAddressIP4": base.public_ip(), "RemotePort": random.choice([53, 80, 443, 3389]), "Protocol": random.choice([6, 17]), "ContextProcessId": random.randint(1000, 65000)})
    else:
        common.update({"DomainName": random.choice(["login.corp.example", "updates.vendor.example", "example.com"]), "ContextProcessId": random.randint(1000, 65000), "RequestType": random.choice([1, 28])})
    return common


def make_cloud_saas_event(profile_id: str, base: Any, ts: str) -> Dict[str, Any]:
    if profile_id == "okta_system_log": return okta_event(base, ts)
    if profile_id == "gcp_audit": return gcp_admin_audit_event(base, ts)
    if profile_id == "google_workspace": return workspace_admin_event(base, ts)
    if profile_id == "kubernetes_audit": return kubernetes_audit_event(base, ts)
    if profile_id == "github_audit": return github_audit_event(base, ts)
    if profile_id == "cloudflare_http": return cloudflare_http_event(base, ts)
    if profile_id == "salesforce_event_monitoring": return salesforce_event(base, ts)
    if profile_id == "crowdstrike_fdr_sensor": return crowdstrike_event(base, ts)
    raise ValueError(f"Unsupported cloud/SaaS profile: {profile_id}")


def serialize(profile_id: str, event: Dict[str, Any]) -> str:
    if profile_id == "salesforce_event_monitoring":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=SALESFORCE_FIELDS, lineterminator="")
        writer.writerow(event)
        return buf.getvalue()
    return json.dumps(event, separators=(",", ":"))


def header(profile_id: str) -> str:
    if profile_id == "salesforce_event_monitoring":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="")
        writer.writerow(SALESFORCE_FIELDS)
        return buf.getvalue()
    return ""


def extension(profile_id: str) -> str:
    return ".csv" if profile_id == "salesforce_event_monitoring" else ".ndjson"


def contract_metadata() -> Dict[str, Any]:
    return {"version": 1, "profiles": ["okta_system_log", "gcp_audit", "google_workspace", "kubernetes_audit", "github_audit", "cloudflare_http", "salesforce_event_monitoring", "crowdstrike_fdr_sensor"]}
