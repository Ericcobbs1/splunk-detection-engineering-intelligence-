"""TA-facing Azure Monitor event contracts for DEI lab telemetry."""
from __future__ import annotations

import random
import uuid
from typing import Any, Dict

CONTRACT_VERSION = 1
TENANT_ID = "501792f2-ef2c-4251-957b-293fadb63ddc"
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"

ENTRA_CATEGORIES = (
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "ManagedIdentitySignInLogs",
)
CA_STATUS = ("success", "failure", "notApplied")
RISK_LEVEL = ("none", "low", "medium", "high", "hidden")
RISK_STATE = ("none", "confirmedSafe", "remediated", "dismissed", "atRisk", "confirmedCompromised")
CLIENT_APPS = ("Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync", "Other clients")


def _user_display(base: Any) -> str:
    return base.username().replace("_", " ").title()


def entra_signin_event(base: Any, ts: str) -> Dict[str, Any]:
    """Return an Azure Monitor AAD envelope containing Entra sign-in properties."""
    category = random.choice(ENTRA_CATEGORIES)
    principal = base.email()
    client_ip = base.public_ip()
    result = random.choice(
        [
            ("0", "Success"),
            ("50126", "Error validating credentials due to invalid username or password."),
            ("50074", "Strong authentication is required."),
            ("53003", "Access has been blocked by Conditional Access policies."),
        ]
    )
    success = result[0] == "0"
    app_id = str(uuid.uuid4())
    resource_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())

    properties: Dict[str, Any] = {
        "id": event_id,
        "createdDateTime": ts,
        "userDisplayName": _user_display(base),
        "userPrincipalName": principal,
        "userId": user_id,
        "appId": app_id,
        "appDisplayName": random.choice(["Microsoft 365", "Azure Portal", "Microsoft Graph", "Exchange Online"]),
        "ipAddress": client_ip,
        "clientAppUsed": random.choice(CLIENT_APPS),
        "conditionalAccessStatus": random.choice(CA_STATUS),
        "correlationId": str(uuid.uuid4()),
        "resourceDisplayName": random.choice(["Microsoft Graph", "Office 365 Exchange Online", "Windows Azure Service Management API"]),
        "resourceId": resource_id,
        "homeTenantId": TENANT_ID,
        "resourceTenantId": TENANT_ID,
        "isInteractive": category == "SignInLogs",
        "riskDetail": "none" if success else random.choice(["none", "adminConfirmedSigninCompromised", "userPerformedSecuredPasswordReset"]),
        "riskLevelAggregated": random.choice(RISK_LEVEL),
        "riskLevelDuringSignIn": random.choice(RISK_LEVEL),
        "riskState": random.choice(RISK_STATE),
        "authenticationRequirement": random.choice(["singleFactorAuthentication", "multiFactorAuthentication"]),
        "deviceDetail": {
            "deviceId": str(uuid.uuid4()),
            "displayName": base.hostname(),
            "operatingSystem": random.choice(["Windows 11", "macOS", "iOS", "Android"]),
            "browser": random.choice(["Edge", "Chrome", "Safari"]),
            "isCompliant": random.choice([True, False]),
            "isManaged": random.choice([True, False]),
        },
        "status": {
            "errorCode": int(result[0]),
            "failureReason": "" if success else result[1],
            "additionalDetails": "MFA completed" if success else "",
        },
    }

    return {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "operationVersion": "1.0",
        "category": category,
        "tenantId": TENANT_ID,
        "resultType": result[0],
        "resultSignature": "None",
        "durationMs": random.randint(0, 2500),
        "callerIpAddress": client_ip,
        "correlationId": properties["correlationId"],
        "identity": principal,
        "Level": 4,
        "location": random.choice(["US", "CA", "GB", "DE"]),
        "properties": properties,
    }


def azure_activity_event(base: Any, ts: str) -> Dict[str, Any]:
    """Return a Microsoft Azure Activity Log record envelope."""
    operation = random.choice(
        [
            "Microsoft.Compute/virtualMachines/write",
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Storage/storageAccounts/write",
            "Microsoft.Network/networkSecurityGroups/write",
        ]
    )
    caller = base.email()
    success = random.choice([True, True, True, False])
    return {
        "time": ts,
        "category": "Administrative",
        "operationName": operation,
        "resourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/dei-lab/"
            "providers/Microsoft.Compute/virtualMachines/vm01"
        ),
        "callerIpAddress": base.public_ip(),
        "correlationId": str(uuid.uuid4()),
        "durationMs": random.randint(1, 5000),
        "identity": {
            "authorization": {
                "action": operation,
                "scope": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/dei-lab",
            },
            "claims": {
                "name": caller,
                "http://schemas.microsoft.com/identity/claims/objectidentifier": str(uuid.uuid4()),
            },
        },
        "level": "Informational" if success else "Error",
        "properties": {
            "statusCode": "OK" if success else "Forbidden",
            "serviceRequestId": str(uuid.uuid4()),
        },
        "resultSignature": "Succeeded" if success else "Failed",
        "resultType": "Success" if success else "Failure",
        "tenantId": TENANT_ID,
    }


def contract_metadata() -> Dict[str, Any]:
    return {
        "version": CONTRACT_VERSION,
        "entra_sourcetype": "azure:monitor:aad",
        "activity_sourcetype": "azure:monitor:activity",
        "authorities": {
            "splunk_source_types": "https://help.splunk.com/en/splunk-cloud-platform/ingest-data-from-cloud-services/data-inputs-user-manual/1.17/getting-data-in-gdi/overview-of-source-types-for-data-inputs",
            "signin_schema": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs",
            "activity_schema": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema",
        },
    }
