# DEI SIEM Telemetry Corpus Plan

## Objective

Build a production-realistic SIEM corpus for DEI using source-native event structures and field/value pairs that are traceable to authoritative vendor documentation, Splunk-supported add-ons, vendor-supported Splunk add-ons, or Splunk CIM documentation.

The corpus is a validation asset for the detection engine. It must not invent fields merely to make detections production-ready.

## Non-negotiable provenance rules

1. A generated source profile must be `verified` before the generator is allowed to emit events for it.
2. `verified` requires at least one authoritative event-schema reference and, where Splunk parsing/CIM depends on an add-on, a Splunk or vendor-supported TA reference.
3. Raw events model the vendor schema. CIM fields are expected to be produced by the supported TA/search-time knowledge unless the vendor itself emits that field.
4. Lab-only aliases are never promoted to production truth.
5. Event values must respect vendor value domains where documented (for example Okta `outcome.result`, Microsoft 365 `ResultStatus`, Palo Alto `Action`, Suricata `event_type`, Windows `EventCode`).
6. Profiles that still need authoritative research remain `pending_research` and are generator-blocked.

## TA strategy

Install technology add-ons when they materially provide source typing, field extraction, event typing, tags, or CIM mappings. Do not recreate those mappings inside the synthetic generator.

Initial TA candidates:

- Splunk Add-on for Microsoft Windows (TA-Windows)
- Splunk Add-on for Unix and Linux (TA-nix)
- Splunk Add-on for AWS (TA-AWS) where used for Enterprise collection/parsing
- Splunk Add-on for Okta Identity Cloud
- Splunk Add-on for Microsoft Office 365
- Splunk Add-on for Microsoft Cloud Services / Microsoft Security as applicable to the selected Azure/Defender path
- Splunk Add-on for CrowdStrike FDR
- Zscaler Technical Add-On for Splunk
- Palo Alto Networks add-on/app-supported parsing path
- Splunk Add-on for Cisco ASA
- Splunk Add-on for Google Workspace
- Community/vendor-supported Suricata TA where required for CIM

## Target telemetry families

The full corpus target includes:

- Windows Security, PowerShell, Sysmon, Active Directory and DNS
- Linux auth/syslog and auditd
- AWS CloudTrail, GuardDuty, Security Hub, IAM Access Analyzer, VPC Flow, CloudWatch and S3 activity
- Microsoft Entra ID sign-in and audit logs, Azure Activity, Defender/Security, Office 365 audit and message trace
- GCP Audit Logs, VPC Flow and Security Command Center
- Google Workspace authentication/admin/Gmail activity
- Okta System Log
- CrowdStrike Falcon FDR
- Microsoft Defender for Endpoint
- Palo Alto Networks traffic/threat/config/globalprotect
- Cisco ASA and IOS
- Zscaler ZIA web/firewall/DLP and ZPA
- DNS, DHCP, proxy, VPN and NetFlow
- Suricata/IDS/IPS
- Email security gateways
- DLP
- Vulnerability scanners (Tenable/Qualys/Rapid7)
- Kubernetes/container audit and runtime telemetry
- Database audit telemetry
- SaaS audit sources such as GitHub and Salesforce
- Threat-intelligence feeds
- Splunk Enterprise Security notable/finding and Risk data-model events
- AI service/gateway audit telemetry only where a vendor schema is available

## Corpus generation phases

### Phase A — schema registry

Create a machine-readable source registry containing:

- vendor/product
- supported Splunk sourcetype(s)
- production-style target index
- required/recommended TA
- raw vendor fields
- documented value domains/examples
- CIM data models enabled by the TA
- authoritative documentation URLs
- verification status

### Phase B — event generators

Implement source-specific generators. Each generator must consume its verified registry profile and produce both benign background activity and security-relevant sequences. The generator must reject `pending_research` profiles.

### Phase C — TA validation

Where a TA is required, install it and verify:

1. sourcetype assignment
2. expected field extraction
3. CIM tags/eventtypes
4. data-model visibility
5. representative DEI field readiness

### Phase D — detection corpus expansion

After telemetry breadth is established, expand the detection opportunity catalog from the 21-detection baseline into a broad ATT&CK-aligned catalog with alternate telemetry paths rather than one rigid sourcetype per detection.

## Current verified foundation

The first registry batch includes authoritative profiles for Windows Security, Windows PowerShell, AWS CloudTrail, AWS GuardDuty, Okta System Log, Microsoft 365 Management Activity, Microsoft 365 Message Trace, Microsoft Entra sign-in telemetry, Palo Alto traffic logs, Zscaler NSS web logs, and Suricata EVE alerts. Remaining target sources are explicitly marked pending until their field schemas are reviewed.
