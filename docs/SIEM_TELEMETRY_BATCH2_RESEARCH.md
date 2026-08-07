# SIEM Telemetry Batch 2 Research

This batch promotes only source profiles whose Splunk sourcetype and event-field shape can be tied to authoritative Splunk or vendor documentation.

## Promoted profiles

### CrowdStrike FDR sensor telemetry
- Splunk sourcetype: `crowdstrike:events:sensor`
- Integration: Splunk Add-on for CrowdStrike FDR / Splunk Data Inputs CrowdStrike
- High-value native fields include `event_simpleName`, `event_platform`, `aid`, `aip`, `cid`, process/thread identifiers, and event timestamps.
- Splunk documentation publishes example FDR sensor events and the exact sourcetype.

### AWS Security Hub
- Splunk sourcetype: `aws:securityhub:finding`
- Integration: Splunk AWS cloud data inputs
- High-value finding fields include account, finding ID, generator/product ARNs, resource collection, severity, record/workflow state, title, description, and timestamps.

### Azure Activity Logs
- Splunk sourcetype: `azure:monitor:activity`
- Integration: Splunk Microsoft Azure / Data Inputs
- High-value fields include `category`, `operationName`, `resourceId`, `callerIpAddress`, `identity`, `resultType`, `resultSignature`, `tenantId`, and `time`.

### Cisco ASA
- Splunk sourcetype: `cisco:asa`
- Integration: Splunk Add-on for Cisco ASA
- Splunk documents this sourcetype as ASA/FTD syslog and maps it into CIM-compatible security/network models.
- ASA message IDs remain part of the raw contract; normalized network fields are produced through the add-on and must not be confused with literal raw syslog tokens.

## Held for further research

The following remain generator-blocked until the exact ingestion path and resulting Splunk sourcetype are verified together with the vendor event schema: Microsoft Defender for Endpoint, GCP Audit Logs, Google Workspace, AWS VPC Flow Logs, Linux auditd, Cisco IOS, vulnerability scanners, Kubernetes audit, GitHub audit, and Salesforce Event Monitoring.

## Lab rule

When a TA or Splunk cloud data input performs parsing or CIM normalization, the lab should ingest realistic vendor-native raw records and allow the supported integration to create extracted/normalized fields whenever practical. We should not inject CIM-normalized fields into raw synthetic records solely to make detections pass.
