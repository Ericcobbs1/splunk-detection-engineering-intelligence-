# SIEM Telemetry Mega-Batch Plan

## Objective

Accelerate the post-baseline DEI corpus build by researching and promoting major SIEM telemetry families in parallel rather than opening small source-by-source pull requests.

## Operating rules

- Research 15-20 source families in parallel.
- Promote a profile only when the native event schema and the intended Splunk ingestion/sourcetype path are both authoritative.
- Prefer, in order: vendor schema + Splunk-supported add-on, vendor schema + vendor-supported TA, then vendor schema + documented raw ingestion path.
- Keep vendor-native fields separate from search-time TA/CIM aliases.
- Do not make a source generator-ready based only on synthetic lab observations.
- Ambiguous sources remain blocked without holding up the rest of the batch.
- Build the high-volume generator immediately after this mega-batch rather than waiting for every possible integration.

## Mega-batch targets

1. Microsoft Defender for Endpoint / Defender XDR
2. Google Cloud Audit Logs
3. AWS VPC Flow Logs
4. Linux auditd
5. Cisco IOS syslog
6. Tenable vulnerability telemetry
7. Qualys vulnerability telemetry
8. Kubernetes audit logs
9. GitHub organization audit logs
10. Google Workspace audit telemetry
11. Salesforce Event Monitoring
12. Palo Alto Threat logs
13. Palo Alto URL logs
14. DNS telemetry beyond current stream:dns coverage
15. DHCP telemetry
16. VPN / remote-access telemetry
17. Email-security telemetry
18. Endpoint malware/AV telemetry beyond current EDR coverage

## Authoritative findings already established in the mega-batch

### Microsoft Defender for Endpoint

Microsoft Defender XDR Advanced Hunting documents native process and network telemetry through DeviceProcessEvents and DeviceNetworkEvents. Representative native fields include Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, and ReportId. The exact Splunk sourcetype and add-on path must still be locked before generator promotion.

### AWS VPC Flow Logs

AWS documents the native flow-record schema including version, account-id, interface-id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, and log-status. The intended Splunk Add-on for AWS ingestion/sourcetype path must be confirmed before generator promotion.

### GitHub organization audit logs

GitHub documents native audit-event fields including @timestamp, action, actor, actor_id, org, org_id, repo/repository identifiers, user, user_agent, created_at, operation_type, request_id, and event-specific fields. The intended Splunk add-on/sourcetype path must be confirmed before generator promotion.

### Cisco IOS

Cisco documents IOS syslog wire format as sequence/timestamp followed by `%facility-severity-MNEMONIC:description`. We will generate native IOS syslog messages only after the exact Splunk TA sourcetype and extraction path are verified.

## Execution sequence

1. Complete authoritative research for all mega-batch targets in parallel.
2. Promote every source with sufficient vendor + Splunk evidence in one PR.
3. Leave unresolved profiles blocked, without delaying verified profiles.
4. Install the required supported/vendor TAs in the lab.
5. Build one schema-driven corpus generator that reads only verified profiles.
6. Generate a multi-source corpus at production-style volume and index layout.
7. Validate sourcetypes, field extraction, event counts, and CIM/TA-derived aliases in Splunk.
8. Expand the detection opportunity catalog against the verified corpus.
