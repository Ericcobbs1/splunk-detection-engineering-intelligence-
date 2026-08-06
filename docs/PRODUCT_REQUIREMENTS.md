# Product Requirements Document

## Product

Splunk Detection Engineering Intelligence (DEI)

## Positioning

DEI is a platform-first, Enterprise Security-enhanced Splunk application. It analyzes representative subsets of indexed telemetry and recommends detection use cases that are technically supported by the observed data.

## Problem

Security teams frequently ingest large volumes of telemetry without a reliable way to determine:

- Which security detections the data can support
- Which required fields and event types are missing
- Whether detections are ready for implementation
- Which ATT&CK techniques are covered or unsupported
- Whether existing Enterprise Security content duplicates a proposed use case
- How cloud and AI telemetry can be converted into actionable detections

## Users

- Detection engineers
- SOC analysts
- Security architects
- Splunk administrators
- Content developers
- Detection program leaders

## Core workflow

1. Select an index, sourcetype, dataset, or constrained search.
2. Analyze a controlled sample of events.
3. Profile fields, event types, quality, volume, and normalization.
4. Classify the telemetry domain and platform.
5. Match the profile against detection knowledge packs.
6. Rank supported use cases by readiness and confidence.
7. Generate platform-specific SPL and validation guidance.
8. Test the proposed detection against historical data.
9. Export or promote content through an analyst-controlled workflow.

## Version 1 goals

- Operate without Splunk Enterprise Security.
- Support Splunk Enterprise and Splunk Cloud Platform.
- Profile telemetry without requiring a full-index scan.
- Recommend detections based on observed data, not only sourcetype labels.
- Support traditional infrastructure, cloud, and AI detection categories.
- Calculate explainable readiness and confidence scores.
- Generate reviewable SPL from versioned templates.
- Provide historical validation and estimated result volume.
- Detect Enterprise Security and enable optional enhancements.

## Version 1 non-goals

- Automatic deployment of detections to production
- Automated response or SOAR execution
- Autonomous tuning
- Replacement of Enterprise Security
- Inspection or storage of unredacted prompt content by default
- Claims that probabilistic AI-security indicators confirm malicious activity

## Core capability areas

### Data intelligence

- Index and sourcetype discovery
- Controlled event sampling
- Field-population profiling
- Common and rare value analysis
- Event-code and action discovery
- Timestamp and host coverage checks
- CIM-readiness analysis
- Data-quality scoring

### Detection intelligence

- Detection catalog
- Required telemetry definitions
- Required and optional fields
- Event prerequisites
- MITRE ATT&CK mappings
- False-positive guidance
- Validation instructions
- SPL templates and mappings

### Recommendations

- Fully supported
- Supported with tuning
- Supported after normalization
- Partially supported
- Requires additional telemetry
- Unsupported

### Detection domains

- Windows and Active Directory
- Endpoint and process activity
- Linux and Unix
- Network and firewall
- Identity and authentication
- Cloud control plane and data access
- Containers and Kubernetes
- AI usage, infrastructure, data protection, and governance

### Enterprise Security enhancements

When ES is available, DEI may additionally analyze:

- Correlation searches
- Finding-based detections
- Risk rules and risk modifiers
- Notable and finding activity
- Data model acceleration and field coverage
- Existing content overlap
- Detection health, utilization, and tuning opportunities

## Success measures

- Percentage of recommendations with explainable evidence
- Percentage of generated searches that execute successfully in supported test data
- Time required to profile a constrained dataset
- Reduction in manual telemetry-to-use-case analysis
- Accuracy of required-field and required-event matching
- Number of useful detections identified without ES
- Additional value surfaced when ES is installed

## Product principles

1. Runs everywhere; enhanced by ES.
2. Recommendations must be evidence based.
3. Missing prerequisites must be explicit.
4. Analysts remain in control.
5. Knowledge packs are versioned and testable.
6. Sensitive content is minimized and redacted by default.
7. Performance safeguards are part of the product, not an afterthought.
