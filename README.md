# Splunk Detection Engineering Intelligence (DEI)

**Analyze. Detect. Validate. Improve.**

Splunk Detection Engineering Intelligence is a platform-first Splunk application that profiles available telemetry, identifies supported security use cases, calculates detection readiness, and helps analysts build and validate detections across traditional infrastructure, cloud, and AI environments.

DEI is designed to run on Splunk Enterprise and Splunk Cloud Platform without requiring Splunk Enterprise Security. When Enterprise Security is installed, DEI enables additional integrations for correlation searches, risk-based alerting, findings, notable events, data models, and detection coverage analysis.

## Product principles

- **Splunk platform first:** Core capabilities do not require Enterprise Security.
- **ES enhanced:** Enterprise Security adds deeper lifecycle and content integrations.
- **Data driven:** Recommendations are based on telemetry that is actually present.
- **Explainable:** Every recommendation identifies its evidence, missing requirements, and confidence.
- **Extensible:** Technology support is delivered through versioned knowledge packs.
- **Analyst controlled:** Initial releases recommend, generate, and test content without automatically deploying it.

## Phase 0

The initial project phase establishes the product definition and technical contracts before implementation:

- Product requirements
- Technical architecture
- Repository structure
- Open Detection Definition schema
- Knowledge Pack specification
- KV Store data model
- Development standards
- Delivery roadmap

See [`docs/`](docs/) for the design package.

## Modular detection library

Installable detection content lives under `app/knowledgepacks/<pack-id>/`. Each pack owns a
versioned `manifest.json` and one or more detection files declared by `detection_files`. At
runtime, DEI aggregates the enabled packs and rejects incompatible content, duplicate detection
IDs, undeclared capabilities, undeclared telemetry sources, invalid field requirements, and
schema violations before recommendations are served.

Detection IDs are stable upgrade contracts. New content should be added to its owning pack; the
removed monolithic catalog must not be recreated. The runtime health response reports both loaded
pack and detection counts so library migrations can be verified after installation.

## Planned capability areas

- Telemetry and field profiling
- Data-quality and CIM-readiness analysis
- Detection recommendation and readiness scoring
- SPL generation and historical validation
- MITRE ATT&CK coverage and telemetry gap analysis
- Windows, endpoint, network, identity, cloud, and AI knowledge packs
- Optional Splunk Enterprise Security integrations

## Status

Early architecture and product-definition phase. Interfaces and schemas may change until the first tagged specification release.
