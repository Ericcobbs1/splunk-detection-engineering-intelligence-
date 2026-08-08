# DEI Detection Engineering Framework and Lifecycle

## Purpose

DEI reduces the manual work required to move from raw Splunk telemetry to reviewable,
validated detection content. It is platform-first and runs without Splunk Enterprise
Security. Enterprise Security adds optional correlation-search, RBA, finding, notable,
CIM, content-overlap, and deployment-package enhancements.

DEI recommendations must remain evidence based. The application must never report that
SPL, validation, review, deployment, or monitoring work is complete unless a persisted
artifact proves that lifecycle state.

## Intelligence pipeline

1. **Discover** — identify active indexes and sourcetypes within a bounded time window.
2. **Profile** — sample events and measure fields, event types, values, quality, volume,
   timestamps, hosts, and CIM readiness.
3. **Qualify** — normalize observed sourcetypes, validate prerequisites, and classify
   parser, alias, semantic, and field gaps.
4. **Recommend** — match qualified evidence to versioned detection knowledge and rank
   supported use cases with explainable readiness and confidence.
5. **Design** — create an Open Detection Definition containing purpose, telemetry,
   logic strategy, MITRE ATT&CK mapping, false-positive guidance, parameters, and tests.
6. **Generate** — render platform SPL and optional ES, Sigma, EQL, or KQL packages from
   versioned templates and resolved field mappings.
7. **Validate** — execute bounded historical tests, record runtime and result volume,
   inspect entity distributions, and preserve positive and negative test evidence.

## Managed lifecycle

Each generated detection progresses through explicit persisted states:

`draft → testing → peer_review → production → monitoring → tuning → retired`

- **Draft:** design and generated logic exist, but validation is incomplete.
- **Testing:** historical and fixture tests are executing or awaiting evidence.
- **Peer review:** logic, MITRE mapping, prerequisites, false positives, security, and
  performance have been reviewed.
- **Production:** an analyst-approved package has been deployed outside DEI's automatic
  control.
- **Monitoring:** health, execution, result volume, utilization, and telemetry
  dependencies are measured.
- **Tuning:** approved exclusions, thresholds, schedules, entities, or risk settings
  are being revised.
- **Retired:** the detection is disabled or superseded with reason and history retained.

## Required artifacts

A lifecycle record must reference:

- Open Detection Definition and version
- Observed and canonical telemetry
- Required and optional fields
- Generated SPL and template version
- MITRE ATT&CK techniques and tactics
- Validation cases and results
- Expected and measured runtime
- Expected and measured result volume
- False-positive and tuning guidance
- Reviewer, review decision, and timestamps
- Deployment target and external object identifier
- Monitoring, tuning, deprecation, and retirement history

## Metrics contract

### Metrics available from the current recommendation report

- Sourcetypes analyzed
- Canonical mappings
- Detection opportunities evaluated
- Field-verified recommendations
- Confirmed field gaps
- MITRE-mapped recommendations
- Telemetry-ready recommendations

### Metrics requiring persisted lifecycle artifacts

These remain zero or “not tracked” until the corresponding capability exists:

- Open Detection Definitions created
- SPL searches generated
- Historical validations passed
- Peer reviews completed
- Production detections deployed
- Detections monitored, tuned, deprecated, or retired

## Platform-first and ES-enhanced behavior

Core discovery, profiling, recommendation, SPL generation, validation, and lifecycle
tracking must work on Splunk Enterprise and Splunk Cloud Platform without ES.

When ES is present, DEI may additionally generate or assess:

- Correlation searches and finding-based detections
- Risk events, risk modifiers, and RBA metadata
- Notable and finding dispositions
- CIM data-model requirements and acceleration
- Existing content overlap and duplicate coverage
- Detection health, utilization, and tuning opportunities

## Safety and control

- Analysts remain responsible for review and production deployment.
- Initial releases must not automatically deploy or enable detections.
- Historical validation must use bounded searches and explicit performance safeguards.
- Sensitive fields and AI prompt content are minimized or redacted by default.
- A recommendation is not a completed detection; evidence advances lifecycle state.
