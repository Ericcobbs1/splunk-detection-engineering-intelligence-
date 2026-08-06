# Technical Architecture

## Architecture objective

DEI separates telemetry analysis, detection knowledge, recommendation logic, validation, and user experience so each can evolve independently.

## Runtime model

```text
Splunk Enterprise or Splunk Cloud Platform
│
├── DEI UI
│   ├── Overview
│   ├── Data Profiler
│   ├── Recommendations
│   ├── Detection Detail
│   ├── Validation Lab
│   └── Administration
│
├── Core Services
│   ├── Telemetry Profiler
│   ├── Classification Engine
│   ├── Detection Matcher
│   ├── Readiness Scorer
│   ├── SPL Renderer
│   ├── Validation Engine
│   ├── Knowledge Pack Loader
│   └── Integration Manager
│
├── Persistence
│   ├── KV Store collections
│   ├── CSV lookups
│   ├── JSON knowledge packs
│   └── Saved-search results and summaries
│
└── Optional Integrations
    ├── Splunk Enterprise Security
    ├── Splunk SOAR
    ├── Splunk UBA
    ├── Cribl
    └── Detection-as-code repositories
```

## Platform-first behavior

The core application must not depend on ES-specific indexes, macros, REST endpoints, data models, or permissions. ES integrations are loaded through a capability adapter only after compatibility checks succeed.

## Core services

### Telemetry Profiler

Accepts an index, sourcetype, dataset, or bounded SPL scope and produces a normalized telemetry profile. The profiler must enforce configurable time, event-count, and search-cost limits.

### Classification Engine

Classifies data into one or more domains based on observed fields, values, event identifiers, CIM mappings, vendor markers, and knowledge-pack signatures.

### Detection Matcher

Compares normalized telemetry profiles with Open Detection Definition requirements. It records satisfied, partially satisfied, missing, and transformable prerequisites.

### Readiness Scorer

Produces an explainable score composed of field availability, population, event presence, data quality, normalization, sample evidence, and expected detection specificity.

### SPL Renderer

Selects a compatible template and field mapping for the observed platform. It must generate reviewable SPL and never silently deploy content.

### Validation Engine

Runs proposed searches against bounded historical windows and records runtime, result count, entity distribution, missing fields, and projected alert volume.

### Knowledge Pack Loader

Loads versioned manifests and detection definitions. Invalid, unsigned, incompatible, or schema-noncompliant packs are rejected or quarantined.

### Integration Manager

Detects optional products and exposes feature flags. ES-specific functionality must remain isolated behind this layer.

## Storage strategy

### KV Store

Use KV Store for mutable operational state:

- assessments
- telemetry profiles
- recommendation results
- validation runs
- user projects
- review status
- exceptions and approved tuning
- installed knowledge-pack metadata
- environment capabilities

### JSON and YAML

Use repository-controlled files for immutable or versioned knowledge:

- detection definitions
- pack manifests
- field mappings
- SPL templates
- validation fixtures
- scoring defaults

### CSV lookups

Use CSV only for compact, stable tabular mappings that benefit from SPL access, such as severity normalization or small technique mappings.

## Security requirements

- Least-privilege capabilities and roles
- No unbounded index searches by default
- No execution of arbitrary pack-provided Python
- Strict schema validation for packs
- Redaction of secrets, prompt content, and regulated data
- Audit logging for assessments, exports, configuration changes, and ES writes
- Read-only ES integration by default
- Explicit authorization for any future write or deployment operation

## Performance safeguards

- Configurable maximum events sampled
- Configurable earliest-time limit
- Concurrency controls
- Cached telemetry profiles
- Summary generation for recurring analysis
- Search cancellation and timeout handling
- Template-specific cost classification
- Prefer accelerated data models or summary indexes only when available and beneficial

## UI approach

Use Splunk-native dashboards for overview and analysis pages. Use custom UI components only for workflows that cannot be delivered safely and maintainably with standard dashboard capabilities.

## Extensibility

Knowledge packs must be declarative. New vendors and telemetry types should normally require a pack rather than core code changes. Integration adapters may add code only when required to communicate with a distinct product API or Splunk capability.
