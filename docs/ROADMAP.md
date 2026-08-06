# Development Roadmap

## Phase 0 — Foundation

- Product requirements
- Technical architecture
- Repository and branching standards
- Open Detection Definition schema
- Knowledge Pack manifest and layout
- KV Store collection design
- Development and test standards
- Initial GitHub issue backlog

## Phase 1 — Core telemetry engine

- Bounded index and sourcetype discovery
- Sampling strategy
- Field-population profiler
- Event and value profiler
- Telemetry classification
- Cached assessment records
- Platform capability detection

## Phase 2 — Recommendation engine

- Knowledge Pack loader
- Schema validation
- Requirement matching
- Explainable readiness scoring
- Missing-field and missing-event reporting
- Supported, partial, and unsupported classifications

## Phase 3 — Initial knowledge packs

- Windows Security
- Sysmon and endpoint process telemetry
- Linux authentication and process activity
- Network and firewall
- AWS
- Azure and Entra ID
- Google Cloud
- Kubernetes
- Enterprise AI usage and AI infrastructure

## Phase 4 — Detection builder and validation

- SPL template renderer
- Field mapping resolution
- Historical test execution
- Runtime and result-volume measurement
- Entity distribution analysis
- Exportable detection package

## Phase 5 — User experience

- Overview dashboard
- Data Profiler
- Recommendation list
- Detection detail
- Validation Lab
- ATT&CK coverage
- Administration and pack management

## Phase 6 — Enterprise Security enhancements

- ES capability detection
- Existing detection inventory
- Correlation and finding-based content analysis
- Risk-based alerting mapping
- Data model readiness
- Duplicate and overlap detection
- Detection utilization and tuning analysis

## Phase 7 — Continuous detection intelligence

- Scheduled telemetry reassessment
- Newly supported detection notifications
- Telemetry degradation alerts
- Pack update impact analysis
- Detection lifecycle tracking

## Release strategy

- `0.1.x`: architecture and schemas
- `0.2.x`: telemetry profiling prototype
- `0.3.x`: recommendation engine prototype
- `0.4.x`: initial detection packs and SPL generation
- `0.5.x`: validation and user workflows
- `0.9.x`: release candidate and Splunk AppInspect hardening
- `1.0.0`: supported platform-first release
