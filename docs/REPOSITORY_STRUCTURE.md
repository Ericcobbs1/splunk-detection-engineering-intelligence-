# Repository Structure

```text
.
├── README.md
├── docs/
│   ├── PRODUCT_REQUIREMENTS.md
│   ├── TECHNICAL_ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── REPOSITORY_STRUCTURE.md
│   ├── KNOWLEDGE_PACK_SPECIFICATION.md
│   ├── KV_STORE_SCHEMA.md
│   └── DEVELOPMENT_STANDARDS.md
├── schemas/
│   ├── open-detection-definition.schema.json
│   └── knowledge-pack-manifest.schema.json
├── app/
│   └── splunk_detection_engineering_intelligence/
│       ├── default/
│       ├── metadata/
│       ├── appserver/
│       ├── bin/
│       ├── lookups/
│       └── static/
├── knowledge-packs/
│   ├── windows/
│   ├── endpoint/
│   ├── network/
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   ├── kubernetes/
│   └── ai/
├── integrations/
│   └── splunk-es/
├── tests/
│   ├── schemas/
│   ├── unit/
│   ├── fixtures/
│   └── appinspect/
├── tools/
└── .github/
    ├── workflows/
    └── ISSUE_TEMPLATE/
```

## Boundaries

- `app/` contains deployable Splunk application assets.
- `knowledge-packs/` contains declarative detection knowledge and templates.
- `integrations/` contains optional product-specific adapters.
- `schemas/` contains machine-enforced contracts.
- `tests/` contains fixtures and automated validation.
- `docs/` contains product and engineering decisions.

The core Splunk app must remain functional when all optional integrations are absent.
