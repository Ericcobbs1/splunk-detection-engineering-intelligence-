# DEI telemetry corpus

The corpus is intended to replicate the data shapes that supported/vendor Splunk technology add-ons actually receive and normalize, while keeping one reusable dataset per dedicated index.

## Hard requirements

- One dataset per index.
- Use the installed TA's canonical searchable sourcetype.
- Raw payload shape must match the vendor or TA input contract; do not fabricate CIM fields into raw events.
- CIM normalization is validated at search time through the installed TA's tags, event types, aliases and calculated fields.
- Event/action-specific semantics must be preserved: fields and values that do not belong to a particular event type are forbidden.
- `ta_replication_contracts.json` is the source-of-truth readiness matrix. A dataset is merge-ready only when both `format_verified` and `semantic_verified` are true.

## Azure / Entra isolation

`entra_signin` and `azure_activity` intentionally use separate indexes so either dataset can be reused independently. Entra sign-ins use `azure:monitor:aad`; Azure Activity Logs use `azure:monitor:activity`. Entra raw records are represented as Azure Monitor AAD envelopes with sign-in-specific values under `properties`, rather than flattened Log Analytics table rows.

## Windows normalization

The installed Splunk Add-on for Microsoft Windows normalizes channel-specific `XmlWinEventLog:*` stanzas to the canonical searchable sourcetype `XmlWinEventLog`. Dataset identity is retained by the dedicated `windows_security` and `windows_powershell` indexes and by event/channel semantics.
