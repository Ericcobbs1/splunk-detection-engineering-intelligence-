# Schema-Authentic Generator Policy

1. Generate only source profiles whose registry status is `verified`.
2. Every verified profile must have at least one authoritative vendor or Splunk source.
3. Preserve vendor-native raw event structure and documented value domains.
4. Keep raw vendor fields separate from TA/CIM-normalized fields.
5. Where a supported Splunk add-on performs parsing, aliases, tags, or CIM normalization, prefer installing that add-on in the lab and validating its output.
6. Do not invent a raw field solely because DEI or a detection expects a normalized field.
7. Malicious scenarios must remain schema-valid examples of real operations/events for that source system.
8. Profiles marked `pending_research` must be rejected by generator tooling.
9. Field provenance must remain auditable from generated event family back to the registry authority.
10. Before increasing corpus volume, validate representative records in Splunk with `fieldsummary` and compare them to the documented schema.
