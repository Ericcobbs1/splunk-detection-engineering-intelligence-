# Pre-Library Expansion Hardening Acceptance

Library expansion is blocked until every automated and installed-runtime gate below passes.

## Automated release gates

- Full Python and packaged-asset regression suite
- JavaScript syntax for every shipped static asset
- Python bytecode compilation for every runtime module
- Simple XML parsing for every shipped view
- Detection catalog integrity, field provenance, SPL safety, and idempotency
- REST handler authentication, namespace isolation, and runtime compatibility
- Durable scan, lifecycle, and per-user preference persistence
- Tutorial state transitions, Back review navigation, Show me, close, resume, and completion
- Installable `.spl` archive structure with no Python cache artifacts
- CI lint, type checking, clean React rebuild, unit tests, and package validation

## Installed Splunk end-to-end gates

- Upgrade installation and Splunk restart complete without DEI initialization errors
- Home, Discovery, Insights, Builder, Action Center, Catalog, MITRE, Health, and Help load
- Discovery works for every window with internal indexes disabled and enabled
- Enterprise Security disabled and enabled paths remain accurate
- Actionable recommendations remain separate from unsupported library opportunities
- Draft generation and bounded validation work with accurate route and field evidence
- Draft, Testing, Peer review, Production, Monitoring, Tuning, revalidation, redeployment, and return-to-draft transitions persist
- Tutorial Back enters read-only review mode and Next returns to the current checkpoint
- Show me targets the correct enabled control; collapse, move, close, restart, and resume work
- Saved filters, selected detection, scan history, lifecycle state, and recovery data survive reload and restart
- Repeated saves do not produce KV Store duplicate-key errors
- Cross-page tutorial navigation does not produce duplicate HTTP requests or zero-byte responses
- A final MCP query reports no new DEI runtime errors after the test window

Record screenshots and reproduction steps for every failure. Hardening is complete only when the installed-runtime gates and CI are both green.
