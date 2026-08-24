# DEI end-to-end hardening audit

Audit target: app version 0.1.140, build 147  
Audit date: 2026-08-24  
Status: **Not ready for library expansion**

## Evidence collected

- 297/297 local tests pass, plus Python compilation, JavaScript syntax, XML parsing, and duplicate-ID checks.
- Static review covered all views, JavaScript controllers, REST handlers, KV persistence, lifecycle transitions, tutorial state, scan engine, packaging, responsive CSS, and accessibility names.
- Splunk MCP verified Splunk 10.0.5, KV Store ready, DEI collection state, page traffic, and `_internal` runtime errors.
- Live browser automation is still blocked because only the MCP tunnel is available; the browser requires a public HTTPS Splunk Web URL.
- The existing test suite is contract/source based and does not use Playwright, Selenium, WebDriver, jsdom, or axe. Its passing result is not evidence that every UI control works.

## Release-blocking defects

| ID | Severity | Defect | Required acceptance test |
|---|---|---|---|
| H-01 | Critical | Lifecycle governance is enforced mainly in JavaScript. The storage API accepts arbitrary lifecycle states, records, and history. | Invalid schemas and illegal transitions receive 4xx responses in direct REST tests. |
| H-02 | Critical | Lifecycle/audit history is replaceable through unrestricted upsert and therefore is not immutable. | Existing audit events cannot be edited or deleted; corrections append new events. |
| H-03 | Critical | No optimistic concurrency exists; simultaneous tabs/users can silently overwrite one another. | Stale-version writes return 409 and preserve the newer record. |
| H-04 | Critical | Actor and audit timestamps are client supplied rather than server stamped. | Server derives authenticated actor and timestamp and ignores spoofed values. |
| H-05 | Critical | KV upsert has a check-then-write race. MCP captured two storage HTTP 500s where `contains()` succeeded but update returned KV HTTP 404 for a scan-history key. | Concurrent scan persistence has no 500s; atomic create/update behavior is tested. |
| H-06 | Critical | Browser persistence fallback can report successful saves/deletes even though shared KV persistence failed. | UI identifies non-durable state, does not report shared success, and offers retry/reconciliation. |
| H-07 | High | Validation persists up to 25 raw result rows in lifecycle KV records, risking credentials, secrets, PII, and excessive record size. | Only allowlisted/redacted evidence metadata is persisted; sensitive-field tests pass. |
| H-08 | High | Scan history has no retention policy and is already about 5.9 MB for 50 records. | Configurable retention/size limits prune safely and preserve required audit summaries. |
| H-09 | High | REST storage accepts unbounded payloads and collections use `enforceTypes=false`. | Oversized, deeply nested, and malformed requests receive controlled 4xx responses. |

## Workflow and tutorial defects

| ID | Severity | Defect | Required acceptance test |
|---|---|---|---|
| W-01 | High | A repeat tutorial can dead-end when the scan contains no unused Recommendation-stage detection. | Tutorial can use/reset a safe training record or clearly recover without modifying production work. |
| W-02 | High | Scan `complete_with_warning` does not advance the tutorial because the listener accepts only `complete`. | Durable-warning scan advances with a visible persistence warning. |
| W-03 | High | Missing tutorial targets repeatedly show “updating” without a deterministic recovery action. | Every missing target yields retry, return, or restart; no indefinite loop. |
| W-04 | High | Back enters review mode but does not reverse prior actions; the behavior is not made explicit enough. | Every step has Back; completed mutations are never replayed and review-only behavior is announced. |
| W-05 | High | Home loads workspace layout v12 while resume/recent-activity/preferences are implemented in v14. | Home and all workflow pages load one current controller version and share state consistently. |
| W-06 | High | v14 `restartOnboarding()` returns when `DEINextGuide` exists, making its subsequent `start()` branch unreachable. | Restart reliably opens step 1 from every page and app state. |
| W-07 | High | Restart availability is inconsistent between lifecycle states and surfaces. | Draft, Testing, Peer Review, and completed tutorial restart behavior matches one specification. |
| W-08 | High | Post-scan direction is split between Insights, Coverage, and Builder, with no single authoritative next action. | Scan completion shows one primary next action and preserves selected detection/context. |
| W-09 | High | Detection work remains fragmented across pages, causing context loss and navigation jitter. | Core build/validate/review/deploy/monitor actions remain in one workspace with stable URL/state. |
| W-10 | Medium | Textarea tutorial progression depends on `change`/blur rather than current input, making prompts appear stalled. | Input-driven steps advance predictably with keyboard and pointer use. |
| W-11 | Medium | Filter restoration runs twice in v14 and triggers duplicate change events/writes. | One restoration pass, one render, and one preference write occur per page load. |

## Lifecycle, persistence, and semantic defects

| ID | Severity | Defect | Required acceptance test |
|---|---|---|---|
| P-01 | High | Browser fallback state is not reconciled after KV recovers. | Recovery presents a conflict-aware merge/retry workflow. |
| P-02 | High | Failed KV delete resolves success after deleting only the local fallback copy. | Durable delete failure remains failed and leaves server/local state explicitly described. |
| P-03 | High | Scan history uses upsert even though the UI calls it immutable history. | History is create-only; duplicate IDs are rejected or idempotently verified. |
| P-04 | High | Scan summary/history persistence is only best-effort transactional and rollback can split state. | Fault-injection tests prove consistent committed state or an explicit repairable transaction record. |
| P-05 | High | Separation of duties is guidance only; reviewer can equal submitter. | Server rejects self-review where independent review is required. |
| P-06 | High | Catalog “Disable/Re-enable” changes only the DEI record but wording implies the Splunk saved search/detection is changed. | Either perform and verify the Splunk action or label it strictly as DEI catalog status. |
| P-07 | Medium | Freshness is computed with the browser clock rather than Splunk/server time. | Clock-skew tests produce server-consistent freshness. |
| P-08 | Medium | Field gaps are inferred from a 200-event route sample but can read like confirmed absence. | UI labels them “not observed in sample” and exposes sample size/time. |
| P-09 | Medium | Fixed per-route and total profiling timeouts hide the exact failing route/root cause. | Results distinguish permission, timeout, no data, cancellation, and search failure per route. |

## Runtime, security, and health defects

| ID | Severity | Defect | Required acceptance test |
|---|---|---|---|
| R-01 | High | The DEI health endpoint only proves the library loads; it does not check KV, search, storage, REST dependencies, or writeability. | Health response reports each dependency independently and fails readiness when a required dependency fails. |
| R-02 | High | Action Center accepts an unrestricted `return` query parameter and assigns it to an href. | Only same-app allowlisted routes are accepted; malicious/external schemes fall back safely. |
| R-03 | Medium | Splunk overall health is red while DEI may display “API healthy,” creating a misleading readiness signal. | UI distinguishes DEI component readiness from overall Splunk health. |
| R-04 | Medium | MCP shows 59 repeated 404s for missing `static/appLogo.png`. | App logo exists at the requested path and new page loads create zero 404s. |
| R-05 | Medium | Current package includes six unreferenced legacy assets and multiple obsolete image/CSS generations. | Package contains only referenced runtime assets; fresh install and upgrade both pass. |

## UI, accessibility, and responsive defects

| ID | Severity | Defect | Required acceptance test |
|---|---|---|---|
| U-01 | High | Unnamed controls exist in Command Center, Catalog, Health, MITRE Coverage, and MITRE Heatmap. | Automated accessibility scan finds every input/select/textarea has an accessible name. |
| U-02 | High | Builder tabs do not implement a complete tablist/tab/tabpanel keyboard and ARIA model. | Arrow/Home/End navigation, selection, focus, and panel relationships pass keyboard tests. |
| U-03 | Medium | Home uses clickable `<article role="link">` cards instead of semantic anchors. | Cards are real links with correct focus, context menu, and open-in-new-tab behavior. |
| U-04 | High | Health load failures can be swallowed by fallback and status messages overwritten by unconditional render. | Network/KV failure remains visible, actionable, and announced; empty data is distinct from error. |
| U-05 | Medium | Dynamic catalog actions inconsistently expose busy/disabled state and persistence announcements. | Double-submit is impossible and screen readers receive pending/success/failure state. |
| U-06 | Medium | Help advertises v14 resume features that Home v12 does not provide. | Help and deployed behavior are version-aligned. |
| U-07 | High | Mobile layouts are incomplete for navigation, lifecycle tables, tutorial popover, filter groups, and fixed notifications. | Full workflow passes at 320, 375, 768, 1024, and desktop widths without hidden actions or horizontal page overflow. |
| U-08 | High | Tutorial can occupy most of a mobile viewport and scroll its target away, destabilizing target visibility/focus. | Popover and target remain usable under zoom, mobile viewport, and virtual keyboard. |
| U-09 | Medium | Compact status text has readability/contrast risk. | WCAG contrast and 200% zoom checks pass. |
| U-10 | Medium | Filter restoration, scroll positioning, and tutorial positioning can race during initialization. | Deterministic browser tests show one stable position with no layout jump. |

## Packaging findings

The package script correctly excludes `__pycache__`, `*.pyc`, and macOS metadata and validates gzip/top-level layout. It does not run Splunk AppInspect, schema/security checks, or reject unreferenced assets. Confirmed unreferenced static files:

- `dei_design_system_v1.css`
- `persistent_environment.js`
- `mitre_workspace.js`
- `dei_home_globe_v5.css`
- `dei_home_globe_v6.css`
- `command_center.css`

## Required release gate

1. Fix all Critical and High items, then Medium items that affect correctness/accessibility.
2. Add real browser E2E coverage for every page, button, form, state transition, Back/Restart path, failure path, and responsive breakpoint.
3. Add direct REST negative, authorization, concurrency, size-limit, and fault-injection tests.
4. Run AppInspect and package-content checks on the final `.spl`.
5. Install the final package on a clean Splunk instance and an upgrade instance.
6. Run the complete tutorial from start to finish and backward at every step.
7. Verify with Splunk MCP that new DEI page/API activity has zero unexpected 4xx/5xx and zero DEI PersistentScript errors.
8. Only then mark the engine hardened and begin library expansion.
