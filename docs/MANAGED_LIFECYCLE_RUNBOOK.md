# DEI Managed Lifecycle Analyst Runbook

## Access model

Lifecycle records are stored in the Splunk KV Store collection
`dei_lifecycle_records`.

- Splunk administrators can read and write records.
- Members of the `dei_lifecycle_analyst` role can read and write records.
- Other authenticated users have read-only visibility.
- A Splunk administrator must assign approved detection engineers and reviewers to
  `dei_lifecycle_analyst` after installing or upgrading the app.

The browser cache is a resilience fallback. The Lifecycle status badge identifies
whether the active source is Splunk KV Store or browser fallback.


## Using the Lifecycle Action Center

Select **Manage** beside a persisted Work Queue item. The Action Center identifies the
current gate, responsible role, required evidence, exact next steps, and the outcome of
the available decision.

1. **Testing:** the detection engineer reviews validation evidence, enters the required
   handoff note, and submits the version for peer review.
2. **Peer Review:** a DEI lifecycle reviewer inspects the Builder artifact and either
   approves it with rationale or returns it with specific changes.
3. **Approved Peer Review:** the deployment owner deploys through the organization's
   normal change process, then records the target environment and exact saved-search,
   ES detection, or external object reference.
4. **Production:** the detection owner records the initial health baseline, result
   volume, runtime, and observed analyst outcomes to begin Monitoring.
5. **Monitoring:** the owner records periodic health evidence, opens a controlled
   tuning version, or retires the detection with a reason.
6. **Tuning:** DEI archives the prior version's validation, approval, deployment, and
   monitoring evidence. The new version must be revised, validated, reviewed, and
   deployed through the same gates.
7. **Retired:** the record becomes immutable while the complete audit history remains
   available.

DEI records lifecycle decisions; it does not replace the organization's deployment,
change-management, or peer-approval process.

## End-to-end analyst workflow

### 1. Recommendation to Draft

1. Run **Analyze Environment** in Command Center.
2. Open **Lifecycle Overview**.
3. Select **Build** for a telemetry-ready, field-unverified, or field-gap candidate.
4. Review the readiness warning, MITRE mapping, observed sourcetypes, generated SPL,
   cron schedule, search window, and optional ES configuration.
5. Select **Save draft**.

Evidence persisted:

- generated SPL and schedule;
- source readiness and unresolved fields;
- MITRE ATT&CK mapping;
- optional ES correlation-search and RBA parameters;
- actor, timestamp, version, and audit event.

### 2. Draft to Testing

1. Edit the SPL or scheduling fields as required.
2. Select **Run validation**.
3. DEI executes a bounded historical search with the configured relative time window,
   a 60-second timeout, and a 25-row evidence cap.

Successful execution persists the result count, runtime, timestamp, representative
rows, and advances the record to **Testing**. Search completion is execution evidence;
it is not proof that the analytic is effective.

### 3. Testing to Peer Review

1. Open **Lifecycle Overview** and select **Manage**.
2. Verify that validation passed.
3. Enter a review-submission note describing the expected behavior and evidence.
4. Select **Submit for peer review**.

The record advances only when passed validation evidence exists.

### 4. Peer Review

The reviewer inspects the SPL, mappings, prerequisites, validation evidence, schedule,
risk/notable settings, false-positive expectations, and audit history.

- **Approve** requires a written rationale.
- **Return for changes** requires written change guidance and sends the record to Draft.

Approval does not claim deployment. The record remains in Peer Review until a
deployment reference is recorded.

### 5. Production

After deploying the approved package through the organization's normal change process:

1. Select **Manage**.
2. Choose the deployment target.
3. Enter the saved-search name, ES detection identifier, or external object ID.
4. Select **Record deployment**.

DEI records who supplied the deployment reference and when. It does not silently
enable content.

### 6. Monitoring

1. Record the detection's health, result volume, and runtime.
2. Select **Start monitoring** or **Record health**.

A record cannot enter Monitoring without timestamped health evidence.

### 7. Tuning

1. Enter the tuning rationale.
2. Select **Start tuning**.
3. DEI increments the version and clears prior validation and review evidence.
4. Open Detection Builder, revise the content, validate it, and submit it for review.

### 8. Retirement

1. Enter the retirement reason and any replacement context.
2. Select **Retire**.

The record becomes immutable in the interface while its deployment, monitoring,
version, and audit history remain available.

## Truthful metrics

Lifecycle metrics are calculated from persisted records:

- Draft, Testing, Peer Review, Production, Monitoring, Tuning, and Retired count the
  current state of each record.
- SPL Generated counts persisted detection artifacts.
- Validation Passed requires a persisted successful validation result.
- Production requires peer approval and an external deployment reference.
- Monitoring requires timestamped health evidence.

Recommendations and persisted records are joined in the Engineering Work Queue.
Therefore, saved lifecycle work remains visible even when the latest recommendation
snapshot is unavailable.
