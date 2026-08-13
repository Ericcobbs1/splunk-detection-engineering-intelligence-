# Splunk Review Checkpoint 0.1.0

This checkpoint is intended for hands-on product review inside Splunk before additional feature development continues.

## Build the installable package

From the repository root:

```bash
chmod +x tools/package_app.sh
./tools/package_app.sh
```

The package is written to:

```text
dist/splunk_detection_engineering_intelligence-0.1.0.spl
```

## Install in Splunk

1. Open **Apps > Manage Apps**.
2. Select **Install app from file**.
3. Upload the generated `.spl` package.
4. Choose **Upgrade app** when replacing an earlier DEI installation. Do not delete the existing app directory first: an in-place package upgrade preserves KV Store collections and shared scan/lifecycle history.
5. Restart Splunk if prompted.
6. Open **Detection Engineering Intelligence** from the Apps menu.

Always deploy the completed `.spl` archive rather than copying a partial `app/` tree. The package includes `metadata/default.meta`, REST configuration, static assets, and KV collection definitions as one validated unit.

## Review scope

Focus the first review on the product experience rather than complete detection coverage.

### Command Center

- Confirm the dark command-center page loads as the default view.
- Confirm the layout is readable at normal browser width.
- Confirm the telemetry coverage ring and metric cards are visible.
- Confirm Windows, AWS, cloud, and AI presentation feels consistent.

### Telemetry analysis

Enter one or more source types, for example:

```text
XmlWinEventLog:Security
aws:cloudtrail
ai:gateway
```

Select **Analyze environment** and confirm:

- observed source count updates;
- production-ready and partial counts update;
- detection potential changes;
- Knowledge Pack domains render;
- ranked recommendations display supporting and missing telemetry.

### Enterprise Security behavior

Run the same analysis with Enterprise Security disabled and enabled. The app must remain usable without ES, while ES-dependent recommendations should become more actionable when the option is enabled.

### REST validation

The following app endpoints should be available to authenticated users:

```text
/services/dei/v1/health
/services/dei/v1/capabilities
/services/dei/v1/telemetry/analyze
/services/dei/v1/recommendations
```

## Known checkpoint limitations

- Telemetry source types are entered manually; automatic Splunk environment discovery is the next major backend milestone.
- The catalog currently contains an initial set of Windows, AWS, cloud, and AI detection opportunities.
- Recommendation cards do not yet create saved searches or ES correlation searches.
- MITRE coverage, Detection Library, and Administration pages are not yet part of this checkpoint.
- The visual design is an original DEI interface inspired by modern security operations products; it is not a copy of Cortex XSIAM.

## Review feedback to capture

Record issues under these headings:

- installation and startup;
- page loading or JavaScript errors;
- visual hierarchy and readability;
- source-type input behavior;
- recommendation accuracy;
- ES and non-ES behavior;
- desired next detections;
- desired next visualizations.

This checkpoint is a suitable stopping point. Resume feature development after the Splunk review findings are documented and prioritized.
