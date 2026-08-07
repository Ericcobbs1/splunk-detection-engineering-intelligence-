# Technical Add-on Installation Plan

Install or enable supported add-ons only when they materially affect parsing, field extraction, or CIM normalization for the corpus.

## Required for verified corpus

- Splunk Add-on for Microsoft Windows
- Splunk Add-on for AWS / corresponding Splunk AWS cloud data inputs
- Splunk Add-on for Okta Identity Cloud
- Splunk Add-on for Microsoft Office 365
- Microsoft Azure / Splunk cloud data input integration used for `azure:monitor:aad` and `azure:monitor:activity`
- Palo Alto Networks Splunk integration
- Zscaler Technical Add-On for Splunk
- Splunk Add-on for CrowdStrike FDR or the supported Splunk Data Inputs CrowdStrike ingestion path
- Splunk Add-on for Cisco ASA

## Conditional

- Suricata TA/community integration: optional when ingesting EVE JSON directly because the vendor JSON schema is self-describing; use a supported TA if CIM normalization is required for a detection path.

## Installation principle

The synthetic corpus should resemble vendor-native events before TA parsing. If an add-on normally performs extractions, aliases, tags, or CIM normalization, install the add-on and validate those results in Splunk rather than embedding the normalized values into the raw event solely for DEI readiness.

Pending source families will be added to this plan only after their exact supported ingestion path is verified.
