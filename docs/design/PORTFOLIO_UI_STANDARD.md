# Portfolio UI Standard

## Purpose

This document defines the UI/UX standard for the Splunk application portfolio. Every new application should feel native to Splunk while remaining visually recognizable as part of the same product family.

The standard is based on Splunk's supported UI stack:

- Splunk UI Toolkit (SUIT) for React single-page applications and reusable components.
- `@splunk/react-ui` for application controls and interaction components.
- `@splunk/themes` for Splunk design tokens and theme behavior.
- `@splunk/react-icons` for iconography.
- Unified Dashboard Framework (UDF) when a coded dashboard is the right surface.
- Splunk visualizations for charts and analytic graphics.

Reference documentation:

- https://dev.splunk.com/enterprise/docs/developapps/createapps/buildapps/
- https://dev.splunk.com/enterprise/docs/developapps/createapps/buildapps/adduicomponent
- https://splunkui.splunk.com/

## Product principles

### Native first

Use Splunk UI components, tokens, interaction patterns, and accessibility behavior before introducing custom equivalents. Custom UI should extend Splunk rather than imitate or replace it.

### Premium, not decorative

Visual polish must improve hierarchy, clarity, confidence, and workflow speed. Avoid ornamental gradients, excessive glow, novelty controls, or bespoke interaction patterns that make an app feel disconnected from Splunk.

### Shared portfolio language

All applications use the same semantic states, spacing rules, page hierarchy, empty states, loading states, and severity/readiness language. Product-specific branding may change the accent and hero treatment but not interaction behavior.

### Progressive disclosure

The landing page answers: What is healthy? What requires attention? What should I do next? Detailed evidence, field mappings, search context, and configuration belong in drilldowns, drawers, or dedicated pages.

### Explainability by default

Security recommendations must expose why a result exists, what evidence supports it, what is missing, and the next action. Scores without context are not sufficient.

## App information architecture

Each premium app should use a consistent hierarchy where applicable:

1. Command Center / Overview
2. Primary workflow pages
3. Coverage / Health
4. Investigation or analysis views
5. Administration / Settings

Top-level navigation should remain shallow. Use sub-navigation or in-page tabs for closely related workflows rather than expanding the Splunk app bar excessively.

## Page shell

Every page should use the same conceptual shell:

- Product/page title and concise purpose.
- Context or health badge when useful.
- Primary action in a predictable location.
- Optional filter/context bar.
- Executive summary or KPI layer.
- Main workflow content.
- Details/drilldown layer.

Do not begin pages with raw tables or large configuration forms unless the task itself is configuration.

## Shared component families

The portfolio should standardize these reusable patterns:

### AppShell

Owns page width, navigation context, background, theme, and global page spacing.

### PageHeader

Contains eyebrow/product context, title, description, health/status, and optional primary action.

### MetricCard

Displays a single operational KPI with label, value, trend/status, and optional drilldown. Metrics must have a defined operational meaning.

### StatusBadge

Uses semantic state rather than arbitrary color:

- success / healthy / production-ready
- info / informational
- warning / partial / unverified
- error / field-gap / failed
- neutral / unsupported / unavailable

### SeverityBadge

Standard severity vocabulary: critical, high, medium, low, informational.

### DetectionCard

Required content:

- detection name
- severity
- readiness
- score or priority only when explainable
- capability/domain
- reason/recommendation summary
- evidence state
- MITRE techniques when present
- next action/drilldown

### CoveragePanel

Shows overall readiness plus domain breakdown. It must distinguish source understanding, field validation, and detection readiness rather than collapsing them into one ambiguous percentage.

### DataSourceCard

Shows vendor/source identity, index/sourcetype context, parsing/TA state, CIM status when applicable, field readiness, and recent activity.

### HealthBanner

For dependency, API, TA, CIM, or platform conditions that materially affect the workflow. Avoid persistent banners for low-value informational text.

### EmptyState

Must explain why the surface is empty and provide a meaningful next action. Never use only "No data."

### ErrorState

Must distinguish configuration, permissions, unavailable telemetry, API failure, and timeout where possible.

### LoadingState

Use progressive text or structured skeleton states for multi-step analysis. The UI should identify the current phase when work takes more than a moment.

### EvidenceDrawer

Use for source/field evidence, SPL context, mappings, and technical details that support a recommendation without crowding the primary card.

## Semantic design tokens

Applications should consume Splunk theme tokens where possible. Portfolio-specific tokens may alias Splunk tokens but must not hard-code a competing independent theme system.

Required semantic aliases:

- `surface.canvas`
- `surface.panel`
- `surface.raised`
- `border.subtle`
- `text.primary`
- `text.secondary`
- `text.muted`
- `status.success`
- `status.info`
- `status.warning`
- `status.error`
- `severity.critical`
- `severity.high`
- `severity.medium`
- `severity.low`
- `focus.visible`

The shared alias layer exists so applications can change Splunk theme versions without rewriting every component.

## Typography

Use the typography supplied by the Splunk design system. Avoid shipping custom fonts.

Hierarchy should normally be:

- page title
- section heading
- card title
- body text
- metadata/supporting text

Do not use uppercase for body text. Eyebrows and compact status labels may use uppercase sparingly.

## Spacing and density

Use a small shared spacing scale rather than arbitrary per-component values. Components should support a standard and compact density where operational tables require it.

Avoid dashboard layouts where every panel has the same visual weight. Primary workflow surfaces should be visually dominant.

## Color

Color conveys state, not decoration. Never rely on color alone; pair color with text, iconography, or shape.

Product accents are allowed for branding and emphasis, but readiness/severity colors remain consistent across the portfolio.

## Tables

Tables are for comparison and scanning, not as a default home page.

Required behavior for substantial tables:

- sortable columns where meaningful
- sticky or clear headers for long lists
- readable empty/error states
- filters outside the table when they affect the whole dataset
- row drilldown rather than excessive inline actions
- compact density option for analyst-heavy views

## Forms and settings

Use Splunk UI form controls. Group settings by task, include helper text only when needed, and validate close to the field.

Destructive or consequential actions require explicit visual distinction and confirmation appropriate to risk.

## Accessibility

Portfolio apps must preserve keyboard navigation, visible focus, semantic labels, readable contrast, and non-color state indicators provided by Splunk UI components.

Custom components are responsible for matching the accessibility behavior of the Splunk components they extend.

## Dashboard guidance

Use UDF or Splunk visualizations when the primary task is analytic visualization. Use a SUIT single-page app when the primary task is a workflow that combines analysis, state, controls, evidence, and navigation.

Do not rebuild a standard chart in custom SVG/CSS when an appropriate Splunk visualization exists.

## Implementation rules

1. Prefer SUIT components over custom controls.
2. Prefer Splunk theme tokens over hard-coded colors and spacing.
3. Prefer Splunk icons over custom icon sets.
4. Keep backend contracts independent of the frontend framework.
5. Build reusable portfolio components before app-specific clones.
6. Add visual regression or structural tests for critical shared surfaces.
7. Preserve Splunk Cloud packaging/AppInspect compatibility.
8. Increment app version/build when static assets change for release packaging.
9. Do not claim CIM support when only native vendor fields are available.
10. Do not use visual polish to obscure incomplete telemetry or uncertain readiness.

## Review gate for new UI work

A UI PR is not portfolio-ready unless reviewers can answer yes to all of the following:

- Does it use Splunk-native components/patterns where available?
- Does it follow the shared semantic states?
- Is the hierarchy obvious within a few seconds?
- Are error, empty, and loading states designed?
- Are security scores and recommendations explainable?
- Does it work without relying on color alone?
- Is app-specific CSS limited to genuine product differentiation?
- Could the component be reused by another portfolio app?
- Does it preserve Splunk Cloud/AppInspect constraints?
- Does the result look intentional beside a Splunk premium app rather than merely themed to resemble one?
