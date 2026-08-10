# DEI SPL Query Standards

DEI detection searches follow these Splunk platform rules:

1. Start with search terms or an approved generating command. `search` retrieves events when it is first in the pipeline; commands such as `tstats`, `from`, `inputlookup`, and `makeresults` use their documented leading-pipe form.
2. Put indexed constraints and the narrowest practical time window first. Prefer explicit indexes, sourcetypes, hosts, and sources over `index=*`.
3. Place one executable command between every pair of pipe delimiters. Pipes inside quoted values are data, not command boundaries.
4. Keep quoted strings and quoted field identifiers balanced. Escape embedded backslashes and double quotes when generating literals.
5. Use `search` for field-to-value filtering and `where` for field-to-field or evaluated comparisons.
6. Use `eval` to normalize fields before transforming commands. Separate multiple assignments with commas and preserve left-to-right dependencies.
7. Prefer `stats`, `eventstats`, or `streamstats` over `transaction` and review `join`, unlimited `sort`, and high-cardinality grouping for cost and truncation risk.
8. Preserve investigation context after transformation: time, primary entity, detection description, and MITRE ATT&CK identifiers.
9. Bound validation searches by earliest/latest time, timeout, and result limit. A successful bounded validation is evidence, not permission to deploy.

## Automatic correction policy

DEI may automatically correct a failed validation only when the change is deterministic and does not alter detection intent:

- replace the exact command-position typo `rshell` with `search`;
- add `search` when the query begins with a field-filter expression and has no generating command;
- remove an empty pipeline stage while preserving both adjacent commands; or
- narrow the validation window after a safety timeout.

Each automatic correction preserves the original failure in validation history, updates the editor, identifies exactly what changed, and requires validation to run again. DEI does not guess replacements for unknown commands, fields, macros, permissions, unmatched quotes, or ambiguous parser failures.

## Splunk references

- Search command: https://help.splunk.com/en?resourceId=Splunk_SearchReference_Search
- Anatomy of a search pipeline: https://help.splunk.com/en/splunk-cloud-platform/search/search-manual/10.1.2507/using-the-search-app/anatomy-of-a-search
- Write better searches: https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.2/optimizing-searches/write-better-searches
- Eval command: https://help.splunk.com/en?resourceId=Splunk_SearchReference_Eval
- Where command: https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.4/search-commands/where
- Tstats command: https://help.splunk.com/en?resourceId=SplunkCloud_SearchReference_Tstats
