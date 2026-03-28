# Cross-Reference Mappings

This directory contains cross-tool dedup key mappings. Each YAML file maps
a shared namespace (e.g., CIS M365 benchmark controls) to tool-native check
IDs across all supported assessment tools.

## Purpose

When multiple tools assess the same security control (e.g., "MFA is enabled
for admin accounts"), each tool uses its own check ID. These mappings provide
the shared truth so the consolidation engine can deduplicate findings across
tools.

## File Format

```yaml
cis:m365:{control_id}:
  scubagear: "MS.{MODULE}.{check}"
  maester: "MT.{id}"
  monkey365: "m365.{module}.{check}"
  m365_assess: "{control_id}"
  semantic: "{human-readable description}"
```

- **Key**: The shared dedup key used by the consolidation engine.
- **Tool entries**: Tool-native check ID that maps to this control.
- **`semantic`**: Human-readable description for AI QA and reports. Not used
  for dedup or lookup -- purely descriptive.

## How Adapters Use These

Each adapter's `mappings.py` contains a `DEDUP_KEY_RULES` dict that maps
its native check IDs to the shared namespace. These rules should be
consistent with the cross-reference YAMLs here.

When adding a new check mapping:
1. Add the entry here first (this is the source of truth).
2. Update the adapter's `DEDUP_KEY_RULES` to match.
3. Run the mapping coverage tests to verify consistency.

## Adding a New Tool

When adding a new adapter:
1. Add a new key (e.g., `new_tool: "NT.{id}"`) to each existing entry.
2. Create the adapter's `mappings.py` with matching `DEDUP_KEY_RULES`.
3. Run conformance tests to verify the adapter's mappings cover its fixtures.

## Files

- `cis-m365-crossref.yaml` -- CIS Microsoft 365 benchmark controls
