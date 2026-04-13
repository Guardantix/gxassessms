# CLI Reference

All commands are run as `mseco <command>`. Use `--help` on any command for
built-in documentation.

## Global Options

These options are available on every command:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--version` | | | Show version and exit |
| `--log-level` | `debug`, `info`, `warning`, `error` | `warning` | Set logging verbosity |
| `--log-format` | `rich`, `json` | `rich` | `rich` for human-readable, `json` for log aggregation |
| `-v` / `--verbose` | | | Shortcut for `--log-level debug` |

## mseco run

Run the full assessment pipeline (COLLECT through RENDER).

```
mseco run [OPTIONS] CONFIG_PATH
```

| Option | Description |
|--------|-------------|
| `--engagement-id TEXT` | Resume or re-run an existing engagement instead of creating a new one |
| `--dry-run` | Validate config and report execution plan without running tools |
| `--force-stage STAGE` | Invalidate a specific stage and re-run from there (requires `--engagement-id`). Values: `collect`, `parse`, `consolidate`, `qa_review`, `render` |
| `--rerun` | Re-run all stages regardless of state (requires `--engagement-id`) |
| `--qa-strategy TEXT` | Override QA strategy selection |

**Examples:**

```bash
# New assessment
mseco run assessment.yaml

# Dry run (validate only)
mseco run --dry-run assessment.yaml

# Re-run from consolidation
mseco run --engagement-id abc123 --force-stage consolidate assessment.yaml
```

## mseco preflight

Validate config, prerequisites, auth, and renderer dependencies.

```
mseco preflight [OPTIONS] CONFIG_PATH
```

No additional options. Run this before every assessment.

**Example:**

```bash
mseco preflight assessment.yaml
```

## mseco collect

Run assessment tools only (no parsing, consolidation, or reporting).

```
mseco collect [OPTIONS] CONFIG_PATH
```

| Option | Description |
|--------|-------------|
| `--engagement-id TEXT` | Target an existing engagement |

**Example:**

```bash
mseco collect assessment.yaml
```

## mseco report

Generate report deliverables from existing consolidated findings. The
engagement must be in QA_APPROVED state.

```
mseco report [OPTIONS] CONFIG_PATH
```

| Option | Description |
|--------|-------------|
| `--engagement-id TEXT` | **(Required)** Engagement to render |

**Example:**

```bash
mseco report --engagement-id abc123 assessment.yaml
```

## mseco replay

Re-run the pipeline from persisted raw output without re-executing tools.

```
mseco replay [OPTIONS] ENGAGEMENT_ID
```

| Option | Description |
|--------|-------------|
| `--from STAGE` | Stage to replay from: `parse`, `consolidate`, `qa`, `report`. Default: `parse` |
| `--qa-strategy TEXT` | Override QA strategy selection |

**Examples:**

```bash
# Re-run from parse stage
mseco replay abc123

# Re-run only from consolidation
mseco replay --from consolidate abc123
```

## mseco consolidate

Re-run normalization and deduplication from persisted data.

```
mseco consolidate [OPTIONS] CONFIG_PATH
```

| Option | Description |
|--------|-------------|
| `--engagement-id TEXT` | **(Required)** Engagement to consolidate |
| `--reparse` | Start from raw output (re-parse + re-normalize + re-consolidate) |
| `--qa-strategy TEXT` | Override QA strategy selection |

**Example:**

```bash
mseco consolidate --engagement-id abc123 assessment.yaml
mseco consolidate --engagement-id abc123 --reparse assessment.yaml
```

## mseco review

Launch the browser-based interface for reviewing an engagement. Requires an
extension package with a review implementation.

```
mseco review [OPTIONS] ENGAGEMENT_ID
```

## mseco engagement

Manage assessment engagements.

### mseco engagement create

```
mseco engagement create [OPTIONS] CONFIG_PATH
```

Create a new engagement record, directory structure, and config snapshot.

### mseco engagement list

```
mseco engagement list
```

List all engagements with their state and timestamps.

### mseco engagement status

```
mseco engagement status ENGAGEMENT_ID
```

Show detailed status for a specific engagement.

### mseco engagement archive

```
mseco engagement archive ENGAGEMENT_ID
```

Compress raw output to cold storage. Structured data stays in the database
for reference. Use `restore` to decompress later.

### mseco engagement restore

```
mseco engagement restore ENGAGEMENT_ID
```

Restore an archived engagement for re-analysis.

### mseco engagement export

```
mseco engagement export [OPTIONS] ENGAGEMENT_ID
```

| Option | Description |
|--------|-------------|
| `--format` | `yaml` or `json`. Default: yaml |

Export engagement metadata (ID, client, state, timestamps, tool list). Does not
include findings or client data.

### mseco engagement purge

```
mseco engagement purge --confirm ENGAGEMENT_ID
```

**Permanently delete** all data for an engagement. This is irreversible. Deletes
database records and filesystem artifacts. Writes an audit manifest before
deletion.

The `--confirm` flag is required.

## mseco adapters

Manage assessment tool adapters.

### mseco adapters list

```
mseco adapters list
```

Show all discovered adapters, their capabilities, and status.

### mseco adapters check

```
mseco adapters check
```

Run prerequisite and provenance checks for all discovered adapters.

### mseco adapters scaffold

```
mseco adapters scaffold NAME
```

Generate a new adapter package from the standard template.

## mseco ingest

Import raw tool output that was collected outside of `mseco`.

```
mseco ingest [OPTIONS] ENGAGEMENT_ID
```

| Option | Description |
|--------|-------------|
| `--tool TEXT` | **(Required)** Tool slug (e.g., `scubagear`) |
| `--from DIRECTORY` | Directory containing raw tool output |
| `--replace` | Replace existing raw output for this tool |
| `--schema-version TEXT` | Override default schema version |
| `--run-at TEXT` | ISO 8601 timestamp for when the tool was run |
| `--operator TEXT` | Override operator identity |

**Example:**

```bash
mseco ingest --tool scubagear --from ./scuba-output abc123
```

## mseco compute-module-hash

Compute the `sha256tree:v1` hash for a PowerShell module directory. Used for
populating adapter provenance policies.

```
mseco compute-module-hash --manifest-path PATH
```

| Option | Description |
|--------|-------------|
| `--manifest-path FILE` | **(Required)** Path to the module `.psd1` manifest |

## mseco analytics

Analytics and insight commands. Requires an extension package with analytics
support.

```
mseco analytics COMMAND
```

| Subcommand | Description |
|-----------|-------------|
| `cost` | Token usage and cost per engagement |
| `coverage` | Tool coverage across engagements |
| `tuning` | Tuning recommendations from engagement history |

## Common Workflows

**Full assessment (typical):**

```bash
mseco preflight assessment.yaml    # validate everything first
mseco run assessment.yaml          # run the pipeline
mseco engagement status <id>       # check the result
```

**Re-generate a report:**

```bash
mseco report --engagement-id <id> assessment.yaml
```

**Resume after a partial failure:**

```bash
mseco replay <id>                  # re-run from parse stage
mseco replay --from consolidate <id>  # re-run from consolidation only
```

**Check what's installed:**

```bash
mseco adapters list                # show discovered adapters
mseco adapters check               # run prerequisite checks
```

**Import externally-collected output:**

```bash
mseco ingest --tool scubagear --from ./client-data <id>
mseco replay <id>                  # process the imported data
```
