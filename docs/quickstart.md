# Quick Start Tutorial

This tutorial walks you through running your first M365 security assessment.
You'll configure a single tool (ScubaGear), run it against a tenant, and look
at the results.

**Time:** About 15 minutes (plus tool execution time).

**Prerequisites:** Python 3.12+ installed, Azure app registration created,
ScubaGear PowerShell module installed. See [Installation](installation.md) if
you haven't done these yet.

## 1. Create Your Config File

Create a file called `assessment.yaml`:

```yaml
# Client identification
client:
  name: "My Company"                              # Your organization's name
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # Your M365 tenant ID

# Azure authentication
auth:
  method: "client_credential"                     # Automated (no browser popup)
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # Must match client.tenant_id
  client_id: "11111111-2222-3333-4444-555555555555"   # From your app registration
  client_secret_env: "AZURE_CLIENT_SECRET"        # pragma: allowlist secret

# Which tools to run
tools:
  scubagear:
    enabled: true
    modules: ["AAD", "EXO"]    # Start small -- just Entra ID and Exchange
    timeout: 1200              # 20 minutes (generous for a first run)
```

Replace the tenant ID and client ID with your actual values. Make sure the
`AZURE_CLIENT_SECRET` environment variable is set.

## 2. Validate Before Running

Always run preflight first:

```bash
mseco preflight assessment.yaml
```

You should see something like:

```
                          Preflight Validation
┏━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check        ┃ Status ┃ Details                                    ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ScubaGear    │  PASS  │ ScubaGear: all packages available          │
└──────────────┴────────┴───────────────────────────────────────────┘
```

**If a check fails:**
- **"provenance verification: no_candidates"** -- ScubaGear isn't installed or the
  version doesn't match. Install or update it (see [Installation](installation.md)).
- **Config validation errors** -- check that tenant IDs match and required fields
  aren't empty. See [Configuration Reference](configuration.md) for field details.

## 3. Run the Assessment

```bash
mseco run assessment.yaml
```

The pipeline runs through these stages:

1. **COLLECT** -- runs ScubaGear against your tenant (this is the slow part --
   a few minutes depending on tenant size)
2. **PARSE** -- reads ScubaGear's raw output files
3. **NORMALIZE** -- maps findings to the unified schema (severity, category,
   remediation phase)
4. **CONSOLIDATE** -- deduplicates findings (relevant when multiple tools are
   enabled)
5. **RENDER** -- generates the assessment report

You'll see progress in the terminal. If something goes wrong, the error message
tells you which stage failed and why.

## 4. Find Your Results

After a successful run, `mseco` tells you the engagement ID. You can also list
engagements:

```bash
mseco engagement list
```

The engagement directory contains:

- **Raw tool output** -- the original files from ScubaGear
- **SQLite database** -- all findings, metadata, and pipeline events
- **Report** -- the generated .docx file

Use `mseco engagement status <engagement_id>` to see details about a specific
engagement.

## 5. Next Steps

Now that you have a working assessment:

- **Add more tools:** Enable `maester`, `securescore`, or others in your config.
  See [Adapter Guide](adapters.md) for what each tool covers and how to set it up.
- **Customize the config:** Adjust timeouts, modules, report format. See
  [Configuration Reference](configuration.md).
- **Explore the CLI:** `mseco replay` re-runs the pipeline from saved output,
  `mseco report` regenerates reports. See [CLI Reference](cli-reference.md).
