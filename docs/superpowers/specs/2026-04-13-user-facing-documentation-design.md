# User-Facing Documentation Design

**Date:** 2026-04-13
**Scope:** Both repos (gxassessms + gxassessms-guardantix)
**Audiences:** (a) Non-expert IT admin operators (public package), (d) Internal Guardantix developers (private package)

## Design Principles

- Target audience is an IT admin who is not a security expert. They know their M365
  tenant but may not know what ScubaGear is or how Azure app registrations work.
- Foundation-first: document what works today, structured for expansion as features
  mature through real client engagements.
- The README is the front door. Docs/ pages are the rooms. No one should have to read
  the architecture spec to run an assessment.

---

## File Layout

New user-facing docs go at the top level of `docs/`. Existing internal docs stay
where they are:

```
gxassessms/
  README.md                              # rewrite
  docs/
    installation.md                      # new
    quickstart.md                        # new
    configuration.md                     # new
    cli-reference.md                     # new
    adapters.md                          # new
    security.md                          # new (operator-facing)
    runbook.md                           # existing, unchanged
    security/                            # existing internal docs, unchanged
      gxassessms-threat-model.md
      gxassessms-security-best-practices-report.md
      shared-host-deployment.md
    superpowers/specs/                   # existing design specs, unchanged
    superpowers/plans/                   # existing plans, unchanged

gxassessms-guardantix/
  README.md                              # rewrite
  (all other docs unchanged)
```

---

## Public Package: gxassessms

### 1. README.md (complete rewrite)

Replaces the current stub. Answers "what is this, why should I care, how do I start"
in under 2 minutes.

**Structure:**

1. **Title + one-liner.** "Microsoft Ecosystem Assessment Orchestrator." Plain English:
   runs security/compliance tools against your M365 tenant and consolidates results
   into a single report.

2. **What it does.** 3-4 bullet points, no jargon:
   - Runs ScubaGear, Maester, Monkey365, and other tools for you
   - Consolidates overlapping findings and deduplicates
   - Assigns severity and remediation priority
   - Produces a single report
   - Emphasize: you don't need to know how each tool works individually

3. **Quick install.** `pip install gxassessms` (or editable install for now). Python 3.12+
   requirement noted.

4. **Minimal example.** ~15-line config YAML (client name, tenant ID, auth, one tool) +
   `mseco run config.yaml`. Show what happens, what output to expect.

5. **Documentation links.** Table pointing to each doc in `docs/`.

6. **Supported tools.** Adapter table with one-line descriptions (carried forward from
   current README).

7. **License.** MIT.

**Removes from current README:** Architecture ASCII diagram (moves to internal docs),
module provenance details (moves to docs/security.md), CLI command listing (moves to
docs/cli-reference.md).

### 2. docs/installation.md

Highest-traffic page for IT admins who've never touched Python.

**Structure:**

1. **Requirements summary.** Table: Python 3.12+, PowerShell 7+ (for PS-based adapters),
   Node.js (for report rendering). Clear about what's optional per adapter type.

2. **Python setup.** 3.12+ is widely available on all platforms. Brief
   platform-specific pointers:
   - Windows: python.org download or winget
   - Linux: system package manager or deadsnakes PPA
   - Container: base image recommendation

3. **Installing gxassessms.** `pip install gxassessms` and editable install from source.
   Virtual environment setup.

4. **PowerShell modules.** Per-module: `Install-Module` commands, version requirements.
   Note that `mseco` verifies module integrity (link to security.md).

5. **Azure app registration.** Step-by-step: create registration, grant API permissions
   (per adapter), generate secret or certificate. Exact portal navigation paths and
   az CLI equivalents. This is the highest-friction section for non-experts.

6. **Verify installation.** `mseco preflight config.yaml` as smoke test. Explain each
   check and what to do if one fails.

7. **Container deployment.** Placeholder section -- Dockerfile sketch, expand when
   battle-tested.

8. **Troubleshooting.** Common problems: wrong Python version, PowerShell execution
   policy, module not found, auth permission errors.

### 3. docs/quickstart.md

Complete tutorial: "I just installed this" to "I'm looking at my first report."

**Structure:**

1. **What you'll do.** One paragraph: configure a single-adapter assessment (ScubaGear),
   run it, look at the output. ~15 minutes, requires a working Azure app registration
   (links to installation.md).

2. **Create your config file.** Annotated minimal YAML with inline comments. Client
   name, tenant ID, auth with `client_credential`, ScubaGear enabled with a few
   modules (`aad`, `exo`).

3. **Validate before running.** `mseco preflight config.yaml`. Walk through each line
   of output, what "OK" means, what failure looks like, what to fix.

4. **Run the assessment.** `mseco run config.yaml`. Explain each stage (COLLECT, PARSE,
   NORMALIZE, CONSOLIDATE, RENDER) in plain language. Set expectations for timing
   (~5-15 minutes depending on tenant size).

5. **Understand the output.** Where the engagement directory is, what files are in it,
   how to read the report. Walk through example findings: severity, remediation
   recommendation.

6. **Next steps.** Enable more adapters, customize report options, `mseco engagement
   list`. Links to configuration.md and cli-reference.md.

Deliberately stops before QA review, analytics, or anything requiring the private
package. Self-contained "first win" with just the public package.

### 4. docs/configuration.md

Full config YAML reference. Operators come here after the quickstart.

**Structure:**

1. **Config file overview.** Five top-level sections (`client`, `auth`, `tools`, `report`,
   `pipeline`), only `client` and `auth` required. Note: strict validation rejects
   misspelled keys and wrong types immediately.

2. **`client` section.** Field table: `name` (required), `tenant_id` (required,
   must match `auth.tenant_id`), `subscription_id` (optional).

3. **`auth` section.** Four auth methods explained separately:
   - `client_credential` with secret (automated/unattended)
   - `client_credential` with certificate (higher security)
   - `device_code` (interactive, admin at keyboard)
   - `interactive` (browser-based)
   Each: when to use, required fields, example YAML. Emphasize `client_secret_env`
   is env var *name*, not the secret.

4. **`tools` section.** Shorthand (`scubagear: true`) vs expanded form. ToolConfig
   field table. Per-adapter subsections with valid `modules`, recommended timeouts,
   useful `extra_args`. Link to adapters.md.

5. **`report` section.** Formats, themes, logo. Note which are built-in vs extension.

6. **`pipeline` section.** `max_parallel`, `qa_model`, `qa_token_budget`. Trade-off
   guidance.

7. **Module provenance overrides.** Clarify this is a per-tool nested field within
   the `tools` section, not a top-level config section. What `module_policy_override`
   does (exact version/hash pin). Link to security.md. Framed as advanced.

8. **Complete example.** Full annotated YAML showing all sections. Copy-paste starting
   point.

9. **Validation errors.** Table of every error/warning from `mseco preflight`, cause,
   and fix.

### 5. docs/cli-reference.md

Scannable reference. No prose paragraphs -- syntax, examples, notes.

**Structure:**

1. **Global options.** `--log-level`, `--log-format`, `-v/--verbose`. When to use JSON
   vs Rich logging.

2. **One subsection per command**, ordered by frequency of use:
   - `mseco run` -- full pipeline
   - `mseco preflight` -- validation
   - `mseco collect` -- collection only
   - `mseco report` -- regenerate from existing data
   - `mseco replay` -- re-run from raw outputs
   - `mseco consolidate` -- re-consolidate with different policy
   - `mseco review` -- QA review workflow
   - `mseco engagement create|list|status|archive|restore|purge|export` -- lifecycle
   - `mseco adapters list|check|scaffold` -- discovery
   - `mseco ingest` -- import external output
   - `mseco compute-module-hash` -- advanced/security
   - `mseco analytics` -- tracking and trends (extension point)

   Each subsection: what it does (one sentence), syntax + options, example
   invocation, expected output/exit codes/common errors.

3. **Common workflows.** Short recipes:
   - Full assessment: `preflight` then `run`
   - Re-generate report: `report`
   - Resume after failure: `replay`
   - Check installation: `adapters list` + `adapters check`

### 6. docs/adapters.md

Per-adapter reference for operators choosing which tools to enable.

**Structure:**

1. **Overview.** What adapters are, how they're discovered, that failures in one don't
   block others.

2. **One subsection per adapter**, ordered by likely use:
   - **ScubaGear** -- CISA SCuBA M365 baseline
   - **Maester** -- Entra ID / M365 security testing
   - **Monkey365** -- Azure / M365 / Entra ID compliance
   - **Prowler** -- multi-cloud security (Azure focus)
   - **Secure Score** -- Microsoft's built-in scoring (API-based)
   - **Azure Advisor** -- Azure recommendations (API-based)
   - **M365 Assess** -- custom M365 assessment framework

   Each: what it assesses (plain language), requirements (module/API permissions),
   config options (valid `modules`, recommended timeout, useful `extra_args`),
   coverage (which services, which frameworks), known quirks.

3. **Choosing which adapters to run.** Decision guidance:
   - M365 only: ScubaGear + Maester
   - Add Azure: + Monkey365
   - Lightweight extras: Secure Score + Azure Advisor
   - Simple decision matrix, not "figure it out yourself"

4. **How findings overlap.** Brief: multiple tools may flag the same issue,
   consolidation engine deduplicates. Operator doesn't need to worry.

### 7. docs/security.md

Operator-facing trust model. Not the internal threat model.

**Structure:**

1. **Security philosophy.** Fail-closed. If something looks wrong, the pipeline stops.
   A security assessment tool that silently swallows errors is worse than useless.

2. **Module provenance.** Plain-language explanation:
   - Version checked against adapter's pinned range
   - Module copied to private temp dir (nothing can change it mid-run)
   - Tree hash computed and compared to known-good hashes
   - Authenticode signature verified when available
   - Any check failure blocks that adapter entirely
   Framed as supply-chain protection.

3. **Data handling.** Where data lives (engagement dir, SQLite DB), permissions set
   (0o700 dirs, 0o600 files), nothing phones home.

4. **Config security.** Secrets by env var name only. Strict validation prevents
   injection via malformed values.

5. **Operator checklist.** Keep modules updated, use certificate auth for production,
   rotate secrets, review output before sharing, clean up with
   `mseco engagement purge`.

---

## Private Package: gxassessms-guardantix

### README.md (rewrite as internal onboarding guide)

**Structure:**

1. **What this is.** One paragraph: proprietary extension. AI QA, branded reports,
   review UI, analytics, longitudinal tracking. Discovered via entry points.

2. **Relationship to gxassessms.** Dependency rule, how entry points work, which
   Protocols this package implements. 30-second understanding of the boundary.

3. **Development setup.** Step-by-step:
   - Clone both repos into workspace
   - Run `scripts/setup-venv.sh`
   - Verify: `pytest` and `mseco adapters list`
   - Note: Anthropic API key needed for QA layer development

4. **Package layout.** Five modules (qa, reporting, review_ui, analytics, longitudinal)
   with one sentence each. Not an architecture repeat -- just where to look.

5. **Key documentation.** Table: architecture spec, code conventions, build log,
   roadmap, CHANGELOG. With guidance on when to read each.

6. **Testing.** How to run (`pytest`), test layers (unit, integration, contracts,
   conventions), coverage expectations.

7. **Entry points.** Table: QA strategy, renderers (docx, pptx), analytics, review UI.
   Makes "extends via entry points" concrete.

---

## Out of Scope (deferred)

- Contributor guide / CONTRIBUTING.md (audience b/c)
- Adapter authoring guide (audience b)
- API/extension documentation (audience b)
- Deployment deep dives (container, CI) beyond placeholder sections
