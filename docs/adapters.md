# Adapter Guide

Adapters connect `mseco` to individual security and compliance tools. Each
adapter knows how to run a tool, read its output, and map findings to the
unified schema.

**Key points:**

- Adapters are discovered automatically at startup via entry points. Run
  `mseco adapters list` to see what's available.
- Adapters run in parallel. If one fails, the others continue.
- You enable adapters in your [config file](configuration.md) under the
  `tools` section.

## ScubaGear

**What it assesses:** Microsoft 365 security configuration against the CISA
SCuBA (Secure Cloud Business Applications) baseline. Covers Entra ID,
Exchange Online, SharePoint, Teams, Defender, and Power Platform.

**Type:** PowerShell module.

**Requirements:**
- PowerShell 7+
- ScubaGear module v1.5.0 -- v1.x (install with `Install-Module -Name ScubaGear`)
- API permissions: `Directory.Read.All`, `Policy.Read.All` (Microsoft Graph)

**Config options:**

```yaml
tools:
  scubagear:
    enabled: true
    modules: ["AAD", "Defender", "EXO", "PowerPlatform", "SharePoint", "Teams"]
    timeout: 1800    # default: 1800 (30 minutes)
```

The `modules` field controls which M365 products to assess. Valid values:
`AAD`, `Defender`, `EXO`, `PowerPlatform`, `SharePoint`, `Teams`. Omit the
field to assess all of them.

**Notes:** ScubaGear is the slowest adapter -- large tenants with thousands of
users can take 15-30 minutes. Start with a subset of modules for initial testing.

## Maester

**What it assesses:** Entra ID and Microsoft 365 security configuration using
the Maester test framework. Tests cover conditional access policies, MFA
configuration, privileged identity management, and more.

**Type:** PowerShell module.

**Requirements:**
- PowerShell 7+
- Maester module v1.0.0 -- v1.x (install with `Install-Module -Name Maester`)
- API permissions: `Directory.Read.All`, `Policy.Read.All` (Microsoft Graph)

**Config options:**

```yaml
tools:
  maester:
    enabled: true
    timeout: 600
```

**Notes:** Maester overlaps with ScubaGear on Entra ID checks. Running both
gives broader coverage -- the consolidation engine deduplicates shared findings.

## Monkey365

**What it assesses:** Azure, Microsoft 365, and Entra ID compliance. Covers
storage accounts, networking, identity, and M365 service configuration.

**Type:** PowerShell module.

**Requirements:**
- PowerShell 7+
- monkey365 module v1.0.0 -- v1.x (install with `Install-Module -Name monkey365`)
- API permissions: `Directory.Read.All` (Microsoft Graph), Reader role on Azure subscription

**Config options:**

```yaml
tools:
  monkey365:
    enabled: true
    timeout: 900
```

**Notes:** Monkey365 is the primary adapter for Azure infrastructure checks.
If your client has Azure resources beyond M365, enable this one.

## Prowler

**What it assesses:** Multi-cloud security posture with strong Azure coverage.
Checks against CIS benchmarks, security best practices, and compliance
frameworks.

**Type:** Python CLI tool.

**Requirements:**
- Prowler installed (`pip install prowler` -- requires Python 3.10-3.12)
- API permissions: Reader role on Azure subscription

**Config options:**

```yaml
tools:
  prowler:
    enabled: true
    timeout: 1200
```

**Notes:** Prowler runs as a separate Python process. It has its own Python
version requirements (3.10-3.12) which may differ from GxAssessMS.

## Secure Score

**What it assesses:** Microsoft Secure Score -- Microsoft's own security posture
rating for your M365 tenant. Provides a score and improvement actions.

**Type:** API-based (Microsoft Graph). No PowerShell required.

**Requirements:**
- API permissions: `SecurityEvents.Read.All` (Microsoft Graph)

**Config options:**

```yaml
tools:
  securescore: true    # shorthand is usually enough
```

**Notes:** Lightweight -- runs in seconds. The findings come with Microsoft's own
severity ratings, which are mapped to the unified schema.

## Azure Advisor

**What it assesses:** Azure Advisor recommendations covering security,
reliability, performance, cost, and operational excellence.

**Type:** API-based (Azure Management API). No PowerShell required.

**Requirements:**
- `subscription_id` set in the `client` section of your config
- Reader role on the Azure subscription

**Config options:**

```yaml
tools:
  azureadvisor: true
```

**Notes:** Requires `client.subscription_id` in your config. Findings use
Azure Advisor's own impact ratings.

## M365 Assess

**What it assesses:** Custom Microsoft 365 assessment framework with coverage
mapping to CIS benchmarks.

**Type:** PowerShell modules.

**Requirements:**
- PowerShell 7+
- `Microsoft.Graph.Authentication` and `ExchangeOnlineManagement` modules

**Config options:**

```yaml
tools:
  m365_assess:
    enabled: true
    script_dir: "/path/to/M365-Assess"     # directory containing Invoke-M365Assessment.ps1
    output_dir: "/path/to/m365-output"     # where raw output is written
```

Both `script_dir` and `output_dir` are required for this adapter. `script_dir`
must point to the directory containing `Invoke-M365Assessment.ps1`.

## Choosing Which Adapters to Run

Start simple and add tools as needed:

| Scenario | Recommended Adapters |
|----------|---------------------|
| M365 only (first assessment) | ScubaGear + Maester |
| M365 + Azure infrastructure | ScubaGear + Maester + Monkey365 |
| Comprehensive (all available data) | ScubaGear + Maester + Monkey365 + Secure Score + Azure Advisor |
| Quick posture check | Secure Score (runs in seconds) |

You can always add more adapters later and re-run. The pipeline preserves
previous results.

## How Findings Overlap

Multiple tools often flag the same issue. For example, both ScubaGear and
Maester check whether MFA is enforced for administrators. The consolidation
engine detects these overlaps and merges them into a single finding, keeping
the most detailed information from each source.

You don't need to worry about double-counting. The report shows deduplicated
findings with source attribution so you can see which tools contributed.
