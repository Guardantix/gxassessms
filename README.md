# GxAssessMS

**Microsoft Ecosystem Assessment Orchestrator**

GxAssessMS runs security and compliance tools against your Microsoft 365 and Azure
tenants, consolidates the results into a unified set of findings, and produces a
single assessment report. You don't need to learn how each tool works individually --
configure what you want assessed and let `mseco` handle the rest.

## What It Does

- **Runs multiple tools for you** -- ScubaGear, Maester, Monkey365, Prowler, Secure
  Score, Azure Advisor, and M365 Assess, all from a single config file
- **Consolidates and deduplicates** -- overlapping findings from different tools are
  merged so nothing is double-counted
- **Assigns severity and priority** -- each finding gets a severity rating and
  remediation timeline
- **Produces a report** -- generates a .docx deliverable summarizing findings,
  severity breakdown, and recommended remediation roadmap

## Quick Start

**Requirements:** Python 3.12+. See [Installation Guide](docs/installation.md) for
full setup including PowerShell modules and Azure configuration.

```bash
pip install gxassessms
```

Create a config file (`assessment.yaml`):

```yaml
client:
  name: "Contoso"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

auth:
  method: "client_credential"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_id: "11111111-2222-3333-4444-555555555555"
  client_secret_env: "AZURE_CLIENT_SECRET"  # pragma: allowlist secret

tools:
  scubagear:
    enabled: true
    output_dir: "./output/scubagear"
    modules: ["AAD", "EXO", "SharePoint", "Teams"]
```

Run the assessment:

```bash
mseco preflight assessment.yaml   # validate config and prerequisites
mseco run assessment.yaml          # run the full pipeline
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Python, PowerShell modules, Azure app registration, verification |
| [Quick Start Tutorial](docs/quickstart.md) | Your first assessment, step by step |
| [Configuration Reference](docs/configuration.md) | Every config field explained |
| [CLI Reference](docs/cli-reference.md) | All `mseco` commands with examples |
| [Adapter Guide](docs/adapters.md) | What each tool assesses and how to configure it |
| [Security Model](docs/security.md) | Module provenance, data handling, trust model |

## Supported Tools

| Tool | What It Assesses | Type |
|------|-----------------|------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | M365 security baseline (CISA SCuBA) | PowerShell module |
| [Maester](https://github.com/maester365/maester) | Entra ID / M365 security testing | PowerShell module |
| [Monkey365](https://github.com/silverhack/monkey365) | Azure / M365 / Entra ID compliance | PowerShell module |
| [Prowler](https://github.com/prowler-cloud/prowler) | Multi-cloud security (Azure focus) | Python CLI |
| Secure Score | Microsoft Secure Score | Graph API |
| Azure Advisor | Azure optimization recommendations | Management API |
| M365 Assess | Custom M365 assessment framework | PowerShell modules |

## License

[MIT](LICENSE)
