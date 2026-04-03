# GxAssessMS

**Microsoft Ecosystem Assessment Orchestrator**

Chains together best-in-class security and compliance tools, consolidates findings into a unified schema, and produces branded Guardantix deliverables.

## Integrated Tools

| Tool | Scope |
|------|-------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | M365 security baseline (CISA SCuBA) |
| [Maester](https://github.com/maester365/maester) | Entra ID / M365 security testing |
| [Monkey365](https://github.com/silverhack/monkey365) | Azure / M365 / Entra ID compliance |

## Architecture

```
Client M365 Tenant
        |
   GxAssessMS Orchestrator
        |
   +----+----+----+
   |    |    |    |
ScubaGear Maester Monkey365 ...
   |    |    |    |
   +----+----+----+
        |
  Unified Finding Schema
        |
  Branded Gx Deliverables
```

## CLI

```
mseco run <config.yaml>             Run full assessment pipeline
mseco collect <config.yaml>         Run collection stage only
mseco preflight <config.yaml>       Validate config, prerequisites, auth, renderers
mseco adapters list                 Show discovered adapters
mseco adapters check                Run prerequisite checks (baseline policy)
mseco adapters scaffold <name>      Generate new adapter package from template
mseco compute-module-hash           Compute sha256tree:v1 hash for a PowerShell module
mseco engagement list|archive|...   Manage engagement lifecycle
mseco report <config.yaml>          Generate reports from existing engagement
mseco replay <config.yaml>          Re-run pipeline from persisted raw outputs
```

## Module Provenance

PowerShell modules (ScubaGear, Maester) are verified before execution:

- **Version pinning**: semver range constraints per adapter policy
- **Tree hash integrity**: `sha256tree:v1` hash of the full module directory
- **Signature verification**: Authenticode when available, hash-only fallback
- **Staging**: modules are copied to a private temp directory and verified there (eliminates TOCTOU)
- **Fail-closed**: unrecognized modules, ambiguous candidates, and confinement violations block execution

See `docs/superpowers/specs/2026-04-03-powershell-module-provenance-design.md` for the full design.

## Status

Early development.
