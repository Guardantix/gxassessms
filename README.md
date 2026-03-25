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

## Status

Early development.
