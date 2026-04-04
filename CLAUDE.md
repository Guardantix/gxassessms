# CLAUDE.md -- GxAssessMS

## Project

**GxAssessMS** -- Microsoft Ecosystem Assessment Orchestrator. Chains ScubaGear, Maester, Monkey365, and other security/compliance tools; consolidates findings into a unified schema; produces branded Guardantix deliverables.

## Owner

Rick Passero (rick@guardantix.com) -- GitHub org: `Guardantix`

## Architecture

This is the **public half** of an open-core system. Defines Protocol-based extension points for adapters, renderers, QA strategies, and policies. The private package (`gxassessms-guardantix`) registers Guardantix-specific implementations via entry points.

**Critical rule:** `gxassessms-guardantix` depends on this package. This package never imports from `gxassessms-guardantix`.

Design spec: `../gxassessms-guardantix/docs/specs/2026-03-25-gxassessms-architecture-design.md`

## Tech Stack

- Python >=3.14, Pydantic, Click, Rich, httpx
- Node.js for report renderers (guardantix-docx-kit, guardantix-pptx-kit)
- SQLite (WAL mode) + filesystem for persistence

## Conventions

- Follow workspace-wide standards from `/home/guardantix/Claude/CLAUDE.md`
- Security-first: this tool handles client tenant data -- treat all assessment output as confidential
- No hardcoded credentials or tenant identifiers in source
- All datetime operations via centralized `core/config/datetime_utils.py`
- All domain constants via `core/domain/constants.py` (Literal + frozenset pattern)
- Fail-closed error handling: typed exceptions, narrow catches, no silent fallbacks
- <=400 lines per file target
- Module provenance policy lives in `adapters/<tool>/policy.py` -- changes are security-critical and require careful PR review
- PowerShell templates in `adapters/_verification_scripts/` are static; all dynamic data flows through JSON input (no string substitution)
- Config `module_policy_override` can narrow policy (exact version pin, hash subset) but never widen it

## Workspace

Both GxAssessMS packages live in `~/Claude/gxassessms-workspace/`:
- `GxAssessMS/` -- this repo
- `gxassessms-guardantix/` -- private Guardantix extension (sibling directory)

## Related Repos

- `guardantix-docx-kit` -- .docx deliverable generation
- `guardantix-pptx-kit` -- .pptx deliverable generation
- `GxDocs` -- canonical business documentation (service catalog, methodology)
