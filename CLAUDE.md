# CLAUDE.md -- GxAssessMS

## Project

**GxAssessMS** -- Microsoft Ecosystem Assessment Orchestrator. Chains ScubaGear, Maester, Monkey365, and other security/compliance tools; consolidates findings into a unified schema; produces branded Guardantix deliverables.

## Owner

Rick Passero (rick@guardantix.com) -- GitHub org: `Guardantix`

## Tech Stack

TBD -- early project scaffolding phase.

## Conventions

- Follow workspace-wide standards from `/home/guardantix/Claude/CLAUDE.md`
- Security-first: this tool handles client tenant data -- treat all assessment output as confidential
- No hardcoded credentials or tenant identifiers in source
- Branded deliverables use guardantix-docx-kit and guardantix-pptx-kit

## Related Repos

- `guardantix-docx-kit` -- .docx deliverable generation
- `guardantix-pptx-kit` -- .pptx deliverable generation
- `GxDocs` -- canonical business documentation (service catalog, methodology)
