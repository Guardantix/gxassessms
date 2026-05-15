# Pipeline Lifecycle

The pipeline executes six stages -- COLLECT, PARSE, NORMALIZE, CONSOLIDATE,
QA_REVIEW, RENDER -- against a single engagement. Each stage is a pure
function in [`pipeline/stages.py`](../src/gxassessms/pipeline/stages.py); the
`Orchestrator` in [`pipeline/orchestrator.py`](../src/gxassessms/pipeline/orchestrator.py)
calls them through `_runner.run_stages()` and persists results between calls.

This document covers four flows:

1. Plugin discovery and entry-point registration
2. End-to-end orchestrator run
3. Tool-adapter invocation lifecycle inside `COLLECT` and `PARSE`
4. Consolidation pipeline data flow

For state-machine details and resume rules see
[architecture.md](architecture.md#pipeline-lifecycle).

---

## 1. Plugin Discovery and Entry-Point Registration

All extension types follow the same shape: an entry-point group, a generic
discovery pass via [`registry.discover_entry_points()`](../src/gxassessms/registry.py),
and a type-specific validation pass that excludes invalid entries with a
logged warning rather than crashing. The adapter registry adds cross-adapter
constraint checks (duplicate slug / tool_source detection, slug format).

```mermaid
sequenceDiagram
    autonumber
    participant CLI as cli/_helpers
    participant Reg as adapters/__init__<br/>discover_adapters
    participant Disc as registry<br/>discover_entry_points
    participant IM as importlib.metadata
    participant EP as Adapter class<br/>(entry point)

    CLI->>Reg: discover_adapters()
    Reg->>Disc: discover_entry_points("gxassessms.adapters")
    Disc->>IM: entry_points(group=...)
    IM-->>Disc: iterable of EntryPoint
    loop per entry point
        Disc->>EP: ep.load()
        alt load succeeds
            EP-->>Disc: adapter class
            Disc-->>Disc: plugins[name] = class
        else ImportError or AttributeError
            EP-->>Disc: exception
            Disc-->>Disc: errors.append(DiscoveryError)
        end
    end
    Disc-->>Reg: DiscoveryResult(plugins, errors)

    loop per loaded class
        Reg->>Reg: _validate_adapter(name, cls)
        Note over Reg: REQUIRED_ATTRIBUTES present?<br/>cls() instantiates?<br/>tool_name non-empty?<br/>If "ingest" cap: ingest_from_directory<br/>+ default_schema_version present?
        alt valid
            Reg-->>Reg: adapters[name] = cls
        else invalid
            Reg-->>Reg: validation_errors.append(...)
        end
    end
    Reg->>Reg: _validate_registry_constraints(adapters)
    Note over Reg: storage_slug format,<br/>uniqueness,<br/>tool_source uniqueness
    Reg-->>CLI: AdapterRegistry(adapters, validation_errors)
```

Renderers follow the same pattern via
[`reporting/renderer_registry.py:RendererRegistry.discover()`](../src/gxassessms/reporting/renderer_registry.py).
Renderer instantiation also performs dependency-chain validation:
`NodeRenderer.__init__` checks that `render.js` exists and that Node.js is
on the PATH, raising `RendererDependencyError` if either is missing
([`renderer_registry.py:159-169`](../src/gxassessms/reporting/renderer_registry.py)).

QA strategies, policies, consolidation rules, and credential providers are
discovered the same way through `discover_entry_points()` with their
respective group names (see [architecture.md](architecture.md#extension-points)).

---

## 2. Orchestrator Run Lifecycle

`Orchestrator.run()` and `Orchestrator.run_from()` both delegate to
`_runner.run_stages()`, which walks the stage list starting at a given
stage. Between every stage the runner persists outputs through the
appropriate repository and emits a `state_transition` event to the journal.

```mermaid
sequenceDiagram
    autonumber
    participant CLI as cli/commands/run
    participant Orch as Orchestrator
    participant Lock as EngagementLock
    participant Runner as _runner.run_stages
    participant Stage as pipeline.stages
    participant Repo as Repos<br/>(Engagement, Finding,<br/>Coverage, Event)
    participant Art as ArtifactManager
    participant Plugin as Adapters /<br/>Policies / QA /<br/>Renderers

    CLI->>Orch: run(engagement_id, config,<br/>adapters, policies,<br/>qa_strategy, renderers)
    Orch->>Runner: run_stages(start_stage=COLLECT)
    Runner->>Repo: get(engagement_id) — current state
    Repo-->>Runner: state
    Note over Runner: detect_stale_running()<br/>or transition CREATED → COLLECTING

    loop per stage in stage_order
        Runner->>Lock: hold(engagement_id)
        activate Lock

        Runner->>Repo: emit "state_transition" (X → X_ING)
        Runner->>Stage: stage_fn(ctx, plugins)
        Stage->>Plugin: invoke (parallel for collect)
        Plugin-->>Stage: results / observations / findings / etc.
        Stage-->>Runner: stage output

        alt COLLECT
            Runner->>Art: save_raw_outputs()
            Runner->>Repo: emit state_transition (COLLECTING → COLLECTED)
        else PARSE
            Runner->>Art: confine_and_resolve()
            Runner->>Repo: save coverage records
            Runner->>Repo: emit state_transition (PARSING → PARSED)
        else NORMALIZE
            Runner->>Repo: save_parsed(findings)
            Runner->>Repo: emit state_transition (NORMALIZING → NORMALIZED)
        else CONSOLIDATE
            Runner->>Repo: save_consolidated(findings)
            Runner->>Repo: emit state_transition (CONSOLIDATING → CONSOLIDATED)
        else QA_REVIEW
            opt strategy.is_noop
                Runner->>Repo: auto-advance (QA_REVIEW → QA_APPROVED)
            end
        else RENDER
            Runner->>Plugin: renderer.render(payload, output_dir)
            Plugin-->>Runner: written path
            Runner->>Repo: emit state_transition (RENDERING → COMPLETE)
        end

        Lock-->>Runner: release
        deactivate Lock

        opt stop_stage reached
            Runner-->>Orch: return early
        end
    end

    Orch-->>CLI: return
```

Key invariants:

- **Lock scope.** Each stage acquires the lock for its duration; the lock is
  released between stages so a separate process can inspect engagement state.
  ([`_runner.py`](../src/gxassessms/pipeline/_runner.py))
- **Partial collection.** Failed adapters produce a `CollectionResult` with
  status `FAILED`, `TIMEOUT`, or `SKIPPED`; downstream stages skip them and
  log a warning. ([`stages.parse()`](../src/gxassessms/pipeline/stages.py:161-207))
- **Approval freshness for RENDER.** Before entering RENDER, the orchestrator
  walks the journal: if any upstream stage (`COLLECT`, `PARSE`, `NORMALIZE`,
  `CONSOLIDATE`) was re-run after the most recent `QA_APPROVED` event, it
  raises `PipelineError`.
  ([`orchestrator._verify_qa_for_render`](../src/gxassessms/pipeline/orchestrator.py:372-415))
- **Resume.** `determine_resume_stage()` maps the current state to the next
  stage to run. `PARSED -> PARSE` (not `NORMALIZE`) because observations
  aren't persisted; replay re-parses from manifests.
  ([`orchestrator.py:465-514`](../src/gxassessms/pipeline/orchestrator.py))

---

## 3. Tool-Adapter Invocation Lifecycle

Each adapter goes through a fixed sequence inside `COLLECT` and `PARSE`. The
orchestrator never calls adapter methods out of order.

```mermaid
sequenceDiagram
    autonumber
    participant Run as stages.collect
    participant Pool as ThreadPoolExecutor
    participant Ad as ToolAdapter
    participant CP as CredentialProvider
    participant FS as Filesystem<br/>(raw output)

    Run->>Pool: submit(_run_adapter) per adapter

    par per adapter (concurrent)
        Pool->>Ad: check_prerequisites()
        Note over Ad: validates module<br/>provenance / version
        Ad-->>Pool: PrerequisiteResult

        opt prerequisites satisfied
            Pool->>Ad: authenticate(config)
            opt adapter resolves credentials
                Ad->>CP: get_credential(key)
                CP-->>Ad: secret value (SecretStr)
            end
            Ad-->>Pool: AuthContext | None

            Pool->>Ad: collect(config, auth)
            Ad->>FS: write tool output<br/>(PowerShell / API / CLI)
            Ad-->>Pool: CollectionOutput<br/>(artifacts, schema_version)
        end
    end

    Pool-->>Run: list[CollectionResult]<br/>(SUCCESS / FAILED / TIMEOUT / SKIPPED)

    Note over Run: stages.parse() phase begins
    loop per SUCCESS result
        Run->>Ad: validate_raw(manifest)
        alt validation passes
            Ad-->>Run: ok
            Run->>Ad: parse(manifest)
            Ad-->>Run: list[ToolObservation]
            opt "coverage_export" in adapter.capabilities
                Run->>Ad: coverage(manifest)
                Ad-->>Run: list[CoverageRecord]
            end
        else validation fails
            Ad--XRun: RawOutputValidationError
            Note over Run: stage fails fast,<br/>journal records FAILED
        end
    end
```

`CollectionOutput` carries platform-native absolute paths. Before the parse
stage runs, `confine_and_resolve()` rewrites those paths into
`ResolvedManifest` instances whose `file_manifest` entries are absolute paths
proven to live inside the engagement directory. Manifests that fail
confinement raise `ManifestConfinementError`.

### Optional: Operator Ingest

An adapter that declares `"ingest"` in its capability set and implements the
`IngestCapableAdapter` Protocol can also be fed pre-collected output via
`mseco ingest`:

```mermaid
sequenceDiagram
    autonumber
    participant CLI as cli/commands/ingest
    participant Orch as Orchestrator
    participant Ad as IngestCapableAdapter
    participant Art as ArtifactManager
    participant Journal as EventRepo

    CLI->>Ad: ingest_from_directory(source_dir,<br/>schema_version, timestamp)
    Ad-->>CLI: CollectionOutput
    CLI->>Art: save_raw_outputs([CollectionResult])
    CLI->>Orch: record_raw_output_ingested(<br/>engagement_id, tool_slug,<br/>source_path, replaced)
    Orch->>Journal: append "raw_output_ingested" event
```

After ingest, the operator runs `mseco replay <engagement_id>` to re-enter
the pipeline at PARSE.

---

## 4. Consolidation Pipeline Data Flow

CONSOLIDATE deduplicates findings across tools. The default implementation
splits the work between a tool-agnostic union-find dedup engine and a
policy-driven merge step.

```mermaid
flowchart TB
    start([list&lt;Finding&gt; from NORMALIZE]) --> empty{empty?}
    empty -- yes --> done([list&lt;ConsolidatedFinding&gt;])
    empty -- no --> rule[DefaultConsolidationRule.consolidate]

    rule --> dedup[UnionFindDedup.group]
    dedup --> ds[_DisjointSet<br/>indexed by Finding position]
    ds --> key_index[build key → indices map<br/>filter empty/whitespace keys]
    key_index --> union[union all indices<br/>sharing a key]
    union --> warn{key shared by<br/>&gt;50 findings?}
    warn -- yes --> log_warn[log WARNING<br/>possible adapter<br/>misconfiguration]
    warn -- no --> collect
    log_warn --> collect[collect groups by<br/>disjoint-set root]
    collect --> groups([list&lt;list&lt;Finding&gt;&gt;])

    groups --> canon[select canonical finding_key<br/>per group]
    canon --> tie{single<br/>unique key?}
    tie -- yes --> use[use that key]
    tie -- no --> pick[pick highest severity,<br/>tiebreak lex max]

    use --> merge
    pick --> merge[ConsolidationPolicy.merge_group]

    merge --> severity[reconcile severity<br/>across sources]
    merge --> status[reconcile status]
    merge --> conf[compute ConfidenceScore]
    merge --> sources[build SourceEvidence list<br/>from each Finding]

    severity --> cf[ConsolidatedFinding]
    status --> cf
    conf --> cf
    sources --> cf

    cf --> done
```

Highlights:

- **Union-find with iterative path compression.** No recursion -- safe for
  deep dedup chains.
  ([`dedup.py:38-47`](../src/gxassessms/consolidation/dedup.py))
- **Whitespace filtering.** Empty or whitespace-only dedup keys are
  filtered out before grouping. A finding with no valid key remaining gets
  its own isolated group and a WARNING log line.
- **Cardinality warning.** If a single key joins more than 50 findings, the
  engine logs a warning -- usually a sign that an adapter is using too
  generic a `finding_key` rule.
- **Canonical key selection.** Within a group, the policy picks one
  `finding_key` to represent the merged finding. The default rule prefers
  the key from the highest-severity contributor and breaks ties
  lexicographically for determinism.
  ([`rules.py:93-119`](../src/gxassessms/consolidation/rules.py))

The dedup engine has no knowledge of `ConsolidationPolicy`; the policy has
no knowledge of how groups are formed. The bridge sits only in
`DefaultConsolidationRule`. Either piece can be replaced via the
`gxassessms.consolidation_rules` and `gxassessms.policies` entry-point groups.

## See also

- [extension-points.md](extension-points.md) -- full Protocol method
  signatures
- [data-model.md](data-model.md) -- ER diagram for the persisted state
- [configuration.md](configuration.md) -- engagement YAML reference
- [runbook.md](runbook.md) -- partial-failure triage and resume scenarios
