# GxAssessMS Operational Runbook

This runbook covers the ten most common operational scenarios during
Microsoft ecosystem assessments. Each section describes the symptom,
likely cause, diagnostic steps, and resolution.

CLI commands are verified against the current `mseco` implementation. The
global `-v/--verbose` flag is available on every `mseco` subcommand.

---

## 1. Adapter Timeout Mid-Engagement

**Symptom:** Pipeline hangs during COLLECTING stage. Logs show one
adapter running past its expected duration.

**Likely cause:** ScubaGear or Maester taking longer than expected (large
tenants with thousands of users, slow Graph API responses, PowerShell
module loading delays).

**Diagnostic steps:**

1. Check engagement status:

   ```
   mseco engagement status <engagement_id>
   ```

2. Check raw log output for the stalled adapter. Look for PowerShell
   errors or Graph API throttling messages (HTTP 429).

3. Re-run with verbose logging if you need more detail:

   ```
   mseco -v run --engagement-id <engagement_id> <config.yaml>
   ```

**Resolution:**

- If the adapter is still running, wait. Some tenants legitimately take
  30+ minutes for ScubaGear.

- If the process died, resume from the stuck stage:

  ```
  mseco run <config.yaml> --engagement-id <engagement_id> --force-stage COLLECT
  ```

- Increase the per-adapter timeout in the engagement config:

  ```yaml
  tools:
    scubagear:
      enabled: true
      timeout: 3600  # seconds
  ```

- If timeouts persist, run the problematic adapter standalone, collect
  its output manually, and re-enter the pipeline from PARSE:

  ```
  mseco replay <engagement_id> --from parse
  ```

---

## 2. Corrupted SQLite Recovery

**Symptom:** `mseco engagement status` or `mseco run` fails with
`sqlite3.DatabaseError` or "database disk image is malformed."

**Likely cause:** Process killed mid-write (power failure, OOM, SIGKILL).
WAL mode mitigates most of these, but not all.

**Diagnostic steps:**

1. Check SQLite integrity:

   ```
   sqlite3 ~/.gxassessms/engagements.db "PRAGMA integrity_check;"
   ```

2. If integrity check reports errors, check for WAL/SHM files:

   ```
   ls -la ~/.gxassessms/engagements.db*
   ```

   If `.db-wal` and `.db-shm` exist, SQLite may recover on next clean open.

**Resolution:**

- **Automatic recovery:** Simply re-running `mseco engagement list` will
  attempt a clean WAL checkpoint on open. If WAL recovery succeeds, the
  DB is intact.

- **Manual recovery:** If the DB is unrecoverable:

  1. Back up the corrupted DB:

     ```
     cp ~/.gxassessms/engagements.db ~/.gxassessms/engagements.db.corrupt
     ```

  2. Create a fresh DB:

     ```
     rm ~/.gxassessms/engagements.db
     mseco engagement list   # triggers DB initialization
     ```

  3. Raw tool output lives on the filesystem, not in the DB. Re-process
     engagements from raw output using replay mode:

     ```
     mseco replay <engagement_id> --from parse
     ```

- **Prevention:** Ensure stable power and sufficient memory. `Ctrl+C`
  (SIGINT) is safe; `kill -9` (SIGKILL) is not.

---

## 3. Client-Provided Pre-Collected Output Ingestion

**Symptom:** Client sends their own ScubaGear / Maester / Monkey365
output files instead of providing credentials for live collection.

**Likely cause:** Client security policy prohibits granting assessment
tool access. Common in heavily regulated environments.

**Resolution:**

1. Create the engagement normally:

   ```
   mseco engagement create engagement.yaml
   ```

2. Ingest the client's raw output files using `mseco ingest` (see
   issue #78 -- command not yet implemented):

   ```
   mseco ingest <id> --tool scubagear --from client-scubagear/
   ```

   `mseco ingest` copies the artifacts into the engagement directory
   under `raw-output/artifacts/<slug>/` and writes the required
   `RawToolOutput` manifest to `raw-output/manifests/<slug>.json`.
   Without a valid manifest, `mseco replay` will fail.

   **Until `mseco ingest` is available:** This scenario requires
   manually constructing a `RawToolOutput` JSON manifest and placing
   artifacts at the correct paths. Engagement directories are named
   `<slug>-<id>` (e.g., `acme-corp-<id>`), not `<id>` alone.

3. Replay the pipeline from PARSE (skipping COLLECT):

   ```
   mseco replay <id> --from parse
   ```

4. Verify the replay succeeded:

   ```
   mseco engagement status <id>
   ```

**Caveats:**

- Validate that client-provided files match the expected schema. If the
  client used a different tool version, the parser may encounter
  unexpected fields. Check the parser log output for warnings.

- The assessment date in the report reflects when the client ran the
  tools, not when you processed them. Set this in metadata if needed.

---

## 4. AI QA Budget Exhaustion Mid-Pipeline

**Symptom:** Pipeline completes CONSOLIDATED stage but QA_REVIEW fails
with `TokenBudgetExhaustedError`.

**Likely cause:** Large engagement with many findings. The AI QA layer
tracks token usage across all tasks (severity review, dedup review,
root cause, narratives). Budget is configured per engagement.

**Diagnostic steps:**

1. Inspect pipeline events:

   ```
   mseco engagement status <id>
   ```

2. Check which QA tasks completed before exhaustion. Installed analytics
   plugins surface per-task token usage:

   ```
   mseco analytics cost
   ```

**Resolution:**

- **Increase the budget:** Edit the engagement config and re-run QA:

  ```yaml
  pipeline:
    qa_token_budget: 200000  # default is 100000
  ```

  ```
  mseco run <config.yaml> --engagement-id <id> --force-stage QA_REVIEW
  ```

- **Use no-op QA:** If AI QA is not critical for this engagement, select
  the noop strategy and skip AI-generated narratives:

  ```
  mseco run <config.yaml> --engagement-id <id> \
    --force-stage QA_REVIEW --qa-strategy noop
  ```

- **Partial QA results:** If severity review and dedup review completed
  but narratives did not, the partial results persist. The operator can
  write narratives manually in the review UI and approve QA there.

---

## 5. Partial Adapter Failure Triage

**Symptom:** Pipeline completes but reports show "2 of 3 tools
contributed." One adapter failed.

**Likely cause:** Tool prerequisites not met (wrong version, missing
module), authentication failure for one tool, or tool-specific API error.

**Diagnostic steps:**

1. Check engagement status for the failed adapter's error:

   ```
   mseco engagement status <id>
   ```

2. Run prerequisite checks for all adapters:

   ```
   mseco adapters check
   ```

3. For PowerShell adapters, verify module provenance:

   ```
   mseco preflight <config.yaml>
   ```

**Resolution:**

- **Fix and re-collect:** Once the failure is addressed, re-run from
  COLLECT. Note that `--force-stage COLLECT` re-runs **all** adapters,
  not just the failed one -- expect the full collection runtime and API
  load:

  ```
  mseco run <config.yaml> --engagement-id <id> --force-stage COLLECT
  ```

- **Proceed with partial results:** If the failed adapter is not critical
  (e.g., Azure Advisor for an M365-only assessment), the report clearly
  marks which tools contributed. The report methodology section lists
  which tools succeeded and which failed automatically.

---

## 6. Engagement State Stuck in Transition

**Symptom:** `mseco engagement status` shows state like `COLLECTING` or
`NORMALIZING` but no process is running.

**Likely cause:** Process was killed (OOM, Ctrl+C, SSH disconnect) during
a stage transition. The event journal has a `state_transition` event to
a *-ing state without a corresponding transition to the *-ed state.

**Diagnostic steps:**

1. Verify no mseco process is running:

   ```
   pgrep -af mseco
   ```

2. The lock is managed by `filelock` under the engagement directory. A
   stale lock is released automatically when the next process attempts
   to acquire it.

**Resolution:**

1. Re-run `mseco run` with `--force-stage COLLECT`:

   ```
   mseco run <config.yaml> --engagement-id <id> --force-stage COLLECT
   ```

   `reset_for_rerun` forces the engagement state back to the target
   stage's entry state, and `run_from` re-executes from there. Use
   `COLLECT` for any stuck state -- it has no upstream preconditions.
   If you know the pipeline completed further (e.g., stuck at
   CONSOLIDATING but NORMALIZING finished), use the matching stage
   to avoid re-running earlier work.

2. If `force-stage` rejects the transition due to an invalid state, use
   `--rerun` to re-run the entire pipeline:

   ```
   mseco run <config.yaml> --engagement-id <id> --rerun
   ```

---

## 7. Replay from Stale Raw Output

**Symptom:** Operator wants to re-process an older engagement after
updating normalization rules or severity mappings, but the raw output
comes from an older adapter schema version.

**Likely cause:** Adapter output format changed between the original
collection and the current code version. The `schema_version` on the
persisted manifest indicates a mismatch.

**Diagnostic steps:**

1. Compare the persisted manifest's `schema_version` against the current
   adapter's expected schema version (documented in the adapter's
   `parser.py` or `adapter.py` header).

**Resolution:**

- **Compatible versions (minor/patch bump):** Replay proceeds normally:

  ```
  mseco replay <id> --from parse
  ```

- **Incompatible versions (major bump):** Replay raises
  `InvalidRawOutputError`. Options:

  1. Re-collect with the current adapter version (requires client access)
  2. Pin the adapter package to the older version temporarily
  3. Write a schema migration script for the raw output format

- **Prevention:** The conformance suite's fixture round-trip test catches
  format drift at CI time, before it reaches production.

---

## 8. Renderer Failure After Successful Pipeline

**Symptom:** All pipeline stages complete (QA_APPROVED) but RENDERING
fails. Consolidated findings are assembled correctly but the Node.js
renderer exits non-zero.

**Likely cause:** Node.js or npm packages missing, renderer kits not
linked, payload contains unexpected shapes, or renderer JS bug.

**Diagnostic steps:**

1. Check the renderer error in the event log:

   ```
   mseco engagement status <id>
   ```

2. Verify Node.js and renderer prerequisites:

   ```
   mseco preflight <config.yaml>
   ```

3. Test the renderer independently (produces the same output as a full
   pipeline re-render):

   ```
   mseco report <config.yaml> --engagement-id <id>
   ```

**Resolution:**

- **Missing dependencies:** Install Node.js packages in the renderer
  directory:

  ```
  cd report-renderers/basic && npm install
  ```

  Branded renderers installed via plugins typically link their dependencies
  through `file:` references in the renderer's own `package.json`; ensure
  those linked packages are installed.

- **Renderer bug:** Once fixed, re-render the engagement:

  ```
  mseco run <config.yaml> --engagement-id <id> --force-stage RENDER
  ```

---

## 9. Concurrent CLI / UI Conflict Resolution

**Symptom:** An installed review UI shows "Engagement locked by another
process" or CLI reports a lock acquisition timeout.

**Likely cause:** Both the CLI (`mseco run`) and a review UI plugin are
attempting state-mutating operations on the same engagement
simultaneously. The advisory `filelock` serializes these operations.

**Diagnostic steps:**

1. Check what holds the lock:

   ```
   lsof ~/.gxassessms/engagements/.locks/<id>.lock
   ```

2. Check if the holding process is alive.

**Resolution:**

- **Wait:** If a legitimate operation is in progress, wait for it to
  complete. The lock releases as soon as the holder exits.

- **Force release:** If the holding process crashed, the lock file
  lingers. Delete it manually:

  ```
  rm ~/.gxassessms/engagements/.locks/<id>.lock
  ```

  Then re-run the failed command. (There is no `mseco engagement unlock`
  subcommand -- lock management is handled by `filelock` and manual
  cleanup.)

- **Prevention:** Do not run `mseco run` while a review UI has active
  pipeline re-render operations in flight. Use the review UI's own
  pipeline controls when the UI is open.

---

## 10. Emergency Engagement Purge

**Symptom:** Client requires demonstrable data removal. Legal or
contractual obligation (GDPR, data retention policy, post-engagement
cleanup).

**Likely cause:** Regulatory requirement. The client's legal team needs
proof that all assessment data has been deleted.

**Resolution:**

1. Execute the purge (requires `--confirm`):

   ```
   mseco engagement purge <id> --confirm
   ```

   This permanently deletes:

   - All DB rows: findings, overrides, QA results, events, snapshots,
     stage history, coverage records, tool run results, and the
     engagement record itself
   - All filesystem artifacts: raw tool output, generated reports, config
     files, the engagement directory
   - An audit manifest is written BEFORE deletion to a location OUTSIDE
     the engagement directory

2. The audit manifest is preserved outside the engagement directory and
   is NOT deleted by purge. Path is surfaced in the purge output; send
   it to the client's legal team as proof of deletion.

**Caveats:**

- Purge is irreversible. There is no undo.
- Longitudinal snapshots referencing the purged engagement retain a
  `purged` marker instead of actual data. Cross-engagement analytics no
  longer include the purged engagement's findings.
- The audit manifest itself may have its own retention policy
  requirement. Coordinate with the client.
