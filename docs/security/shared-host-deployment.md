# Shared-Host Deployment Guide

## Intended Deployment Model

GxAssessMS is designed for **single-operator analyst workstations** -- one user,
one engagement at a time. The CLI, storage layout, and permission model all assume
a trusted local operator. Shared-host or multi-user deployments (jump boxes, shared
VMs, CI runners) require the additional hardening described in this guide.

## Storage Permissions

The tool stores engagement data under `~/.gxassessms/` by default. This path is
overridable via the `GXASSESSMS_DATA_DIR` environment variable.

**POSIX systems (Linux / macOS):** Directories are created with `0700` permissions
(owner-only read, write, execute). The tool warns at runtime when storage
directories have group- or world-accessible bits set. Fix with:
`chmod -R o-rwx,g-rwx ~/.gxassessms`

**Windows:** NTFS ACLs inherited from the user profile protect the data directory.
Verify that `%USERPROFILE%\.gxassessms` is not on a shared network drive without
proper ACLs. If the data directory is on a network share, apply explicit deny-all
ACEs for users who should not have access.

## Dedicated Service Accounts

On shared hosts, run GxAssessMS under a dedicated, unprivileged service account
(e.g., `gxassessms-runner`). Benefits:

- Isolates assessment data from other users on the host.
- Simplifies audit attribution -- all lifecycle manifests now capture the OS
  username, hostname, and PID of the operator.
- Limits blast radius if the account is compromised.

Do not share service account credentials across multiple operators. Each analyst
should have their own account, or a single automation account should be used
exclusively by the CI pipeline.

## Backup and Retention

Raw tool outputs and rendered reports contain **customer-sensitive assessment
data** -- configuration snapshots, compliance gaps, and security findings.
Backups of the data directory should be encrypted at rest, access to backup media
should be restricted to authorized personnel, and retention schedules should comply
with your organization's data handling policy.

GxAssessMS does **not** manage backups or retention. These are the responsibility
of the deployment environment.

## Lifecycle Command Risks

The `mseco engagement purge` command is **irreversible**. It permanently deletes
engagement data. On shared hosts, restrict access to the `mseco` CLI via OS-level
controls:

- Dedicated service accounts with limited shell access.
- `sudo` policies that gate destructive subcommands.
- RBAC wrappers that enforce approval workflows before purge operations.

Archive and restore operations write audit manifests to the `audit/` directory
alongside the engagement data, providing a tamper-evident record of data movement.

## CLI Access Control

GxAssessMS has **no application-level authorization or role-based access control**.
All access control is the responsibility of the operating system user model.

- Do not grant shared accounts CLI access to assessment data.
- Do not add the `mseco` binary to a shared `PATH` without restricting execute
  permissions to authorized users.
- On Linux, consider restricting the binary with `chmod 750` and a dedicated group.

## Audit Trail

All lifecycle operations -- archive, restore, purge -- write JSON audit manifests
to the `audit/` directory under the data root. Each manifest captures: `action`,
`engagement_id`, `operator`, `timestamp`, `hostname`, `os_user`, `pid`,
`platform`, and `platform_version`. Export operations log equivalent context.

Audit manifests are append-only by convention -- the tool never modifies or
deletes existing manifests. Protect the `audit/` directory with the same
permissions as the engagement data.
