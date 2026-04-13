# Security Model

GxAssessMS is a security assessment tool that runs third-party code against
client tenants. The security model is designed around one principle:
**fail closed**. If something looks wrong, the pipeline stops rather than
producing a questionable report.

## Module Provenance

Before running any PowerShell-based tool (ScubaGear, Maester, Monkey365),
GxAssessMS verifies the module's integrity. This protects against supply-chain
attacks -- someone replacing a module with a malicious version that could
exfiltrate tenant data.

The verification steps:

1. **Version check** -- the installed module version must fall within the
   adapter's allowed range (e.g., ScubaGear 1.5.0 -- 1.x)
2. **Staging** -- the module is copied to a private temporary directory. This
   prevents anything from modifying the module between verification and
   execution (TOCTOU protection)
3. **Tree hash** -- a `sha256tree:v1` hash of the entire module directory is
   computed and compared to known-good hashes in the adapter's provenance policy
4. **Signature verification** -- Authenticode signature is verified when the
   module is signed; hash-only verification is used as a fallback when
   signatures aren't available

If **any** check fails, that adapter is blocked entirely. There is no
"run anyway" option. You can see provenance status with:

```bash
mseco adapters check
```

### Narrowing the Policy

The config file's `module_policy_override` lets you tighten (but never loosen)
the provenance policy for a specific tool. For example, pinning to an exact
version:

```yaml
tools:
  scubagear:
    enabled: true
    module_policy_override:
      version_range: "==1.5.2"
```

See [Configuration Reference](configuration.md) for the full override syntax.

## Data Handling

Assessment output contains sensitive tenant configuration data. GxAssessMS
handles it carefully:

- **Engagement directories** are created with `0o700` permissions (owner-only
  access)
- **Files** are written with `0o600` permissions
- **All data stays local** -- nothing is sent to external services. The tool
  does not phone home.
- **SQLite database** uses WAL mode for safe concurrent access

Data is organized per-engagement. Each engagement has its own directory
containing raw tool output, the SQLite database, and generated reports.

## Config Security

- **Secrets are never stored in the config file.** The `client_secret_env` field
  holds the *name* of an environment variable, not the secret itself. This means
  config files can be committed to version control without exposing credentials.
- **Strict validation** rejects unknown fields, wrong types, and malformed values
  immediately. No input is silently coerced.
- **No string substitution** in PowerShell execution. Tool arguments are passed
  through structured JSON, eliminating injection vectors.

## Operator Checklist

- Keep PowerShell modules up to date within the adapter's supported version range
- Use `client_credential` with a certificate for production assessments (more
  secure than a client secret)
- Rotate client secrets regularly
- Review assessment output before sharing it with anyone outside the engagement
- Clean up completed engagements with `mseco engagement purge --confirm <id>`
  when the data is no longer needed
