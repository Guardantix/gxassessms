# Configuration Reference

GxAssessMS is configured through a YAML file passed to most `mseco` commands.
The config is validated strictly -- misspelled keys and wrong types produce
immediate errors, not silent surprises.

## Config Sections

| Section | Required | Purpose |
|---------|----------|---------|
| `client` | Yes | Who is being assessed |
| `auth` | Yes | How to authenticate to the tenant |
| `tools` | No | Which assessment tools to run and how |
| `report` | No | Output format and theme |
| `pipeline` | No | Execution tuning |

## `client`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Client or organization name (appears in reports) |
| `tenant_id` | string | Yes | Microsoft Entra tenant ID (GUID). Must match `auth.tenant_id` |
| `subscription_id` | string | No | Azure subscription ID (required for Azure Advisor) |

```yaml
client:
  name: "Contoso"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  subscription_id: "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"  # optional
```

## `auth`

Three authentication methods are supported. Choose based on your scenario.

### `client_credential` with Secret

Best for: automated or unattended assessment runs.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | Yes | `"client_credential"` |
| `tenant_id` | string | Yes | Must match `client.tenant_id` |
| `client_id` | string | Yes | Application (client) ID from your app registration |
| `client_secret_env` | string | Yes* | Name of the environment variable holding the secret. **Not the secret itself.** |

*Either `client_secret_env` or `certificate_path` is required.

```yaml
auth:
  method: "client_credential"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_id: "11111111-2222-3333-4444-555555555555"
  client_secret_env: "AZURE_CLIENT_SECRET"  # pragma: allowlist secret
```

### `client_credential` with Certificate

Best for: production deployments with higher security requirements.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | Yes | `"client_credential"` |
| `tenant_id` | string | Yes | Must match `client.tenant_id` |
| `client_id` | string | Yes | Application (client) ID |
| `certificate_path` | string | Yes* | Path to the PEM certificate file |

```yaml
auth:
  method: "client_credential"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_id: "11111111-2222-3333-4444-555555555555"
  certificate_path: "/path/to/cert.pem"
```

### `device_code`

Best for: one-off runs where you're at the keyboard. Opens a browser for
interactive sign-in.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | Yes | `"device_code"` |
| `tenant_id` | string | Yes | Must match `client.tenant_id` |
| `client_id` | string | Yes | Application (client) ID |

```yaml
auth:
  method: "device_code"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_id: "11111111-2222-3333-4444-555555555555"
```

### `interactive`

Best for: browser-based sign-in flow.

Same fields as `device_code`. Uses the system browser instead of a device code
prompt.

```yaml
auth:
  method: "interactive"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_id: "11111111-2222-3333-4444-555555555555"
```

## `tools`

Each tool can be enabled with a shorthand or expanded form.

**Shorthand:**

```yaml
tools:
  scubagear: true
  maester: false
```

**Expanded form:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether to run this tool |
| `modules` | list of strings | `[]` | Which modules/products to assess (tool-specific) |
| `timeout` | integer | varies | Maximum seconds for tool execution |
| `output_dir` | string | `""` | Custom output directory |
| `extra_args` | list of strings | `[]` | Additional arguments passed to the tool |
| `module_policy_override` | object | none | Advanced: narrow module provenance policy (see below) |

```yaml
tools:
  scubagear:
    enabled: true
    modules: ["AAD", "EXO", "SharePoint", "Teams"]
    timeout: 1200

  maester:
    enabled: true
    timeout: 600

  securescore: true    # shorthand -- just enable with defaults
```

**Tool-specific module values:**

| Tool | Valid `modules` | Default (if omitted) |
|------|-----------------|---------------------|
| ScubaGear | `AAD`, `Defender`, `EXO`, `PowerPlatform`, `SharePoint`, `Teams` | All modules |
| Others | Not applicable -- no module selection | N/A |

**Default timeouts:**

| Tool | Default Timeout |
|------|----------------|
| ScubaGear | 1800s (30 min) |
| All others | Adapter-specific |

See [Adapter Guide](adapters.md) for per-tool configuration details.

### Module Provenance Overrides (Advanced)

This is a per-tool nested field for additional security hardening. It narrows
the adapter's built-in provenance policy -- it can restrict to a specific
version or hash, but never loosen the baseline.

| Field | Type | Description |
|-------|------|-------------|
| `version_range` | string | Exact version pin, e.g., `"==1.5.2"` |
| `pinned_package_hashes` | list of strings | Specific `sha256tree:v1:...` hashes to allow |

```yaml
tools:
  scubagear:
    enabled: true
    module_policy_override:
      version_range: "==1.5.2"
      pinned_package_hashes:
        - "sha256tree:v1:abc123..."
```

Most operators won't need this. See [Security Model](security.md) for the full
provenance verification model.

## `report`

| Field | YAML Key | Type | Default | Description |
|-------|----------|------|---------|-------------|
| Report formats | `formats` | list of strings | `["docx"]` | Output formats to generate |
| Theme | `theme` | string | `"basic"` | Report visual theme |
| Logo | `logo_path` | string | none | Path to a logo image for the report |

Additional report formats and themes may be available through extension packages.

```yaml
report:
  formats: ["docx"]
  theme: "basic"
  logo_path: "assets/logo.png"
```

## `pipeline`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_parallel` | integer | `4` | Maximum tools to run simultaneously. Higher = faster but more memory |
| `qa_model` | string | `"claude-sonnet-4-6"` | Model for QA review (if a QA strategy is installed) |
| `qa_token_budget` | integer | `100000` | Token budget for QA review |

```yaml
pipeline:
  max_parallel: 3
  qa_model: "claude-sonnet-4-6"
  qa_token_budget: 100000
```

The `qa_model` and `qa_token_budget` fields only take effect when a QA strategy
extension is installed. With the default no-op strategy, they're ignored.

## Complete Example

```yaml
client:
  name: "Contoso Healthcare"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  subscription_id: "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"

auth:
  method: "client_credential"
  tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_id: "11111111-2222-3333-4444-555555555555"
  client_secret_env: "AZURE_CLIENT_SECRET"  # pragma: allowlist secret

tools:
  scubagear:
    enabled: true
    modules: ["AAD", "Defender", "EXO", "SharePoint", "Teams"]
    timeout: 1800
  maester:
    enabled: true
    timeout: 600
  securescore: true
  azureadvisor: true

report:
  formats: ["docx"]
  theme: "basic"

pipeline:
  max_parallel: 3
```

## Validation Errors

When `mseco preflight` or `mseco run` detects a config problem, it reports the
specific issue. Common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| `client.name is empty` | Name field missing or blank | Add `name: "Your Client"` |
| `client.tenant_id is empty` | Tenant ID missing | Add your M365 tenant GUID |
| `auth.tenant_id does not match client.tenant_id` | Mismatched tenant IDs | Make them identical |
| `client_credential requires client_secret_env or certificate_path` | Neither secret nor cert configured | Add one of these fields |
| `Invalid value type for 'enabled'` | Used a string like `"true"` instead of `true` | Remove the quotes |
| `Invalid value type for 'timeout'` | Used `true` instead of a number | Set an integer value |
| `Unknown section` | Typo in a top-level key | Check spelling against this reference |
| `Extra inputs are not permitted` | Typo in a field name | Check spelling against the field tables above |

**Warnings** (non-blocking):

| Warning | Meaning |
|---------|---------|
| `client_secret_env provided but auth method is device_code` | Secret is ignored for interactive methods |
| `No tools are enabled` | Pipeline will run but produce no findings |
