# Installation

## Requirements

| Requirement | Version | Needed For |
|-------------|---------|------------|
| Python | 3.12+ | Core package |
| PowerShell | 7+ | ScubaGear, Maester, Monkey365 adapters |
| Node.js | 18+ | Report rendering (.docx, .pptx) |

PowerShell and Node.js are only required if you use the adapters or report
formats that depend on them. The API-based adapters (Secure Score, Azure
Advisor) and Prowler need only Python.

## Installing Python

**Windows:**

```powershell
# Option 1: Download from python.org
# https://www.python.org/downloads/ -- choose 3.12 or later

# Option 2: winget
winget install Python.Python.3.12
```

**Linux (Ubuntu/Debian):**

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

**Verify:**

```bash
python3 --version
# Python 3.12.x or later
```

## Installing GxAssessMS

Create a virtual environment (recommended) and install:

```bash
python3 -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install gxassessms
```

**From source (development):**

```bash
git clone https://github.com/Guardantix/gxassessms.git
cd gxassessms
pip install -e ".[dev]"
```

## PowerShell Modules

If you plan to use ScubaGear, Maester, or Monkey365, install the required
PowerShell modules. Each module is verified for integrity before execution --
see [Security Model](security.md) for details.

**ScubaGear** (CISA SCuBA M365 baseline):

```powershell
Install-Module -Name ScubaGear -Scope CurrentUser
```

Required version: 1.5.0 or later (below 2.0.0).

**Maester** (Entra ID / M365 security):

```powershell
Install-Module -Name Maester -Scope CurrentUser
```

Required version: 1.0.0 or later (below 2.0.0).

**Monkey365** (Azure / M365 / Entra ID compliance):

```powershell
Install-Module -Name monkey365 -Scope CurrentUser
```

Required version: 1.0.0 or later (below 2.0.0).

## Azure App Registration

To run assessments against a tenant, you need an Azure app registration with
the right API permissions. This is the most involved setup step -- take it
one piece at a time.

### Create the App Registration

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** > **App registrations** > **New registration**
3. Name it something recognizable (e.g., "GxAssessMS")
4. Set **Supported account types** to "Accounts in this organizational directory only"
5. Leave **Redirect URI** blank (not needed for client credentials)
6. Click **Register**
7. Copy the **Application (client) ID** and **Directory (tenant) ID** -- you'll need
   these for your config file

### Grant API Permissions

The permissions you need depend on which adapters you plan to run. At minimum,
grant these Microsoft Graph permissions (Application type):

- `Directory.Read.All` -- required by most adapters
- `Policy.Read.All` -- required for policy assessment
- `SecurityEvents.Read.All` -- required for Secure Score

For Azure-level adapters (Azure Advisor, Prowler), you also need:

- **Reader** role on the Azure subscription(s) you want to assess

After adding permissions, click **Grant admin consent** for the tenant.

### Create a Client Secret or Certificate

**Option A: Client secret** (simpler, good for testing):

1. In your app registration, go to **Certificates & secrets** > **Client secrets**
2. Click **New client secret**, set an expiry, and click **Add**
3. Copy the secret value immediately (it won't be shown again)
4. Store it in an environment variable:

```bash
# Linux / macOS
export AZURE_CLIENT_SECRET="your-secret-value"  # pragma: allowlist secret

# Windows PowerShell
$env:AZURE_CLIENT_SECRET = "your-secret-value"  # pragma: allowlist secret
```

**Option B: Certificate** (recommended for production):

1. Generate a certificate (or use an existing one)
2. Upload the public key to **Certificates & secrets** > **Certificates**
3. Reference the certificate path in your config file

### Using az CLI Instead

If you prefer the command line:

```bash
# Create the app registration
az ad app create --display-name "GxAssessMS"

# Note the appId from the output, then create a service principal
az ad sp create --id <appId>

# Add Graph API permissions
az ad app permission add --id <appId> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

# Grant admin consent
az ad app permission admin-consent --id <appId>
```

## Verify Your Setup

Once everything is installed, validate with `mseco preflight`:

```bash
mseco preflight assessment.yaml
```

This checks:

1. **Config validation** -- required fields, valid tool names, auth configuration
2. **Prerequisite checks** -- whether each enabled tool is installed and meets
   version requirements
3. **Auth validation** -- whether credentials are accessible
4. **Renderer checks** -- whether Node.js and npm packages are available for
   report generation

A passing preflight looks like:

```
                          Preflight Validation
┏━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check        ┃ Status ┃ Details                                    ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ScubaGear    │  PASS  │ ScubaGear: all packages available          │
│ SecureScore  │  PASS  │ SecureScore: all packages available        │
└──────────────┴────────┴───────────────────────────────────────────┘
```

If a check fails, the **Details** column tells you what's missing and how to fix it.

## Container Deployment

> This section will be expanded as container deployment is tested in production.

A minimal Dockerfile:

```dockerfile
FROM python:3.12-slim

# Install PowerShell (for PS-based adapters)
RUN apt-get update && apt-get install -y wget apt-transport-https \
    && wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get update && apt-get install -y powershell \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (for report rendering)
RUN apt-get update && apt-get install -y nodejs npm \
    && rm -rf /var/lib/apt/lists/*

RUN pip install gxassessms

ENTRYPOINT ["mseco"]
```

## Troubleshooting

**"Python was not found" or wrong version:**

```bash
python3 --version   # Should be 3.12+
```

If your system has an older Python, install 3.12+ alongside it. Use `python3.12`
explicitly or set up pyenv to manage versions.

**PowerShell execution policy errors:**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Module provenance verification failures:**

If `mseco adapters check` shows provenance failures, the installed module version
may not match what the adapter expects. Check the required version ranges above
and update with `Update-Module`.

**Auth errors during preflight:**

- Verify your environment variable is set: `echo $AZURE_CLIENT_SECRET`
- Confirm the app registration has the required API permissions
- Make sure admin consent has been granted
- Check that `client.tenant_id` and `auth.tenant_id` match in your config
