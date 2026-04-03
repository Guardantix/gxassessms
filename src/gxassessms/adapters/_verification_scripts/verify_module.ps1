#Requires -Version 5.1
<#
.SYNOPSIS
    Module provenance verification template for GxAssessMS.

.DESCRIPTION
    Static .ps1 template invoked by gxassessms.adapters._verification.verify_module().
    All dynamic data flows through JSON input -- no string substitution, no injection surface.

    Phases:
        1   - Candidate Discovery
        1.5 - Platform Compatibility
        2   - Live Reparse Point Scan
        3   - Live Signature Check (Informational)
        4   - Staging (Enumerate-and-Copy)
        5   - Manifest Confinement Check
        6   - Staged Reparse Point Scan
        6.5 - Staged Signature Check (Authoritative)
        7   - Tree Hash (sha256tree:v1)
        8   - Approval Logic + Write Report
        9   - Post-Import Invocation (Collection Mode Only)

.PARAMETER InputPath
    Path to JSON input file containing policy and invocation parameters.

.PARAMETER ReportPath
    Path where JSON verification report will be written.

.PARAMETER StagingDir
    Temporary directory for staged module copies.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [Parameter(Mandatory = $true)]
    [string]$StagingDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Read input
# ---------------------------------------------------------------------------

$inputJson = Get-Content -Path $InputPath -Raw -Encoding UTF8
$input = $inputJson | ConvertFrom-Json

$moduleName = $input.module_name
$versionRange = $input.effective_version_range
$approvedHashes = @($input.effective_approved_hashes)
$allowedSigners = @($input.allowed_signers)
$allowHashFallback = [bool]$input.allow_package_hash_fallback
$mode = $input.mode
$postImportInvocation = $input.post_import_invocation

# ---------------------------------------------------------------------------
# Helper: Parse semver X.Y.Z -> array of [major, minor, patch]
# ---------------------------------------------------------------------------

function Parse-Semver {
    param([string]$Version)
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        return $null
    }
    $parts = $Version.Split('.')
    return @([int]$parts[0], [int]$parts[1], [int]$parts[2])
}

# ---------------------------------------------------------------------------
# Helper: Compare two semver tuples. Returns -1, 0, or 1.
# ---------------------------------------------------------------------------

function Compare-Semver {
    param(
        [int[]]$Left,
        [int[]]$Right
    )
    for ($i = 0; $i -lt 3; $i++) {
        if ($Left[$i] -lt $Right[$i]) { return -1 }
        if ($Left[$i] -gt $Right[$i]) { return 1 }
    }
    return 0
}

# ---------------------------------------------------------------------------
# Helper: Check if version satisfies constraint string (e.g. ">=1.0.0,<2.0.0")
# ---------------------------------------------------------------------------

function Test-VersionInRange {
    param(
        [string]$Version,
        [string]$Range
    )
    $ver = Parse-Semver -Version $Version
    if ($null -eq $ver) { return $false }

    $constraints = $Range.Split(',') | ForEach-Object { $_.Trim() }
    foreach ($constraint in $constraints) {
        if ($constraint -match '^(>=|<=|>|<|==)(\d+\.\d+\.\d+)$') {
            $op = $Matches[1]
            $target = Parse-Semver -Version $Matches[2]
            $cmp = Compare-Semver -Left $ver -Right $target

            switch ($op) {
                '>='  { if ($cmp -lt 0) { return $false } }
                '<='  { if ($cmp -gt 0) { return $false } }
                '>'   { if ($cmp -le 0) { return $false } }
                '<'   { if ($cmp -ge 0) { return $false } }
                '=='  { if ($cmp -ne 0) { return $false } }
            }
        }
        else {
            # Invalid constraint -- fail closed
            return $false
        }
    }
    return $true
}

# ---------------------------------------------------------------------------
# Helper: Compute sha256tree:v1 hash for a directory
# ---------------------------------------------------------------------------

function Compute-TreeHash {
    param([string]$Directory)

    $dirLen = $Directory.Length
    $files = @(Get-ChildItem -Path $Directory -Recurse -File -Force | Sort-Object {
        $_.FullName.Substring($dirLen + 1).Replace('\', '/')
    })

    $manifest = ''
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($dirLen + 1).Replace('\', '/')
        $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
        $manifest += "$rel`0$hash`n"
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($manifest)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $treeHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLower()
    return "sha256tree:v1:$treeHash"
}

# ---------------------------------------------------------------------------
# Helper: Check for reparse points in a directory tree
# ---------------------------------------------------------------------------

function Test-ReparsePoints {
    param([string]$Directory)

    $items = @(Get-ChildItem -Path $Directory -Recurse -Force)
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            return $item.FullName
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Helper: Get authenticode signature (platform-aware)
# ---------------------------------------------------------------------------

function Get-SafeAuthenticodeSignature {
    param([string]$FilePath)

    $cmdExists = Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue
    if (-not $cmdExists) {
        return @{
            Status     = 'platform_unsupported'
            Subject    = $null
            Issuer     = $null
            Thumbprint = $null
        }
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $status = $sig.Status.ToString()

        # On Linux/macOS, Get-AuthenticodeSignature exists but returns NotSupportedFileFormat
        # or other non-Valid statuses for non-PE files. Treat as platform_unsupported on
        # non-Windows platforms.
        if (-not $IsWindows) {
            return @{
                Status     = 'platform_unsupported'
                Subject    = $null
                Issuer     = $null
                Thumbprint = $null
            }
        }

        $subject = $null
        $issuer = $null
        $thumbprint = $null
        if ($null -ne $sig.SignerCertificate) {
            $subject = $sig.SignerCertificate.Subject
            $issuer = $sig.SignerCertificate.Issuer
            $thumbprint = $sig.SignerCertificate.Thumbprint
        }

        return @{
            Status     = $status
            Subject    = $subject
            Issuer     = $issuer
            Thumbprint = $thumbprint
        }
    }
    catch {
        return @{
            Status     = 'error'
            Subject    = $null
            Issuer     = $null
            Thumbprint = $null
        }
    }
}

# ---------------------------------------------------------------------------
# Helper: Check if signer matches allowlist
# ---------------------------------------------------------------------------

function Test-SignerApproved {
    param(
        [string]$Subject,
        [string]$Issuer,
        [array]$AllowedSigners
    )

    foreach ($signer in $AllowedSigners) {
        if ($Subject -eq $signer.subject -and $Issuer -eq $signer.issuer) {
            return $true
        }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Helper: Stage a module directory (enumerate-and-copy, no Copy-Item -Recurse)
# ---------------------------------------------------------------------------

function Copy-ModuleTree {
    param(
        [string]$Source,
        [string]$Destination
    )

    [IO.Directory]::CreateDirectory($Destination) | Out-Null

    $sourceLen = $Source.Length
    $items = @(Get-ChildItem -Path $Source -Recurse -Force)

    foreach ($item in $items) {
        $relPath = $item.FullName.Substring($sourceLen + 1)
        $destPath = Join-Path $Destination $relPath

        if ($item.PSIsContainer) {
            [IO.Directory]::CreateDirectory($destPath) | Out-Null
        }
        else {
            $destDir = [IO.Path]::GetDirectoryName($destPath)
            if (-not [IO.Directory]::Exists($destDir)) {
                [IO.Directory]::CreateDirectory($destDir) | Out-Null
            }
            [IO.File]::Copy($item.FullName, $destPath, $true)
        }
    }
}

# ---------------------------------------------------------------------------
# Helper: Check manifest confinement
# ---------------------------------------------------------------------------

function Test-ManifestConfinement {
    param(
        [string]$ManifestPath,
        [string]$ModuleBase
    )

    try {
        $manifest = Import-PowerShellDataFile -Path $ManifestPath
    }
    catch {
        return "Failed to parse manifest: $($_.Exception.Message)"
    }

    # Fields to check for path confinement
    $fieldsToCheck = @('RootModule', 'NestedModules', 'RequiredAssemblies', 'ScriptsToProcess')

    foreach ($field in $fieldsToCheck) {
        $values = $manifest[$field]
        if ($null -eq $values -or ($values -is [string] -and [string]::IsNullOrWhiteSpace($values))) {
            continue
        }

        # Normalize to array
        if ($values -is [string]) {
            $values = @($values)
        }
        elseif ($values -is [System.Collections.Hashtable]) {
            # Module specification -- reject
            return "Confinement violation in ${field}: module specification not allowed"
        }

        foreach ($value in $values) {
            if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) {
                continue
            }

            # Reject hashtable entries (module specifications)
            if ($value -is [System.Collections.Hashtable]) {
                return "Confinement violation in ${field}: module specification not allowed"
            }

            $valueStr = [string]$value

            # Reject UNC paths
            if ($valueStr.StartsWith('\\')) {
                return "Confinement violation in ${field}: UNC path '$valueStr'"
            }

            # Reject absolute paths outside tree
            if ([IO.Path]::IsPathRooted($valueStr)) {
                try {
                    $resolved = [IO.Path]::GetFullPath($valueStr)
                    if (-not $resolved.StartsWith($ModuleBase)) {
                        return "Confinement violation in ${field}: absolute path '$valueStr' outside module base"
                    }
                }
                catch {
                    return "Confinement violation in ${field}: invalid path '$valueStr'"
                }
                continue
            }

            # Reject bare names without extension (could resolve via GAC)
            # Exception: if the value has a path separator, it's a relative path
            if (-not $valueStr.Contains('.') -and -not $valueStr.Contains('/') -and -not $valueStr.Contains('\')) {
                return "Confinement violation in ${field}: bare name '$valueStr' without extension (potential GAC assembly)"
            }

            # Check for path escape via .. components
            try {
                $combined = Join-Path $ModuleBase $valueStr
                $resolved = [IO.Path]::GetFullPath($combined)
                if (-not $resolved.StartsWith($ModuleBase)) {
                    return "Confinement violation in ${field}: path '$valueStr' escapes module base"
                }
            }
            catch {
                return "Confinement violation in ${field}: invalid path '$valueStr'"
            }
        }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Initialize report structure
# ---------------------------------------------------------------------------

$report = @{
    module_name            = $moduleName
    provenance_approved    = $false
    execution_supported    = $false
    evidence_path          = $null
    rejection_reasons      = @()
    approved_candidate     = $null
    candidates             = @()
    required_modules_logged = @()
    powershell_executable  = (Get-Process -Id $PID).MainModule.FileName
}

# ---------------------------------------------------------------------------
# Phase 1: Candidate Discovery
# ---------------------------------------------------------------------------

$allCandidates = @(Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue)

$candidateOutcomes = @()
$candidateIndex = 0

foreach ($candidate in $allCandidates) {
    $outcome = @{
        version              = $null
        live_manifest_path   = $null
        live_module_root     = $null
        staged_manifest_path = $null
        staged_module_root   = $null
        provenance_approved  = $false
        execution_supported  = $false
        rejection_reasons    = @()
        confinement_violation = $null
        package_hash         = $null
        hash_approved        = $false
        live_signature_status     = $null
        live_signer_subject       = $null
        live_signer_issuer        = $null
        live_signer_thumbprint    = $null
        staged_signature_status   = $null
        staged_signer_subject     = $null
        staged_signer_issuer      = $null
        staged_signer_thumbprint  = $null
        staged_signer_approved    = $null
        evidence_path        = $null
    }

    # Check for .psd1 manifest
    $manifestPath = $candidate.Path
    if (-not $manifestPath -or -not $manifestPath.EndsWith('.psd1')) {
        $outcome.rejection_reasons += 'no_psd1_manifest'
        $candidateOutcomes += $outcome
        $candidateIndex++
        continue
    }

    $outcome.live_manifest_path = $manifestPath
    $outcome.live_module_root = $candidate.ModuleBase

    # Version check
    $versionStr = $candidate.Version.ToString()
    $parsed = Parse-Semver -Version $versionStr
    if ($null -eq $parsed) {
        $outcome.rejection_reasons += "invalid_version_format:$versionStr"
        $outcome.version = $versionStr
        $candidateOutcomes += $outcome
        $candidateIndex++
        continue
    }
    $outcome.version = $versionStr

    # Version range check
    if (-not (Test-VersionInRange -Version $versionStr -Range $versionRange)) {
        $outcome.rejection_reasons += "version_out_of_range:$versionStr"
        $candidateOutcomes += $outcome
        $candidateIndex++
        continue
    }

    # -----------------------------------------------------------------------
    # Phase 1.5: Platform Compatibility
    # -----------------------------------------------------------------------

    $executionSupported = $true
    try {
        $manifestData = Import-PowerShellDataFile -Path $manifestPath -ErrorAction Stop

        # Check CompatiblePSEditions
        $compatEditions = $manifestData['CompatiblePSEditions']
        if ($null -ne $compatEditions -and $compatEditions.Count -gt 0) {
            $currentEdition = $PSVersionTable.PSEdition
            if ($currentEdition -notin $compatEditions) {
                $executionSupported = $false
            }
        }

        # Check PowerShellVersion minimum
        $requiredPSVersion = $manifestData['PowerShellVersion']
        if ($null -ne $requiredPSVersion -and $requiredPSVersion -ne '') {
            $requiredParsed = Parse-Semver -Version $requiredPSVersion
            if ($null -ne $requiredParsed) {
                $currentVer = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
                $currentParsed = Parse-Semver -Version $currentVer
                if ($null -ne $currentParsed) {
                    $cmp = Compare-Semver -Left $currentParsed -Right $requiredParsed
                    if ($cmp -lt 0) {
                        $executionSupported = $false
                    }
                }
            }
        }

        # Log RequiredModules
        $requiredModules = $manifestData['RequiredModules']
        if ($null -ne $requiredModules) {
            foreach ($rm in @($requiredModules)) {
                if ($rm -is [string]) {
                    $report.required_modules_logged += $rm
                }
                elseif ($rm -is [System.Collections.Hashtable] -and $rm.ContainsKey('ModuleName')) {
                    $report.required_modules_logged += $rm['ModuleName']
                }
            }
        }
    }
    catch {
        # If manifest can't be parsed for compat check, flag but continue
        $executionSupported = $true
    }

    $outcome.execution_supported = $executionSupported

    # -----------------------------------------------------------------------
    # Phase 2: Live Reparse Point Scan
    # -----------------------------------------------------------------------

    $reparseItem = Test-ReparsePoints -Directory $candidate.ModuleBase
    if ($null -ne $reparseItem) {
        $outcome.rejection_reasons += "reparse_point_detected:$reparseItem"
        $candidateOutcomes += $outcome
        $candidateIndex++
        continue
    }

    # -----------------------------------------------------------------------
    # Phase 3: Live Signature Check (Informational)
    # -----------------------------------------------------------------------

    $liveSig = Get-SafeAuthenticodeSignature -FilePath $manifestPath
    $outcome.live_signature_status = $liveSig.Status
    $outcome.live_signer_subject = $liveSig.Subject
    $outcome.live_signer_issuer = $liveSig.Issuer
    $outcome.live_signer_thumbprint = $liveSig.Thumbprint

    # -----------------------------------------------------------------------
    # Phase 4: Staging (Enumerate-and-Copy)
    # -----------------------------------------------------------------------

    $stageDest = Join-Path $StagingDir "$candidateIndex"
    Copy-ModuleTree -Source $candidate.ModuleBase -Destination $stageDest

    $stagedManifestName = [IO.Path]::GetFileName($manifestPath)
    $stagedManifestPath = Join-Path $stageDest $stagedManifestName

    $outcome.staged_manifest_path = $stagedManifestPath
    $outcome.staged_module_root = $stageDest

    # -----------------------------------------------------------------------
    # Phase 5: Manifest Confinement Check
    # -----------------------------------------------------------------------

    $confinementViolation = Test-ManifestConfinement -ManifestPath $stagedManifestPath -ModuleBase $stageDest
    if ($null -ne $confinementViolation) {
        $outcome.confinement_violation = $confinementViolation
        $outcome.rejection_reasons += "confinement_violation"
        $candidateOutcomes += $outcome
        $candidateIndex++
        continue
    }

    # -----------------------------------------------------------------------
    # Phase 6: Staged Reparse Point Scan
    # -----------------------------------------------------------------------

    $stagedReparse = Test-ReparsePoints -Directory $stageDest
    if ($null -ne $stagedReparse) {
        $outcome.rejection_reasons += "staged_reparse_point_detected:$stagedReparse"
        $candidateOutcomes += $outcome
        $candidateIndex++
        continue
    }

    # -----------------------------------------------------------------------
    # Phase 6.5: Staged Signature Check (Authoritative)
    # -----------------------------------------------------------------------

    $stagedSig = Get-SafeAuthenticodeSignature -FilePath $stagedManifestPath
    $outcome.staged_signature_status = $stagedSig.Status
    $outcome.staged_signer_subject = $stagedSig.Subject
    $outcome.staged_signer_issuer = $stagedSig.Issuer
    $outcome.staged_signer_thumbprint = $stagedSig.Thumbprint

    $signerApproved = $false
    if ($stagedSig.Status -eq 'Valid' -and $null -ne $stagedSig.Subject -and $null -ne $stagedSig.Issuer) {
        $signerApproved = Test-SignerApproved -Subject $stagedSig.Subject -Issuer $stagedSig.Issuer -AllowedSigners $allowedSigners
    }
    $outcome.staged_signer_approved = $signerApproved

    # -----------------------------------------------------------------------
    # Phase 7: Tree Hash (sha256tree:v1)
    # -----------------------------------------------------------------------

    $treeHash = Compute-TreeHash -Directory $stageDest
    $outcome.package_hash = $treeHash

    $hashApproved = $treeHash -in $approvedHashes
    $outcome.hash_approved = $hashApproved

    # -----------------------------------------------------------------------
    # Determine evidence path and provenance approval
    # -----------------------------------------------------------------------

    if ($signerApproved -and $hashApproved) {
        $outcome.evidence_path = 'signature_and_hash'
        $outcome.provenance_approved = $true
    }
    elseif ($hashApproved -and $allowHashFallback) {
        $outcome.evidence_path = 'hash_only'
        $outcome.provenance_approved = $true
    }
    else {
        # Neither signature+hash nor hash fallback available
        $reasons = @()
        if (-not $hashApproved) {
            $reasons += 'hash_not_approved'
        }
        if (-not $signerApproved -and -not $allowHashFallback) {
            $reasons += 'signature_required_but_not_valid'
        }
        $outcome.rejection_reasons += $reasons
        $outcome.provenance_approved = $false
    }

    $candidateOutcomes += $outcome
    $candidateIndex++
}

# ---------------------------------------------------------------------------
# Phase 8: Approval Logic + Write Report
# ---------------------------------------------------------------------------

$report.candidates = $candidateOutcomes

if ($candidateOutcomes.Count -eq 0) {
    $report.provenance_approved = $false
    $report.execution_supported = $false
    $report.rejection_reasons = @('no_candidates')
}
else {
    # Find candidates that are both provenance_approved and execution_supported
    $canExecute = @($candidateOutcomes | Where-Object { $_.provenance_approved -eq $true -and $_.execution_supported -eq $true })
    $provenanceApproved = @($candidateOutcomes | Where-Object { $_.provenance_approved -eq $true })

    if ($canExecute.Count -eq 1) {
        $winner = $canExecute[0]
        $report.provenance_approved = $true
        $report.execution_supported = $true
        $report.evidence_path = $winner.evidence_path
        $report.approved_candidate = $winner
    }
    elseif ($canExecute.Count -gt 1) {
        $report.provenance_approved = $false
        $report.execution_supported = $true
        $report.rejection_reasons = @('ambiguity')
    }
    elseif ($provenanceApproved.Count -eq 1) {
        $winner = $provenanceApproved[0]
        $report.provenance_approved = $true
        $report.execution_supported = $false
        $report.evidence_path = $winner.evidence_path
        $report.approved_candidate = $winner
    }
    elseif ($provenanceApproved.Count -gt 1) {
        $report.provenance_approved = $false
        $report.execution_supported = $false
        $report.rejection_reasons = @('ambiguity')
    }
    else {
        $report.provenance_approved = $false
        $report.execution_supported = $false
        $report.rejection_reasons = @('provenance_rejected')
    }
}

# Write report -- ALWAYS, regardless of outcome
$reportJson = $report | ConvertTo-Json -Depth 10 -Compress:$false
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($ReportPath, $reportJson, $utf8NoBom)

# ---------------------------------------------------------------------------
# Phase 9: Post-Import Invocation (Collection Mode Only)
# ---------------------------------------------------------------------------

if ($mode -eq 'collection' -and $report.provenance_approved -eq $true -and $report.execution_supported -eq $true -and $null -ne $postImportInvocation) {
    $approvedCandidate = $report.approved_candidate
    $stagedPsd1 = $approvedCandidate.staged_manifest_path

    # Import the staged module
    Import-Module -Name $stagedPsd1 -Force -ErrorAction Stop

    # Build invocation
    $commandName = $postImportInvocation.command_name
    $params = @{}

    if ($null -ne $postImportInvocation.named_args) {
        $namedArgs = $postImportInvocation.named_args
        if ($namedArgs -is [System.Management.Automation.PSCustomObject]) {
            $namedArgs.PSObject.Properties | ForEach-Object {
                $params[$_.Name] = $_.Value
            }
        }
    }

    if ($null -ne $postImportInvocation.switches) {
        foreach ($sw in @($postImportInvocation.switches)) {
            $params[$sw] = $true
        }
    }

    # Invoke the command
    & $commandName @params

    # Exit code from tool propagates as PS process exit code
    exit $LASTEXITCODE
}

exit 0
