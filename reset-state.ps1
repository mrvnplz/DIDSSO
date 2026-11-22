[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $ValidateOnly,
    [string] $IdpDataDir,
    [string] $RpDataDir,
    [string] $WalletDataDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$pluginRoot = Join-Path $projectRoot "firefox-extension"

# A single inherited override does not identify the three participants' stores.
if (-not [string]::IsNullOrWhiteSpace($env:DIDSSO_DATA_DIR)) {
    foreach ($parameter in @("IdpDataDir", "RpDataDir", "WalletDataDir")) {
        if (-not $PSBoundParameters.ContainsKey($parameter)) {
            throw "DIDSSO_DATA_DIR is set. Specify -IdpDataDir, -RpDataDir and -WalletDataDir explicitly; no files were changed."
        }
    }
}

function Resolve-DataDirectory {
    param([string] $Path, [string] $DefaultPath)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = $DefaultPath
    }
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $Path = Join-Path $projectRoot $Path
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\', '/') -eq $volumeRoot.TrimEnd('\', '/')) {
        throw "A drive root cannot be used as a reset data directory: $fullPath"
    }
    $fullPath = $fullPath.TrimEnd('\', '/')
    $prefix = $fullPath + [System.IO.Path]::DirectorySeparatorChar
    if ($fullPath -eq $projectRoot -or $projectRoot.StartsWith(
        $prefix, [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The project root or its ancestors cannot be reset data directories: $fullPath"
    }
    foreach ($broadDirectory in @(
        $env:USERPROFILE, $env:SystemRoot, $env:ProgramFiles, $env:ProgramData,
        [System.IO.Path]::GetTempPath()
    )) {
        if (-not [string]::IsNullOrWhiteSpace($broadDirectory) -and
            $fullPath -eq [System.IO.Path]::GetFullPath($broadDirectory).TrimEnd('\', '/')) {
            throw "A broad system/user directory cannot be used for reset: $fullPath"
        }
    }
    return $fullPath
}

foreach ($parameter in @("IdpDataDir", "RpDataDir", "WalletDataDir")) {
    if ($PSBoundParameters.ContainsKey($parameter) -and
        [string]::IsNullOrWhiteSpace($PSBoundParameters[$parameter])) {
        throw "-$parameter must not be empty."
    }
}
$idpRoot = Resolve-DataDirectory $IdpDataDir (Join-Path $projectRoot "IdP\data")
$rpRoot = Resolve-DataDirectory $RpDataDir (Join-Path $projectRoot "RP\data")
$walletRoot = Resolve-DataDirectory $WalletDataDir (Join-Path $pluginRoot "data")
$dataRoots = @($idpRoot, $rpRoot, $walletRoot)
for ($i = 0; $i -lt $dataRoots.Count; $i++) {
    for ($j = $i + 1; $j -lt $dataRoots.Count; $j++) {
        $left = $dataRoots[$i] + [System.IO.Path]::DirectorySeparatorChar
        $right = $dataRoots[$j] + [System.IO.Path]::DirectorySeparatorChar
        if ($left.StartsWith($right, [System.StringComparison]::OrdinalIgnoreCase) -or
            $right.StartsWith($left, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Participant data directories must be separate and must not overlap: $left / $right"
        }
    }
}

$requiredDirectories = @(
    (Join-Path $projectRoot "IdP"),
    (Join-Path $projectRoot "RP"),
    $pluginRoot,
    (Join-Path $pluginRoot "backend")
)
foreach ($directory in $requiredDirectories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Required project directory not found: $directory"
    }
}

$requiredPluginFiles = @(
    (Join-Path $pluginRoot "manifest.json"),
    (Join-Path $pluginRoot "backend\server.py")
)
foreach ($file in $requiredPluginFiles) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "The DIDSSO Firefox extension is incomplete: $file"
    }
}

$stateFiles = @(
    [pscustomobject]@{ Path = Join-Path $idpRoot "sso_token_grants.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "sessions.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "users.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "sso_user_did_links.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "oidc_codes.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "registered_rps.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "pending_rp_requests.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $rpRoot "idp_registrations.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $rpRoot "token_grants.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $rpRoot "user_accounts.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $rpRoot "sso_sessions.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $idpRoot "wallet.json"; Content = '{"dids":[]}' },
    [pscustomobject]@{ Path = Join-Path $rpRoot "wallet.json"; Content = '{"dids":[]}' },
    [pscustomobject]@{ Path = Join-Path $walletRoot "wallet.json"; Content = '{"dids":[]}' },
    [pscustomobject]@{ Path = Join-Path $walletRoot "selected_did.json"; Content = "{}" },
    [pscustomobject]@{ Path = Join-Path $walletRoot "sso_auth_request.json"; Content = "{}" },
    [pscustomobject]@{ Path = Join-Path $walletRoot "sso_result.json"; Content = "{}" },
    # Null content means removal, not an empty JSON key/configuration file.
    # Signing keys are regenerated on demand; absent scope configuration uses
    # the RP's built-in defaults. Clear the legacy scope path as well so that
    # the backend cannot restore it after resetting the current configuration.
    [pscustomobject]@{ Path = Join-Path $idpRoot "registration_signing_key.json"; Content = $null },
    [pscustomobject]@{ Path = Join-Path $idpRoot "registration_signing_key_risc0_p256.json"; Content = $null },
    [pscustomobject]@{ Path = Join-Path $rpRoot "authorization_config.json"; Content = $null },
    [pscustomobject]@{ Path = Join-Path $rpRoot "data\authorization_config.json"; Content = $null }
)

foreach ($stateFile in $stateFiles) {
    $fullPath = [System.IO.Path]::GetFullPath($stateFile.Path)
    $rootedTarget = $false
    foreach ($dataRoot in $dataRoots) {
        if ($fullPath.StartsWith(
            $dataRoot + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            $rootedTarget = $true
        }
    }
    if (-not $rootedTarget) {
        throw "Reset target leaves the configured data directories: $fullPath"
    }
    # Reject links/junctions and invalid parent paths before any file is changed.
    $cursor = $fullPath
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Reset targets must not traverse links/junctions: $cursor"
            }
            if ($cursor -eq $fullPath -and $item.PSIsContainer) {
                throw "Reset target is a directory, not a JSON file: $cursor"
            }
            if ($cursor -ne $fullPath -and -not $item.PSIsContainer) {
                throw "Reset target parent is not a directory: $cursor"
            }
        }
        $cursor = Split-Path -Parent $cursor
    }
    if ($null -ne $stateFile.Content) {
        $stateFile.Content | ConvertFrom-Json | Out-Null
    }
}

Write-Warning "Local file reset only: Docker volumes and Firefox extension storage are not reset."
Write-Warning "Stop all IdP/RP web and protocol backends and the wallet backend BEFORE resetting."

if ($ValidateOnly) {
    $stateFiles |
        Select-Object @{ Name = "Exists"; Expression = { Test-Path -LiteralPath $_.Path } },
            @{ Name = "Action"; Expression = { if ($null -eq $_.Content) { "Remove" } else { "Reset" } } }, Path |
        Format-Table -AutoSize
    Write-Host "Validated $($stateFiles.Count) reset targets; no files were changed."
    return
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$writtenFiles = [System.Collections.Generic.List[string]]::new()
$removedFiles = [System.Collections.Generic.List[string]]::new()
foreach ($stateFile in $stateFiles) {
    $removeFile = $null -eq $stateFile.Content
    $operation = if ($removeFile) { "Remove generated key/configuration file" } else { "Reset JSON state" }
    if (-not $PSCmdlet.ShouldProcess($stateFile.Path, $operation)) {
        continue
    }

    if ($removeFile) {
        if (Test-Path -LiteralPath $stateFile.Path -PathType Leaf) {
            Remove-Item -LiteralPath $stateFile.Path -Force
            $removedFiles.Add($stateFile.Path)
        }
        continue
    }

    $directory = Split-Path -Parent $stateFile.Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporary = Join-Path (
        Split-Path -Parent $stateFile.Path
    ) (".{0}.{1}.tmp" -f (Split-Path -Leaf $stateFile.Path), [guid]::NewGuid().ToString("N"))
    try {
        [System.IO.File]::WriteAllText($temporary, $stateFile.Content, $utf8NoBom)
        [System.IO.File]::ReadAllText($temporary, $utf8NoBom) |
            ConvertFrom-Json |
            Out-Null
        Move-Item -LiteralPath $temporary -Destination $stateFile.Path -Force
        $writtenFiles.Add($stateFile.Path)
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

$utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
foreach ($file in $writtenFiles) {
    [System.IO.File]::ReadAllText($file, $utf8Strict) | ConvertFrom-Json | Out-Null
}
foreach ($file in $removedFiles) {
    if (Test-Path -LiteralPath $file) {
        throw "Reset file was not removed: $file"
    }
}

if ($writtenFiles.Count -eq 0 -and $removedFiles.Count -eq 0) {
    Write-Host "No state files were changed."
    return
}

Write-Host "Reset $($writtenFiles.Count) state files successfully."
Write-Host "Removed $($removedFiles.Count) generated key/configuration files."
Write-Host "Restart IdP, RP and firefox-extension/backend before testing again."
Write-Host "Clear stale Firefox extension state separately before selecting a newly created DID."
Write-Host "Missing registration-proof signing keys are regenerated on demand."
Write-Host "Missing RP scope configuration uses the profile/email defaults."
