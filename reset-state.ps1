[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$projectPrefix = $projectRoot + [System.IO.Path]::DirectorySeparatorChar
$pluginRoot = Join-Path $projectRoot "firefox-extension"

$requiredDirectories = @(
    (Join-Path $projectRoot "IdP"),
    (Join-Path $projectRoot "RP"),
    $pluginRoot,
    (Join-Path $pluginRoot "backend"),
    (Join-Path $pluginRoot "data")
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
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\sso_token_grants.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\sessions.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\users.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\sso_user_did_links.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\oidc_codes.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\registered_rps.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\pending_rp_requests.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "RP\idp_registrations.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "RP\token_grants.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "RP\user_accounts.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "RP\sso_sessions.json"; Content = "[]" },
    [pscustomobject]@{ Path = Join-Path $projectRoot "IdP\didcomm-backend\wallet.json"; Content = '{"dids":[]}' },
    [pscustomobject]@{ Path = Join-Path $projectRoot "RP\didcomm-backend\wallet.json"; Content = '{"dids":[]}' },
    [pscustomobject]@{ Path = Join-Path $pluginRoot "data\wallet.json"; Content = '{"dids":[]}' },
    [pscustomobject]@{ Path = Join-Path $pluginRoot "data\selected_did.json"; Content = "{}" },
    [pscustomobject]@{ Path = Join-Path $pluginRoot "data\sso_auth_request.json"; Content = "{}" },
    [pscustomobject]@{ Path = Join-Path $pluginRoot "data\sso_result.json"; Content = "{}" }
)

foreach ($stateFile in $stateFiles) {
    $fullPath = [System.IO.Path]::GetFullPath($stateFile.Path)
    if (-not $fullPath.StartsWith(
        $projectPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Reset target leaves the DIDSSO directory: $fullPath"
    }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $fullPath) -PathType Container)) {
        throw "Reset target directory not found: $fullPath"
    }
    $stateFile.Content | ConvertFrom-Json | Out-Null
}

if ($ValidateOnly) {
    $stateFiles |
        Select-Object @{ Name = "Exists"; Expression = { Test-Path -LiteralPath $_.Path } }, Path |
        Format-Table -AutoSize
    Write-Host "Validated $($stateFiles.Count) reset targets; no files were changed."
    return
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$writtenFiles = [System.Collections.Generic.List[string]]::new()
foreach ($stateFile in $stateFiles) {
    if (-not $PSCmdlet.ShouldProcess($stateFile.Path, "Reset JSON state")) {
        continue
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

if ($writtenFiles.Count -eq 0) {
    Write-Host "No state files were changed."
    return
}

Write-Host "Reset $($writtenFiles.Count) state files successfully."
Write-Host "Restart IdP, RP and firefox-extension/backend before testing again."
