[CmdletBinding()]
param(
    [string] $PythonLauncher = "py",
    [string] $PythonVersion = "3.11"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$environmentRoot = Join-Path $projectRoot ".venv-didcomm"
$pluginEnvironmentRoot = Join-Path $projectRoot "firefox-extension\.venv"
$pythonExecutable = Join-Path $environmentRoot "Scripts\python.exe"
$pluginPythonExecutable = Join-Path $pluginEnvironmentRoot "Scripts\python.exe"
$runtimeScripts = Join-Path $environmentRoot "Scripts"
$pluginRuntimeScripts = Join-Path $pluginEnvironmentRoot "Scripts"
$idpRequirements = Join-Path $projectRoot "IdP\didcomm-backend\requirements.txt"
$rpRequirements = Join-Path $projectRoot "RP\didcomm-backend\requirements.txt"
$pluginRequirements = Join-Path $projectRoot "firefox-extension\backend\requirements.txt"
$commonRequirements = Join-Path $projectRoot "requirements-didcomm.txt"
$buildBackend = "uv-build>=0.8.4,<0.9.0"

$didPeerRequirement = Get-Content -LiteralPath $commonRequirements |
    Where-Object { $_ -match '^did-peer-4\s*@' } |
    Select-Object -First 1
$didPeerRevisionMatch = [regex]::Match($didPeerRequirement, '@([0-9a-fA-F]{40})$')
if (-not $didPeerRevisionMatch.Success) {
    throw "requirements-didcomm.txt must pin did-peer-4 to a full Git commit"
}
$didPeerRevision = $didPeerRevisionMatch.Groups[1].Value

function Install-PinnedDidPeerIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RuntimePython,
        [Parameter(Mandatory = $true)]
        [string] $RuntimeName
    )

    [string] $installedRevision = & $RuntimePython -c "import importlib.metadata as m, json; raw = m.distribution('did-peer-4').read_text('direct_url.json'); info = json.loads(raw) if raw else {}; print(info.get('vcs_info', {}).get('commit_id', ''))"
    if ($LASTEXITCODE -ne 0) {
        $installedRevision = ""
    }
    $installedRevision = $installedRevision.Trim()
    if ($installedRevision -eq $didPeerRevision) {
        return
    }

    Write-Host "Updating did-peer-4 in the $RuntimeName runtime to commit $didPeerRevision..."
    & $RuntimePython -m pip install --use-feature=truststore --no-build-isolation --disable-pip-version-check --force-reinstall --no-deps $didPeerRequirement
    if ($LASTEXITCODE -ne 0) {
        throw "Could not install the pinned did-peer-4 revision in the $RuntimeName runtime"
    }
}

if (-not (Test-Path -LiteralPath $pythonExecutable -PathType Leaf)) {
    if (-not (Get-Command $PythonLauncher -ErrorAction SilentlyContinue)) {
        throw "Python launcher '$PythonLauncher' was not found"
    }

    Write-Host "Creating the shared IdP/RP DIDComm runtime with Python $PythonVersion..."
    if ([System.IO.Path]::GetFileNameWithoutExtension($PythonLauncher) -eq "py") {
        & $PythonLauncher "-$PythonVersion" -m venv $environmentRoot
    }
    else {
        & $PythonLauncher -m venv $environmentRoot
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the DIDComm runtime environment"
    }
}

if (-not (Test-Path -LiteralPath $pluginPythonExecutable -PathType Leaf)) {
    if (-not (Get-Command $PythonLauncher -ErrorAction SilentlyContinue)) {
        throw "Python launcher '$PythonLauncher' was not found"
    }

    Write-Host "Creating the separate Firefox backend runtime with Python $PythonVersion..."
    if ([System.IO.Path]::GetFileNameWithoutExtension($PythonLauncher) -eq "py") {
        & $PythonLauncher "-$PythonVersion" -m venv $pluginEnvironmentRoot
    }
    else {
        & $PythonLauncher -m venv $pluginEnvironmentRoot
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the Firefox backend runtime environment"
    }
}

$env:PATH = "$runtimeScripts;$env:PATH"

Write-Host "Installing the shared IdP/RP build backend..."
& $pythonExecutable -m pip install --use-feature=truststore --disable-pip-version-check $buildBackend
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the shared DIDComm build backend"
}

Write-Host "Installing the shared IdP/RP dependencies..."
& $pythonExecutable -m pip install --use-feature=truststore --no-build-isolation --disable-pip-version-check --requirement $idpRequirements --requirement $rpRequirements
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the DIDComm runtime dependencies"
}

Install-PinnedDidPeerIfNeeded -RuntimePython $pythonExecutable -RuntimeName "shared IdP/RP"

& $pythonExecutable -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The DIDComm runtime has incompatible dependencies"
}

& $pythonExecutable -c "import argon2, cryptography, didcomm; from did_peer_4.input_doc import Multikey; print('DIDComm runtime is ready')"
if ($LASTEXITCODE -ne 0) {
    throw "The DIDComm runtime dependency check failed"
}

$env:PATH = "$pluginRuntimeScripts;$env:PATH"

Write-Host "Installing the Firefox backend build backend..."
& $pluginPythonExecutable -m pip install --use-feature=truststore --disable-pip-version-check $buildBackend
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the Firefox backend build backend"
}

Write-Host "Installing the Firefox backend dependencies..."
& $pluginPythonExecutable -m pip install --use-feature=truststore --no-build-isolation --disable-pip-version-check --requirement $pluginRequirements
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the Firefox backend dependencies"
}

Install-PinnedDidPeerIfNeeded -RuntimePython $pluginPythonExecutable -RuntimeName "Firefox backend"

& $pluginPythonExecutable -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The Firefox backend runtime has incompatible dependencies"
}

& $pluginPythonExecutable -c "import cryptography, didcomm; from did_peer_4.input_doc import KeySpec, input_doc_from_keys_and_services; print('Firefox backend runtime is ready')"
if ($LASTEXITCODE -ne 0) {
    throw "The Firefox backend runtime dependency check failed"
}

Write-Host "Shared IdP/RP Python: $pythonExecutable"
Write-Host "Firefox backend Python: $pluginPythonExecutable"
