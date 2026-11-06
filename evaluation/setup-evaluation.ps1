[CmdletBinding()]
param(
    [string] $PythonLauncher = "py",
    [string] $PythonVersion = "3.11"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$evaluationRoot = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $evaluationRoot "..")).Path
$environmentRoot = Join-Path $projectRoot ".venv-evaluation"
$python = Join-Path $environmentRoot "Scripts\python.exe"
$requirements = Join-Path $evaluationRoot "requirements-evaluation.txt"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    if (-not (Get-Command $PythonLauncher -ErrorAction SilentlyContinue)) {
        throw "Python launcher '$PythonLauncher' was not found"
    }

    Write-Host "Creating the isolated evaluation runtime with Python $PythonVersion..."
    if ([System.IO.Path]::GetFileNameWithoutExtension($PythonLauncher) -eq "py") {
        & $PythonLauncher "-$PythonVersion" -m venv $environmentRoot
    }
    else {
        & $PythonLauncher -m venv $environmentRoot
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the evaluation runtime environment"
    }
}

& $python -m pip install `
    --use-feature=truststore `
    --disable-pip-version-check `
    --requirement $requirements
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the evaluation dependencies"
}

& $python -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The evaluation runtime has incompatible dependencies"
}

& $python -c "import selenium; print(f'Selenium {selenium.__version__} is ready')"
if ($LASTEXITCODE -ne 0) {
    throw "The Selenium installation check failed"
}

Write-Host "Evaluation runtime: $python"
