[CmdletBinding()]
param(
    [ValidateRange(1, 1000)]
    [int] $Runs = 30,

    [ValidateRange(0, 10)]
    [int] $WarmupRuns = 1,

    [string] $Output = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$evaluationRoot = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $evaluationRoot "..")).Path
$python = Join-Path $projectRoot ".venv-didcomm\Scripts\python.exe"
$benchmark = Join-Path $evaluationRoot "benchmark-proofs.py"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "DIDSSO Python runtime not found. Run .\setup-runtime.ps1 first."
}

$benchmarkArguments = @(
    $benchmark,
    "--runs", $Runs,
    "--warmup-runs", $WarmupRuns
)
if (-not [string]::IsNullOrWhiteSpace($Output)) {
    $benchmarkArguments += @("--output", $Output)
}

Push-Location $projectRoot
try {
    & $python @benchmarkArguments
    $benchmarkExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

exit $benchmarkExitCode
