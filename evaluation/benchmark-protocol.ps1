[CmdletBinding()]
param(
    [ValidateSet("all", "sso", "direct-access", "direct-refresh")]
    [string] $Scenario = "all",

    [ValidateRange(1, 1000)]
    [int] $Runs = 30,

    [ValidateRange(0, 10)]
    [int] $WarmupRuns = 1,

    [ValidateRange(1, 3600)]
    [int] $Timeout = 300,

    [switch] $Headless,

    [string] $Output = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$evaluationRoot = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $evaluationRoot "..")).Path
$python = Join-Path $projectRoot ".venv-evaluation\Scripts\python.exe"
$benchmark = Join-Path $evaluationRoot "benchmark-protocol.py"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Evaluation runtime not found. Run .\evaluation\setup-evaluation.ps1 first."
}

$benchmarkArguments = @(
    $benchmark,
    "--scenario", $Scenario,
    "--runs", $Runs,
    "--warmup-runs", $WarmupRuns,
    "--timeout", $Timeout
)
if ($Headless) {
    $benchmarkArguments += "--headless"
}
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
