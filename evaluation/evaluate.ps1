[CmdletBinding()]
param(
    [ValidateSet("all", "protocol", "proofs")]
    [string] $Suite = "all",

    [ValidateSet("all", "sso", "direct-access", "direct-refresh")]
    [string] $Scenario = "all",

    [ValidateRange(1, 1000)]
    [int] $Runs = 100,

    [ValidateRange(0, 10)]
    [int] $WarmupRuns = 1,

    [switch] $Headless
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$evaluationRoot = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $evaluationRoot "..")).Path
$evaluationPython = Join-Path $projectRoot ".venv-evaluation\Scripts\python.exe"
$didcommPython = Join-Path $projectRoot ".venv-didcomm\Scripts\python.exe"

if (($Suite -in @("all", "protocol")) -and -not (Test-Path -LiteralPath $evaluationPython -PathType Leaf)) {
    throw "Evaluation runtime not found. Run .\evaluation\setup-evaluation.ps1 first."
}
if (($Suite -in @("all", "proofs")) -and -not (Test-Path -LiteralPath $didcommPython -PathType Leaf)) {
    throw "DIDSSO Python runtime not found. Run .\setup-runtime.ps1 first."
}

Push-Location $projectRoot
try {
    if ($Suite -in @("all", "protocol")) {
        $protocolArguments = @(
            (Join-Path $evaluationRoot "benchmark-protocol.py"),
            "--scenario", $Scenario,
            "--runs", $Runs,
            "--warmup-runs", $WarmupRuns
        )
        if ($Headless) {
            $protocolArguments += "--headless"
        }
        & $evaluationPython @protocolArguments
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }

    if ($Suite -in @("all", "proofs")) {
        & $didcommPython (Join-Path $evaluationRoot "benchmark-proofs.py") `
            "--runs" $Runs `
            "--warmup-runs" $WarmupRuns
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
}
finally {
    Pop-Location
}
