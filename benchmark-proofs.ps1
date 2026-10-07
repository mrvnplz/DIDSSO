[CmdletBinding()]
param(
    [ValidateSet("all", "stwo", "risc0")]
    [string] $Backend = "all",

    [ValidateRange(1, 100)]
    [int] $Runs = 3,

    [string] $Output = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$python = Join-Path $projectRoot ".venv-didcomm\Scripts\python.exe"
$benchmark = Join-Path $projectRoot "benchmark-proofs.py"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "DIDSSO Python runtime not found. Run .\setup-runtime.ps1 first."
}

$benchmarkArguments = @(
    $benchmark,
    "--backend", $Backend,
    "--runs", $Runs
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
