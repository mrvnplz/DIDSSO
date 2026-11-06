[CmdletBinding()]
param(
    [switch] $Evaluation
)

Set-Location $PSScriptRoot
if ($Evaluation) {
    $env:DIDSSO_EVALUATION_ENABLED = "1"
}
else {
    Remove-Item Env:DIDSSO_EVALUATION_ENABLED -ErrorAction SilentlyContinue
}
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$zkStark = (Resolve-Path (Join-Path $PSScriptRoot "..\..\zk-stark")).Path
$zkRisc0 = (Resolve-Path (Join-Path $PSScriptRoot "..\..\zk-risc0")).Path
$env:AUTHLIB_JOSE_MAX_CIPHERTEXT_SIZE = "16777216"
$env:STWO_RUN_AND_PROVE = Join-Path $zkStark "run_and_prove_wsl.cmd"
$env:STWO_VERIFY = Join-Path $zkStark "verify_wsl.cmd"
$env:STWO_SCARB = Join-Path $zkStark "scarb_wsl.cmd"
$env:STWO_CAIRO_EXECUTE = Join-Path $zkStark "cairo_execute_wsl.cmd"
$env:STWO_CHANNEL_HASH = "blake2s"
$env:STWO_ALLOW_NATIVE_WINDOWS = "0"
$env:RISC0_CREDENTIAL_CLI = Join-Path $zkRisc0 "risc0_wsl.cmd"
if ([string]::IsNullOrWhiteSpace($env:DIDSSO_PROOF_BACKEND)) {
    $env:DIDSSO_PROOF_BACKEND = "risc0"
}
$env:DIDSSO_PROOF_BACKEND = $env:DIDSSO_PROOF_BACKEND.ToLowerInvariant()
if ($env:DIDSSO_PROOF_BACKEND -notin @("risc0", "stwo")) {
    throw "DIDSSO_PROOF_BACKEND must be either 'risc0' or 'stwo'"
}
Remove-Item Env:RISC0_DEV_MODE -ErrorAction SilentlyContinue
Remove-Item Env:STWO_PARAMS_JSON -ErrorAction SilentlyContinue
Write-Host "Registration proof: $($env:DIDSSO_PROOF_BACKEND.ToUpperInvariant())"
Write-Host "Authlib JWE ciphertext limit: $env:AUTHLIB_JOSE_MAX_CIPHERTEXT_SIZE characters"
$pythonCandidate = if ([string]::IsNullOrWhiteSpace($env:DIDSSO_PYTHON)) {
    Join-Path $workspaceRoot ".venv-didcomm\Scripts\python.exe"
}
else {
    $env:DIDSSO_PYTHON
}
if (-not (Test-Path -LiteralPath $pythonCandidate -PathType Leaf)) {
    throw "DIDComm runtime not found at '$pythonCandidate'. Run .\setup-runtime.ps1 from the DIDSSO root or set DIDSSO_PYTHON."
}
$pythonExecutable = (Resolve-Path -LiteralPath $pythonCandidate).Path
& $pythonExecutable -u (Join-Path $PSScriptRoot "server.py")
