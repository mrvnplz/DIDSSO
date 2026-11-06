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
$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
& $python (Join-Path $PSScriptRoot "server.py")
