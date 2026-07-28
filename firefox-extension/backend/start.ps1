Set-Location $PSScriptRoot
$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
& $python (Join-Path $PSScriptRoot "server.py")
