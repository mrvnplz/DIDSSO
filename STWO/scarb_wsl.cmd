@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scarb_wsl.ps1" %*
