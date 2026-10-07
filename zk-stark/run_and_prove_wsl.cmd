@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stwo_wsl.ps1" run_and_prove %*
