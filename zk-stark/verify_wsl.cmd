@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stwo_wsl.ps1" verify %*
