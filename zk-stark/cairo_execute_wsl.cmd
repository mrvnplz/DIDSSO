@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cairo_execute_wsl.ps1" %*
