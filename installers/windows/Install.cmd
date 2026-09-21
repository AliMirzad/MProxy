@echo off
rem Private Proxy - install the native runtime for the current user (no administrator rights needed).
rem Installs to %LOCALAPPDATA%\Programs\PrivateProxy and registers native messaging for
rem Chrome, Chromium, Brave and Edge. Nothing else is installed; no system settings are changed.
setlocal
cd /d "%~dp0"
rem Remove the "downloaded from the internet" mark from the extracted files (harmless if absent).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse | Unblock-File" >nul 2>&1
"%~dp0private-proxy-host.exe" install --interactive
