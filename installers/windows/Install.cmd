@echo off
rem Private Proxy - install the native runtime for the current user (no administrator rights needed).
rem Installs to %LOCALAPPDATA%\Programs\PrivateProxy and registers native messaging for
rem Chrome, Chromium, Brave and Edge. Nothing else is installed; no system settings are changed.
setlocal
cd /d "%~dp0"
rem Remove the "downloaded from the internet" mark from the extracted files (harmless if absent).
rem Full path: a "powershell.exe" or ".bat" planted next to this script must never run instead.
rem The folder is passed in an environment variable, never inside the command text, so a folder
rem name containing quotes or ";" cannot inject PowerShell code.
set "PP_INSTALL_DIR=%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath $env:PP_INSTALL_DIR -Recurse | Unblock-File" >nul 2>&1
"%~dp0private-proxy-host.exe" install --interactive
