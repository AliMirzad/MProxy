@echo off
rem Private Proxy - remove the native runtime and its browser registration.
rem You will be asked whether imported servers and saved credentials should be deleted too.
setlocal
"%~dp0private-proxy-host.exe" uninstall --interactive
