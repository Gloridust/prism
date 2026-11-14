@echo off
rem Double-click launcher for Windows (work-from-home staff).
rem Put this file next to prism-client-windows-amd64.exe and client.json.
cd /d "%~dp0"
start "" "http://127.0.0.1:9797"
prism-client-windows-amd64.exe -c client.json
pause
