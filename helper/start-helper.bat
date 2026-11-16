@echo off
REM Req2Route: start the local helper and the team echo endpoint on Windows.
REM Double-click this file, or run it from a terminal. Close the windows to stop.
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  where py >nul 2>nul
  if errorlevel 1 (
    echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
  )
  set PY=py -3
) else (
  set PY=python
)

if not exist config.json copy config.example.json config.json >nul

echo Starting echo server on 127.0.0.1:9000 (TCP + UDP) in a new window...
start "Req2Route echo server" %PY% echo_server.py --port 9000

echo Starting Req2Route helper on http://127.0.0.1:8765 ...
echo Windows may ask to allow Python through the firewall: "Private networks" is enough.
%PY% server.py
pause
