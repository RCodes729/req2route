@echo off
REM Req2Route: start the local helper and the team echo endpoint on Windows.
REM Double-click this file, or run it from a terminal. Close the windows to stop.
cd /d "%~dp0"

REM Find a real Python 3.10+. "where python" is not enough: on a fresh Windows install it finds
REM the Microsoft Store placeholder (WindowsApps\python.exe), which exists but cannot run scripts.
set "PY="
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PY=python"
if not defined PY py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PY=py -3"
if not defined PY (
  echo Python 3.10 or newer was not found.
  echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH" during setup.
  echo If typing "python" opens the Microsoft Store, that is only a placeholder, not a real install.
  pause
  exit /b 1
)
echo Using: %PY%

if not exist config.json copy config.example.json config.json >nul

echo Starting echo server on 127.0.0.1:9000 (TCP + UDP) in a new window...
start "Req2Route echo server" %PY% echo_server.py --port 9000

echo Starting Req2Route helper on http://127.0.0.1:8765 ...
echo Windows may ask to allow Python through the firewall: "Private networks" is enough.
%PY% server.py
pause
