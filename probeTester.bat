@echo off
setlocal
cd /d "%~dp0"
title NodeSignal port probe

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js not found. Install the LTS build from https://nodejs.org
  pause
  exit /b 1
)

set /p HOSTADDR="Host or IP to test (e.g. 108.203.190.226): "
if "%HOSTADDR%"=="" (
  echo No host entered.
  pause
  exit /b 1
)

set /p PORTLIST="Ports to test [default: 8333 3333]: "
if "%PORTLIST%"=="" set PORTLIST=8333 3333

node probe.js %HOSTADDR% %PORTLIST%
pause
