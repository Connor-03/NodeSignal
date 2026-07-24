@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title NodeSignal - Windows peer

REM ===================================================================
REM  Runs THIS Windows machine as a NodeSignal peer, so it can message
REM  your Bitcoin node and receive replies.
REM
REM  Needs, in this same folder:  nodesignald.js  and  nodesignal.html
REM ===================================================================

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Node.js not found.
  echo   Install the LTS build from https://nodejs.org
  echo   Leave "Add to PATH" ticked, then close this window and re-run.
  echo.
  pause
  exit /b 1
)

if not exist "nodesignald.js" (
  echo   nodesignald.js not found in this folder:
  echo     %cd%
  pause
  exit /b 1
)
if not exist "nodesignal-demo.html" (
  echo   nodesignal-demo.html not found in this folder.
  pause
  exit /b 1
)

if not exist "node_modules\express" (
  echo   First run - installing dependencies ^(express, ws^)...
  echo.
  call npm install express ws --no-audit --no-fund
  if errorlevel 1 (
    echo.
    echo   npm install failed. Check your internet connection and re-run.
    pause
    exit /b 1
  )
  echo.
)

set NICK=%~1
if "%NICK%"=="" set NICK=%COMPUTERNAME%

echo.
echo   ==============================================================
echo    NodeSignal peer starting as: !NICK!
echo.
echo    This window IS the peer. Leave it open.
echo    Its interface:  http://localhost:8789
echo   ==============================================================
echo.
echo   If Windows Firewall prompts, ALLOW it - otherwise replies from
echo   your node cannot get back in. To allow it manually, run this
echo   once in an ADMIN PowerShell:
echo.
echo     netsh advfirewall firewall add rule name="NodeSignal 8788" ^
dir=in action=allow protocol=TCP localport=8788
echo.

REM Impersonate a node identity so this machine appears on other operators'
REM maps as a classified peer. It has no Bitcoin node of its own, so this is
REM SIMULATED and is flagged as such to the peers that receive it.
node nodesignald.js --no-rpc --nick !NICK! --web-port 8789 --peer-port 8788 ^
  --impersonate "/Satoshi:29.2.0/Knots:20251110+bip110-v0.1/UASF-BIP110:0.1/" ^
  --impersonate-height 959370

echo.
echo   Daemon stopped.
pause
