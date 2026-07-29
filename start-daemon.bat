@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title NodeSignal - Windows peer

REM ===================================================================
REM  Runs THIS Windows machine as a NodeSignal peer, so it can message
REM  your Bitcoin node and receive replies.
REM
REM  NO npm install. NO internet needed. Node.js is the only prerequisite.
REM  Keep these four files together in one folder:
REM      nodesignald.js  noise.js  nodeps.js  nodesignal-demo.html
REM ===================================================================

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Node.js not found on PATH.
  echo   1. Install the LTS build from https://nodejs.org
  echo      ^(leave "Add to PATH" ticked^)
  echo   2. CLOSE this window completely and open a NEW one.
  echo      A window opened before the install still has the old PATH.
  echo.
  pause
  exit /b 1
)

for /f "tokens=*" %%v in ('node --version') do set NODEVER=%%v
echo   Node.js !NODEVER! found.

set MISSING=
if not exist "nodesignald.js"       set MISSING=!MISSING! nodesignald.js
if not exist "noise.js"             set MISSING=!MISSING! noise.js
if not exist "nodeps.js"            set MISSING=!MISSING! nodeps.js
if not exist "nodesignal-demo.html" set MISSING=!MISSING! nodesignal-demo.html
if not "!MISSING!"=="" (
  echo.
  echo   Missing file^(s^):!MISSING!
  echo   Folder: %cd%
  echo   Put all four files in this folder and run again.
  echo.
  pause
  exit /b 1
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
echo     netsh advfirewall firewall add rule name="NodeSignal 8788" dir=in action=allow protocol=TCP localport=8788
echo.

REM Impersonate a node identity so this machine appears on other operators'
REM maps as a classified peer. It has no Bitcoin node of its own, so this is
REM SIMULATED and is flagged as such to the peers that receive it.
REM If this laptop DOES run its own Bitcoin node (including a pruned one),
REM delete the --no-rpc and --impersonate lines to use the real node instead.
node nodesignald.js --no-rpc --nick !NICK! --web-port 8789 --peer-port 8788 ^
  --impersonate "/Satoshi:29.2.0/Knots:20251110+bip110-v0.1/UASF-BIP110:0.1/" ^
  --impersonate-height 959370

echo.
echo   Daemon stopped. If it exited immediately, the message above is the reason.
pause
