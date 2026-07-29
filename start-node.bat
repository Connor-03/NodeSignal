@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title NodeSignal - Bitcoin node

REM ===================================================================
REM  For a Windows machine that RUNS A BITCOIN NODE (Core or Knots),
REM  including a PRUNED node. Reads your node over RPC and shows its
REM  real peers on the map.
REM
REM  Pruned nodes are fully supported: NodeSignal only calls
REM  getpeerinfo, getnetworkinfo and getblockchaininfo. None of those
REM  need historical block data.
REM
REM  NO npm install. Node.js is the only prerequisite.
REM  Needs in this folder:
REM      nodesignald.js  noise.js  nodeps.js  nodesignal.html
REM
REM  If this machine has NO Bitcoin node, use start-daemon.bat instead.
REM ===================================================================

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Node.js not found on PATH.
  echo   1. Install the LTS build from https://nodejs.org
  echo      ^(leave "Add to PATH" ticked^)
  echo   2. CLOSE this window completely and open a NEW one.
  echo.
  pause
  exit /b 1
)
for /f "tokens=*" %%v in ('node --version') do set NODEVER=%%v
echo   Node.js !NODEVER! found.

set MISSING=
if not exist "nodesignald.js"  set MISSING=!MISSING! nodesignald.js
if not exist "noise.js"        set MISSING=!MISSING! noise.js
if not exist "nodeps.js"       set MISSING=!MISSING! nodeps.js
if not exist "nodesignal.html" set MISSING=!MISSING! nodesignal.html
if not "!MISSING!"=="" (
  echo.
  echo   Missing file^(s^):!MISSING!
  echo   Folder: %cd%
  echo.
  pause
  exit /b 1
)

set NICK=%~1
if "%NICK%"=="" set NICK=%COMPUTERNAME%

echo.
echo   ==============================================================
echo    NodeSignal starting as: !NICK!
echo    Interface:  http://localhost:8789
echo   ==============================================================
echo.
echo   RPC: the daemon looks for your cookie file and bitcoin.conf in
echo   the usual Windows locations, e.g.
echo     %%APPDATA%%\Bitcoin\.cookie
echo   If it cannot find them, add credentials to the line below:
echo     --rpc-user YOURUSER --rpc-pass YOURPASS
echo   or point at the file directly:
echo     --rpc-cookie "%%APPDATA%%\Bitcoin\.cookie"
echo.
echo   If Windows Firewall prompts, ALLOW it so peers can reach 8788.
echo.

node nodesignald.js --nick !NICK! --web-port 8789 --peer-port 8788 ^
  --rpc-cookie "%APPDATA%\Bitcoin\.cookie"

echo.
echo   Daemon stopped. If it exited immediately, the message above is the reason.
pause
