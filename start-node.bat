@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title NodeSignal - Bitcoin node

REM ===================================================================
REM  Manual launcher, from a copy of the source. Most people should use
REM  NodeSignal-Setup-windows-x64.exe instead (see WindowsInstallGuide.txt),
REM  which needs no Node.js install and starts NodeSignal at sign-in.
REM
REM  For a Windows machine that RUNS A BITCOIN NODE (Core or Knots),
REM  including a PRUNED node. Reads your node over RPC and shows its
REM  real peers on the map. NodeSignal requires a Bitcoin node.
REM
REM  Pruned nodes are fully supported: NodeSignal only calls
REM  getpeerinfo, getnetworkinfo and getblockchaininfo. None of those
REM  need historical block data.
REM
REM  NO npm install. Node.js is the only prerequisite. Run it from the
REM  repository folder: the program files are listed in
REM  packaging\files.json and checked below.
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
for /f "tokens=*" %%m in ('node setup-core.js --check-files . 2^>^&1') do set MISSING=%%m
if not "!MISSING!"=="" (
  echo.
  echo   Missing file^(s^): !MISSING!
  echo   Folder: %cd%
  echo   Run this from a complete copy of the repository.
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
echo   If your node keeps its data elsewhere, point at the file on the
echo   line below:
echo     --rpc-cookie "D:\Bitcoin\.cookie"
echo   For a username and password, use install-windows.bat instead: it
echo   keeps them in a locked config file, never on a command line.
echo.
echo   If Windows Firewall prompts, ALLOW it so peers can reach 8788.
echo.

node nodesignald.js --nick "!NICK!" --web-port 8789 --peer-port 8788

echo.
echo   Daemon stopped. If it exited immediately, the message above is the reason.
pause
