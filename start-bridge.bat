@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title NodeSignal bridge

echo ============================================
echo   NodeSignal bridge
echo ============================================
echo.

REM --- 1. Is Node.js installed and on PATH? ---------------------------------
where node >nul 2>nul
if errorlevel 1 (
  echo   Node.js was not found.
  echo.
  echo   Install the LTS build from https://nodejs.org
  echo   During setup, leave "Add to PATH" ticked.
  echo   Then close this window, reopen it, and run this file again.
  echo.
  pause
  exit /b 1
)

for /f "delims=" %%v in ('node --version') do set NODEVER=%%v
echo   Node.js !NODEVER! found.

REM --- 2. Is bridge.js sitting next to this launcher? -----------------------
if not exist "bridge.js" (
  echo.
  echo   bridge.js was not found in this folder:
  echo     %cd%
  echo.
  echo   Keep start-bridge.bat and bridge.js in the same folder.
  echo.
  pause
  exit /b 1
)

REM --- 3. Install the one dependency, if needed -----------------------------
if not exist "node_modules\ws" (
  echo   Installing the 'ws' dependency, one moment...
  echo.
  call npm install ws --no-audit --no-fund
  if errorlevel 1 (
    echo.
    echo   npm install failed. Check your internet connection, then try again.
    echo.
    pause
    exit /b 1
  )
  echo.
)

REM --- 4. Run it ------------------------------------------------------------
echo   Starting bridge. Leave this window OPEN while you use NodeSignal.
echo   Press Ctrl+C to stop it.
echo.
echo --------------------------------------------
node bridge.js

echo --------------------------------------------
echo.
echo   Bridge stopped.
pause
