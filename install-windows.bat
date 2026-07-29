@echo off
setlocal
cd /d "%~dp0"
title NodeSignal Setup

echo.
echo   Starting NodeSignal setup...
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo   ============================================================
  echo    Node.js is required and was not found.
  echo.
  echo    1. Download the LTS version from  https://nodejs.org
  echo    2. Run the installer, leaving "Add to PATH" ticked.
  echo    3. CLOSE this window completely, open a NEW one, and run
  echo       install-windows.bat again.
  echo.
  echo    A window opened before Node.js was installed still has the
  echo    old PATH and will not find it.
  echo   ============================================================
  echo.
  pause
  exit /b 1
)

if not exist "install.js" (
  echo   install.js not found in this folder:
  echo     %cd%
  echo   Keep every NodeSignal file together and run this again.
  pause
  exit /b 1
)

node install.js
set RC=%ERRORLEVEL%

echo.
if not "%RC%"=="0" (
  echo   Setup did not finish. The message above explains why.
)
pause
exit /b %RC%
