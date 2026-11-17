@echo off
setlocal
chcp 65001 >nul
title win-ssh-setup
where node >nul 2>nul
if errorlevel 1 (
    echo [!] Node.js not found. Installing Node.js LTS via winget ...
    winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
    echo.
    echo [!] Please close this window and run run.cmd again.
    pause
    exit /b 1
)
node "%~dp0src\cli.js" %*
endlocal
