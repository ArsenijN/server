@echo off
REM sync_to_server.bat — Windows launcher for sync_to_server.sh
REM
REM Requirements:
REM   - Git for Windows (https://git-scm.com/download/win) — provides bash and ssh
REM   - rsync.exe in PATH. Two easy options:
REM       a) Install from https://itefix.net/cwrsync  (standalone, just drop in Git/usr/bin/)
REM       b) Enable WSL and run the .sh script directly inside it
REM
REM Usage: double-click this file, or run from cmd/PowerShell:
REM   sync_to_server.bat

REM Find Git Bash
set GIT_BASH=
for %%G in (
    "C:\Program Files\Git\bin\bash.exe"
    "C:\Program Files (x86)\Git\bin\bash.exe"
) do (
    if exist %%G (
        set GIT_BASH=%%G
        goto :found
    )
)

echo ERROR: Git Bash not found. Install Git for Windows from https://git-scm.com/download/win
pause
exit /b 1

:found
echo Using Git Bash: %GIT_BASH%
echo.

REM Check rsync is available inside Git Bash
%GIT_BASH% --login -c "command -v rsync" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: rsync not found inside Git Bash.
    echo   Download rsync.exe from https://itefix.net/cwrsync and place it in:
    echo   C:\Program Files\Git\usr\bin\
    pause
    exit /b 1
)

REM Run the shell script — --login ensures $HOME and PATH are set correctly
%GIT_BASH% --login -c "cd '%~dp0' && bash sync_to_server.sh"

if %ERRORLEVEL% neq 0 (
    echo.
    echo Sync failed with error code %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Done.
pause
