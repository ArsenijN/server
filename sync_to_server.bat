@echo off
REM sync_to_server.bat — Windows launcher for sync_to_server.sh
REM
REM Requirements:
REM   Git for Windows (https://git-scm.com/download/win) — provides bash and ssh.
REM   rsync.exe in Git Bash's PATH. Two easy options:
REM     a) cwrsync standalone: https://itefix.net/cwrsync  → drop rsync.exe into
REM        C:\Program Files\Git\usr\bin\  (no install needed, just copy the file)
REM     b) WSL: run sync_to_server.sh directly inside WSL instead of this .bat
REM
REM Usage: double-click this file, or run from cmd / PowerShell:
REM   sync_to_server.bat
REM
REM Path note: this launcher converts the Windows path to a Unix path with
REM   cygpath so it works even when the repo is in a directory whose name
REM   contains spaces, apostrophes, or other shell-special characters.

setlocal EnableDelayedExpansion

REM ── 1. Locate Git Bash ───────────────────────────────────────────────────────
set "GIT_BASH="
for %%G in (
    "C:\Program Files\Git\bin\bash.exe"
    "C:\Program Files (x86)\Git\bin\bash.exe"
) do (
    if not defined GIT_BASH (
        if exist "%%~G" set "GIT_BASH=%%~G"
    )
)

REM Also check common Scoop and Winget install locations
if not defined GIT_BASH if exist "%LOCALAPPDATA%\Programs\Git\bin\bash.exe" (
    set "GIT_BASH=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
)

if not defined GIT_BASH (
    echo.
    echo ERROR: Git Bash not found.
    echo Install Git for Windows from https://git-scm.com/download/win
    echo then re-run this script.
    pause
    exit /b 1
)
echo Using Git Bash: %GIT_BASH%
echo.

REM ── 2. Check rsync is available inside Git Bash ───────────────────────────────
"%GIT_BASH%" --login -c "command -v rsync" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: rsync not found inside Git Bash.
    echo.
    echo  Quickest fix — download a single rsync.exe from cwrsync:
    echo    https://itefix.net/cwrsync
    echo  and copy rsync.exe into:
    echo    C:\Program Files\Git\usr\bin\
    echo.
    echo  Alternative: run sync_to_server.sh directly inside WSL.
    pause
    exit /b 1
)

REM ── 3. Convert the repo root path to a Unix path ─────────────────────────────
REM  %~dp0 is the Windows path of this .bat file's directory (with trailing \).
REM  We export it as WIN_SCRIPT_DIR so Git Bash can call cygpath to convert it
REM  properly — this handles spaces, apostrophes, and other special characters
REM  without any batch-level quoting gymnastics.
set "WIN_SCRIPT_DIR=%~dp0"

REM ── 4. Run the shell script ───────────────────────────────────────────────────
REM  Inside the bash -c string:
REM    $WIN_SCRIPT_DIR  — inherited from the environment above (Windows path)
REM    cygpath -u       — converts Windows backslash path → /c/... Unix path
REM    Double quotes around cygpath argument handle spaces; the env variable
REM    expansion is safe from shell quoting because it is in double-quotes.
"%GIT_BASH%" --login -c "cd \"$(cygpath -u \"$WIN_SCRIPT_DIR\")\" && bash sync_to_server.sh"

if %ERRORLEVEL% neq 0 (
    echo.
    echo Sync failed with exit code %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Sync complete.
pause
