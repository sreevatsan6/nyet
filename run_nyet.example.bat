@echo off
:: run_nyet.example.bat -- double-click launcher, no manual "Run as
:: Administrator" needed. Copy to run_nyet.local.bat if you want your own
:: (gitignored, same reasoning as config.local.bat -- see CONFIGURATION.md).
::
:: This script itself has no secrets in it -- everything real lives in
:: config.local.bat, which this script loads. Safe to keep checked in.

:: Re-launch elevated if not already admin -- `net session` silently fails
:: (non-zero errorlevel) unless the current process already has admin
:: rights, so this is a cheap admin check with no extra dependencies.
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: %~dp0 = this script's own directory, regardless of where it was
:: double-clicked from. The elevated relaunch above can otherwise start
:: in an unrelated working directory (System32), which would break every
:: relative path below.
cd /d "%~dp0"

if not exist "%~dp0config.local.bat" (
    echo [nyet] config.local.bat not found next to this script.
    echo [nyet] Copy config.example.bat to config.local.bat and fill in your values first.
    pause
    exit /b 1
)
call "%~dp0config.local.bat"

if not exist "%BLOCKLIST_PATH%" (
    echo [nyet] BLOCKLIST_PATH (%BLOCKLIST_PATH%) does not exist.
    echo [nyet] Create it -- see examples\blocklist.tsv and docs\CONFIGURATION.md.
    pause
    exit /b 1
)

:: ----------------------------------------------------------------------
:: Pre-launch sanity checks. Best-effort: if Python isn't available these
:: are skipped entirely rather than blocking the launch -- nyet.exe itself
:: doesn't need Python, only these convenience checks do.
:: ----------------------------------------------------------------------
where python >nul 2>&1
if %errorLevel% equ 0 (
    set PYTHON_CMD=python
) else (
    where python3 >nul 2>&1
    if %errorLevel% equ 0 (
        set PYTHON_CMD=python3
    )
)

if defined PYTHON_CMD (
    echo [nyet] Checking blocklist structural integrity...
    %PYTHON_CMD% "%~dp0scripts\check_tsv.py" "%BLOCKLIST_PATH%"
    if errorlevel 1 (
        echo [nyet] WARNING: check_tsv.py found structural issues above.
        echo [nyet] nyet.exe will still skip malformed lines and continue,
        echo [nyet] but you may want to fix these -- launching in 5s anyway.
        timeout /t 5 >nul
    )

    echo [nyet] Deduplicating blocklist...
    %PYTHON_CMD% "%~dp0scripts\dedup_tsv.py" "%BLOCKLIST_PATH%"
    if errorlevel 1 (
        echo [nyet] dedup_tsv.py failed -- continuing with the blocklist as-is.
    )
) else (
    echo [nyet] Python not found -- skipping blocklist sanity checks.
    echo [nyet] Install Python and these run automatically next time: check_tsv.py, dedup_tsv.py.
)

:: ----------------------------------------------------------------------
:: Launch. --background: fully detached, no console window, survives
:: closing this window. See docs\OPERATIONS.md for how to stop it later
:: (Ctrl+C won't reach a detached process -- use Task Manager/taskkill).
:: ----------------------------------------------------------------------
echo [nyet] Starting nyet.exe...
"%~dp0nyet.exe" --background
