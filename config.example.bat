@echo off
REM ============================================================================
REM  nyet config template
REM ============================================================================
REM  Copy this file to config.local.bat (same directory) and fill in your real
REM  values there. config.local.bat is in .gitignore -- it never gets committed,
REM  so your real WireGuard IP, home LAN IP, and file paths stay local to this
REM  machine even though this template ships in the public repo.
REM
REM  Every value below is read by nyet.exe as an environment variable if the
REM  matching CLI arg is omitted (CLI arg always wins if you do pass one --
REM  see `nyet.exe --help` / README). The Python tools in scripts/ read
REM  BLOCKLIST_PATH the same way, so this file is the one place you edit
REM  instead of hunting through source for hardcoded paths.
REM
REM  Usage:  call config.local.bat
REM          nyet.exe
REM  (or see run_nyet.example.bat for a ready-made launcher using this file)
REM ============================================================================

REM WireGuard address of the Pi -- always reachable (home or away)
set WG_IP=192.0.2.1

REM Home-LAN address of the Pi -- faster, only reachable on the home network
set HOME_IP=198.51.100.2

REM Your hand-curated blocklist. learned.tsv/review.tsv are created
REM automatically in this SAME directory -- see docs/CONFIGURATION.md
set BLOCKLIST_PATH=lists\blocklist.tsv

REM Dense query log (appended to, not overwritten)
set LOG_PATH=nyet.log
