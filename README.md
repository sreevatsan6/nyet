# Nyet — DNS Proxy & Sinkhole (Windows only)

Intercepts local DNS queries (UDP 53), checks them against a radix-tree blocklist plus advisory heuristics, sinkholes known-bad domains, and forwards everything else to whichever upstream (WireGuard or home LAN) last proved reachable. IOCP + worker-thread pool. Non-blocked answers get cached locally after their first real resolution, so a repeat query for the same domain is answered straight from memory instead of paying the full round-trip through your upstream resolver every time — see [`DESIGN.md`](docs/DESIGN.md#answer-cache-answer_cachec).

Windows-only. No Linux/macOS support, no plans to add it — this relies on Winsock/IOCP/WinHTTP throughout.

**Further reading**, moved out of this file to keep it skimmable:
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — what to set before you build/run, TSV format, CLI args/env vars
- [`docs/DESIGN.md`](docs/DESIGN.md) — how domain decisions get made, heuristics internals, known limitations
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — debug output, log format, DNS setup, troubleshooting, emergency recovery
- [`docs/SCRIPTS.md`](docs/SCRIPTS.md) — every tool in `scripts/`, what it does, how to use it

> This repo ships as a template, not a ready-to-run binary — there's no prebuilt `nyet.exe`, no blocklist, and nothing points at real infrastructure. See [`CONFIGURATION.md`](docs/CONFIGURATION.md#what-to-customize-before-you-compilerun) for the exact checklist of what to fill in first.

---

## Building

Requires `gcc` via [MSYS2](https://www.msys2.org/) (mingw-w64) and GNU Make. Other toolchains (MSVC, plain MinGW, CMake) may need different flags — untested.

```powershell
make          # daemon build: no console window, for running detached/background
make debug    # console build: live [heur] lines + shutdown summary print to stdout
make clean    # remove nyet.exe
```

`heuristics.c`/`heuristics.h` must sit in `src/` alongside `nyet.c` — `heuristics.c` is pulled in via `#include` inside `nyet.c`, not compiled separately. See the `Makefile` if you need to hand-roll the `gcc` invocation instead (e.g. no `make` available); it's a direct translation of the two targets above.

---

## Usage

> **⚠️ Before running anything:** copy `config.example.bat` to `config.local.bat` and fill in your real `WG_IP`/`HOME_IP`/`BLOCKLIST_PATH`/`LOG_PATH` — see [`CONFIGURATION.md`](docs/CONFIGURATION.md) for the full checklist. Without real values, nyet has no real upstream to forward to: every allowed or unmatched query effectively goes nowhere, with no obvious error explaining why.

```
nyet.exe [--background] [<wg_ip> <home_ip> <blocklist_path> <log_path>]
```

Every one of the 4 values can come from a CLI arg (shown above) *or* from
the matching environment variable (`WG_IP`/`HOME_IP`/`BLOCKLIST_PATH`/`LOG_PATH`)
— e.g. by running `call config.local.bat` first. A CLI arg always
overrides the env var in that same slot, so you can mix — everything
from `config.local.bat` except one value you want to override for a
one-off test, say.

| Value | Example | Description |
|---|---|---|
| `wg_ip` | `10.10.0.1` | Upstream DNS via WireGuard — tried first. If you don't have one, use `home_ip`'s value here too. |
| `home_ip` | `10.0.0.2` | Upstream DNS on home LAN — faster, only reachable on the home network (hairpin NAT breaks it otherwise). |
| `blocklist_path` | `lists\blocklist.tsv` | Static, hand-curated blocklist TSV. `learned.tsv`/`review.tsv` are created automatically next to this file — see [`CONFIGURATION.md`](docs/CONFIGURATION.md). |
| `log_path` | `nyet.log` | Dense query log (appended). |

Tries `wg_ip` first, falls back to `home_ip` on timeout, sticks with whichever last worked.

**Run from an elevated terminal**, with `config.local.bat` already set up:

```powershell
call config.local.bat
.\nyet.exe --background
```

`--background` relaunches fully detached (no console, survives closing
the terminal). Omit it to run in the foreground with live `[heur]`
debug output instead — see [`OPERATIONS.md`](docs/OPERATIONS.md) for how
to stop a `--background` instance, since Ctrl+C won't reach it.

Want a double-click launcher instead of typing the above every time? Copy
`run_nyet.example.bat` → `run_nyet.local.bat` — both `config.local.bat`
and `run_nyet.local.bat` are gitignored, so your real values never end up
in version control.

**Why admin, if binding a port under 1024 doesn't itself require it on Windows?** It doesn't — Winsock's `bind()` has no OS-level restriction on low ports the way Linux does. In practice you need it anyway: Windows' own DNS Client service (and often Hyper-V's Host Network Service or Internet Connection Sharing) grabs `0.0.0.0:53` on its own the moment the network stack initializes. Admin rights are what let you stop/reconfigure whatever's already squatting on the port, not a requirement of the `bind()` call itself.
