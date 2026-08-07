# Configuration Reference

What to set before you build/run, and the exact TSV format nyet reads and
writes. For *why* the decision pipeline and heuristics are built the way
they are, see [`DESIGN.md`](DESIGN.md) instead — this file is settings,
not rationale.

---

## What to customize before you compile/run

This repo ships as a template — nothing here points at real infrastructure.
Checklist, in the order you'll actually hit them:

1. **Copy `config.example.bat` → `config.local.bat`** (repo root). Fill in:
   - `WG_IP` — your WireGuard upstream DNS address
   - `HOME_IP` — your home-LAN upstream DNS address
   - `BLOCKLIST_PATH` — where your real blocklist TSV will live
   - `LOG_PATH` — where the query log should be written

   `config.local.bat` is gitignored — it never gets committed. `nyet.exe`
   reads these as environment variables if you don't pass the equivalent
   CLI arg (CLI always wins when given — see below). The Python tools in
   `scripts/` read `BLOCKLIST_PATH` the same way.

2. **Create the file `BLOCKLIST_PATH` points at.** Nothing pre-populated
   ships in this repo — see `examples/` for a small starter list you can
   copy and build on, or run `scripts/create_blocklist_tsv.py` against
   your own raw domain list.

3. **(Optional) Copy `run_nyet.example.bat` → `run_nyet.local.bat`** if you
   want a double-click launcher instead of typing the command each time.
   Also gitignored.

4. **(Optional) Review `PROTECTED_DOMAINS`** in `scripts/review_tool.py`
   — the false-positive-prone infra allowlist ships with just
   `cloudflare.com`/`googlevideo.com`; add your own as you find them.

That's it — no macros to hunt down in `src/`, no paths hardcoded per-file.
Every consumer (the C binary, every script) reads from the same
`config.local.bat`-set environment variables.

---

## CLI Args / Environment Variables

```
nyet.exe [--background] [<wg_ip> <home_ip> <blocklist_path> <log_path>]
```

| Value | CLI position | Env var | Notes |
|---|---|---|---|
| WireGuard upstream | arg 1 | `WG_IP` | Tried first each query |
| Home-LAN upstream | arg 2 | `HOME_IP` | Faster, only reachable on the home network |
| Blocklist path | arg 3 | `BLOCKLIST_PATH` | `learned.tsv`/`review.tsv` are created next to this automatically |
| Log path | arg 4 | `LOG_PATH` | Appended to, not overwritten |

Resolution order per value: **CLI arg (if given) → matching env var → error**
naming exactly which one(s) are still missing. A CLI arg always overrides
the env var in that same slot — you can mix, e.g. everything from
`config.local.bat` except a one-off different `wg_ip` for testing.

`--background`: relaunch fully detached (no console window, survives
closing the terminal that launched it). Omit for console/debug mode. See
[`OPERATIONS.md`](OPERATIONS.md) for how to stop a detached instance.

---

## Blocklist TSV Format

Three files share this format: your hand-curated blocklist (`BLOCKLIST_PATH`), plus `learned.tsv` and `review.tsv`, which nyet creates automatically **next to** it — same directory, not a fixed `lists/` folder.

```
status  domain  source  first_seen  last_seen  hit_count  ttl  note
```

- `status`: `B` block · `A` allow (wins over any suffix-matched `B`) · `R` review
- `source`: `S` static · `H` heuristic · `M` manual · `G` Pi-hole gravity
- `ttl`: blocked-response TTL in seconds. `create_blocklist_tsv.py` and every other tool in `scripts/` always writes this column — 60s default, override for chatty repeat offenders you want to ask less often.

`nyet.c`'s parser will still tolerate an old 6-column line with no `ttl` at all (sniffs whether the next tab-delimited field is purely numeric); if you ever hand-edit a line without a `ttl` column, don't make the `note` on that line purely numeric or it'll get misread as a `ttl`. This isn't something you'll hit using the scripts in this repo — they always write all 8 columns.

`review.tsv` (written by heuristics, consumed by `scripts/review_tool.py`): `REVIEW  domain  heuristic  first_seen  last_seen  1  reason`.

All three: case-insensitive, suffix-matched (blocking `doubleclick.net` blocks every subdomain under it for free).

`scripts/check_tsv.py` validates a TSV against this format before you load it. Full rundown of every script in `scripts/` — what each does and how to run it — is in [`SCRIPTS.md`](SCRIPTS.md).

---

## Compile-Time Tuning

Almost everything in this repo is a runtime value (`config.local.bat`, CLI args). The one exception worth knowing about: `ANSWER_CACHE_CAPACITY` in `nyet.c` (default `4096`, ~1MB) sets how many resolved-answer entries `dns_answer_cache` can hold at once — see [`DESIGN.md`](DESIGN.md#answer-cache-answer_cachec) for what that cache does. Must stay a power of 2 if you change it. You likely never need to touch this; it's generous for anything a home network has genuinely "hot" at once, and the shutdown summary's utilization percentage will tell you if it's actually running low.
