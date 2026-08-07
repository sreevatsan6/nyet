# Scripts Reference

Everything in `scripts/` operates on the TSV format described in
[`CONFIGURATION.md`](CONFIGURATION.md). All Python scripts need Python 3;
none have third-party dependencies (stdlib only).

Most take a blocklist path as either a CLI argument or fall back to the
`BLOCKLIST_PATH` environment variable (same one `config.local.bat` sets for
`nyet.exe` itself) — see each entry below for specifics.

---

## Typical workflow

1. Have a raw list of domains, one per line? → **`create_blocklist_tsv.py`** turns it into a proper 8-column blocklist TSV.
2. Before loading anything new → **`check_tsv.py`** to catch malformed rows before nyet ever sees them.
3. Blocklist grown a lot of near-duplicate subdomain entries? → **`dedup_tsv.py`**, then **`clean_blocklist.py`** to roll subdomains up into their parent where safe.
4. Day to day, while nyet is running → **`review_tool.py`**, interactively or via `--add`, to triage what's landed in `review.tsv` and promote/allow/skip.
5. Curious what your tree actually looks like → **`tree_stats.py`** / **`tree_info.py`**.
6. Want to generate a quick burst of synthetic DNS traffic to smoke-test nyet itself → **`bombard.ps1`**.
7. `find_culprits.py` / `deep_inspect.py` are heavier-duty triage passes over a raw domain list — see their own sections below for when to reach for these instead of `create_blocklist_tsv.py`.

---

## `create_blocklist_tsv.py`

Converts a raw list of domains (one per line, `#` comments and blank lines
ignored) into a full 8-column blocklist TSV — the same format `nyet.c`
loads. Every domain gets a status (`B`), source (`S`), timestamps, and an
auto-generated `note` classifying *why* (entropy, known ad/tracking
substrings, etc.) — purely from the domain string itself, no external
lookups.

```
python3 create_blocklist_tsv.py input.txt
```

Output is always written to `output.tsv` in the current directory (not
in-place, not configurable) — review it, then move/rename it to wherever
you actually want your `blocklist_path` to point.

---

## `check_tsv.py`

Validates a TSV's structural integrity before you load it into nyet:
malformed column counts, bad timestamps, non-ASCII contamination, and the
old/new 7- vs 8-column format ambiguity that can silently eat a numeric
`note`. Accepts both formats.

```
python3 check_tsv.py <file.tsv>
```

Exits non-zero on any structural problem — safe to drop into a pre-commit
hook or just run by hand before pointing `BLOCKLIST_PATH` at a new file.

---

## `dedup_tsv.py`

Strict dedup by domain column only — collapses rows that differ purely by
timestamp/hit-count/rule-id but refer to the same domain. Does **not**
try to be clever about subdomain/parent relationships; that's
`clean_blocklist.py`'s job.

```
python3 dedup_tsv.py <file.tsv>                  # in-place (default)
python3 dedup_tsv.py <input.tsv> <output.tsv>     # write elsewhere instead
```

In-place mode writes via a temp file + atomic replace, same pattern
`clean_blocklist.py` uses — a crash mid-write can't corrupt your real
blocklist. Safe to run unconditionally before every launch, which is
exactly what `run_nyet.example.bat` does.

---

## `clean_blocklist.py`

Rolls up subdomains into their parent domain where doing so is provably
safe (e.g. `a.tracker.com` + `b.tracker.com` + `c.tracker.com` →
`tracker.com`, since suffix-matching already covers all three from the
parent alone). Has a `PROTECTED_DOMAINS` set of domains it will never
collapse (things like `google.com`/`amazonaws.com`/`cloudfront.net` —
collapsing those would block far more than intended). Prompts for
confirmation before writing; writes via a temp file + atomic move so a
crash mid-write can't corrupt your real blocklist.

```
python3 clean_blocklist.py [path/to/blocklist.tsv]
```

Path resolution: CLI arg → `BLOCKLIST_PATH` env var (e.g. from
`config.local.bat`) → errors with a usage message if neither is given.
No hardcoded fallback path — give it a real one.

---

## `review_tool.py`

The main day-to-day triage tool. Reads `review.tsv` (domains the
heuristics engine flagged, see `CONFIGURATION.md`), shows you each one
with its hit count and auto-suggested reason, and lets you decide what
happens to it.

**Interactive mode:**

```
python scripts/review_tool.py
```

Per domain, choose:

| Key | Action |
|---|---|
| `b` | Block — appends to `blocklist.tsv`, also blocks every subdomain of it that shows up later in this same queue |
| `n` | Nuke root — block the *parent* domain instead (asks you to confirm/edit which one) — same subdomain-suppression as `b`, just starting from a broader root |
| `l` | Learn/allow — appends to `learned.tsv` with `source=G`, i.e. "confirmed fine, don't ask again" |
| `s` | Skip — drops it from the queue this run without blocking or allowing it |
| `q` | Quit — stops the session; anything not yet handled stays in `review.tsv` for next time |

`PROTECTED_DOMAINS` (currently `cloudflare.com`, `googlevideo.com`) never
even reach the interactive prompt — they're auto-skipped as known
false-positive-prone infra. Extend that set in the script if you find
more.

**Direct/non-interactive mode**, for scripting or piping:

```
python scripts/review_tool.py --add domain1.com domain2.com
echo "domain1.com`ndomain2.com" | python scripts/review_tool.py    # piped stdin works too
```

Both immediately block the given domain(s), no prompts.

**Path overrides** (all three default to sitting next to each other —
`--review`/`--learned` derive from `--blocklist`'s directory unless given
explicitly, same model `nyet.c` itself uses):

```
python scripts/review_tool.py --blocklist D:\nyet\blocklist.tsv
python scripts/review_tool.py --blocklist lists\blocklist.tsv --review lists\review.tsv --learned lists\learned.tsv
```

`BLOCK_FILE` also honors the `BLOCKLIST_PATH` environment variable if no
`--blocklist` flag is given (i.e. reads your `config.local.bat`, same as
`nyet.exe`).

---

## `tree_stats.py` / `tree_info.py`

Both walk your blocklist and reconstruct the same radix-tree shape
`nyet.c` builds at runtime, then print either a numeric summary
(`tree_stats.py`: parent/avg-children/max-children per depth) or a full
per-node breakdown (`tree_info.py`: every parent path and its child
count). Useful for spotting one lopsided node (e.g. thousands of
unrelated children under a single TLD) before it becomes an actual
lookup-cost problem — these are read-only inspection tools, they never
write anything.

```
python3 tree_stats.py [path/to/blocklist.tsv]
python3 tree_info.py [path/to/blocklist.tsv]
```

Path resolution: CLI arg → `BLOCKLIST_PATH` env var — errors with a usage
message if neither is given. No hardcoded fallback path.

---

## `find_culprits.py`

Lighter-weight sibling of `create_blocklist_tsv.py` — classifies a raw
domain list the same way (entropy, known ad/tracking substrings, long hex
labels) but outputs a plain 2-column `domain \t reason` TSV instead of the
full 8-column blocklist format. Useful for a quick "why would each of
these get flagged" pass before you commit to generating the real
blocklist.

```
python3 find_culprits.py input.txt
```

Output is always `output.tsv` in the current directory.

---

## `deep_inspect.py`

A heavier, multi-stage classifier for cases `create_blocklist_tsv.py`'s
simpler heuristics don't catch — canonicalization (leetspeak,
dedup), exact known-vendor matching, substring/trie matching, trigram
similarity, and Damerau-Levenshtein distance against a known-bad list,
combined into one weighted score. Slower than the other tools by design;
reach for this when you specifically suspect obfuscated/lookalike domains
(e.g. typosquats of a domain you already block) that simple entropy
checks let through.

```
python3 deep_inspect.py filtered_input.tsv
```

---

## `bombard.ps1` (PowerShell)

Fires a burst of `nslookup` queries at `127.0.0.1` for a smoke test that
nyet is actually intercepting/sinkholing traffic — useful right after a
fresh build instead of browsing around by hand to generate real queries.
Deliberately minimal: a handful of well-known generic ad/tracking/telemetry
domains, cycled through, not an attempt at real coverage.

```powershell
.\bombard.ps1
```

Edit `$count` or the `$domains` array at the top of the script to change
volume/targets. If you add your own domains, keep them generic — no
device IDs, session IDs, or your own ISP/account-specific hostnames.

---

## Path resolution, consistently

Every script above that touches a blocklist follows the same priority
order, matching `nyet.c` itself: **CLI arg → `BLOCKLIST_PATH` environment
variable (e.g. set via `config.local.bat`) → clear error.** None of them
guess a relative path or silently depend on which directory you happened
to run them from — if you see a `usage:` message, it means neither a CLI
arg nor the env var was given, not that something's broken.
