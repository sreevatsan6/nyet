# Operations Reference

## Debug Output

Console mode (`make debug`, or omit `--background`), stdout redirected separately from `log_path`:

```powershell
.\nyet.exe 192.0.2.1 198.51.100.2 lists\blocklist.tsv nyet.log *> debug.log
```

Or, with `config.local.bat` already set up (see [`CONFIGURATION.md`](CONFIGURATION.md)):

```powershell
call config.local.bat
.\nyet.exe *> debug.log
```

`[heur] domain | REVIEW/clean | <breakdown>` per newly-scored domain, plus a score-distribution summary on shutdown (Ctrl+C), including rate-limit drop counts.

---

## `log_path` Format

```
epoch  client_ip  domain  qtype  status  source  reason  latency_us
```

- `status`: `B` blocked · `A` allowed · `R` review (verdict cached in query_cache, still forwarded to upstream) · `F` forwarded (no tree entry) · `C` cached answer (served from dns_answer_cache, no upstream round-trip at all — see [`DESIGN.md`](DESIGN.md#answer-cache-answer_cachec)) · `E` malformed
- `source`: `e` hash-exact · `s` hash-suffix · `h` heuristic · `n` none
- A domain's *first* sighting always logs `F` — the tree entry (and `status=R`) only exists from the second query on. A `C` can only happen on some later query too, for the same reason -- there's nothing to serve from `dns_answer_cache` until at least one real upstream round-trip has populated it.

---

## Stopping a `--background` Instance

Ctrl+C only works in console mode. `--background` relaunches nyet fully
detached (`DETACHED_PROCESS` — no console at all), specifically so it
survives closing the terminal that started it — which also means there's
no window for Ctrl+C to reach.

To stop it: Task Manager → find `nyet.exe` → End Task, or from a terminal:

```powershell
taskkill /IM nyet.exe
```

(Add `/F` only if the plain form doesn't work — it skips the shutdown
handler that flushes the log buffer and stops worker threads cleanly.)

---

## Setting Windows DNS to Use Nyet

1. `ncpa.cpl` → active adapter → Properties → IPv4 → Properties.
2. Preferred DNS server → `127.0.0.1`. **Leave Alternate blank** (or Windows may bypass the proxy).

For another device (phone, etc.) to use this machine as its DNS server: point it at this machine's LAN IP, not `127.0.0.1`. Nyet binds `0.0.0.0` so it's reachable, but Windows Firewall needs an inbound UDP:53 rule, and the adapter profile must be **Private**, not Public.

**Watch for Windows appending your ISP's connection-specific DNS suffix** (e.g. something like `hsd1.<state>.<isp>.net`, in whatever form your own ISP uses) during resolution — if that suffix (or any part of it) is ever blocked in your list, suffix-matching will sinkhole *everything*, since every query effectively gets tried with that suffix appended somewhere in the chain. Check `ncpa.cpl` → adapter → IPv4 → Advanced → DNS tab if queries start mysteriously all resolving to `0.0.0.0`.

---

## Troubleshooting

| Issue | Check |
|---|---|
| `Bind failed` / `WSAEADDRINUSE` | Port 53 already held by Windows' own DNS Client service, or Hyper-V Host Network Service / ICS — all of which grab `0.0.0.0:53` on their own well before you're involved. `net stop dnscache`, or change `DNS_PORT` in code. See the README for why this needs admin even though the raw `bind()` call doesn't. |
| No upstream replies | Verify `wg_ip`/`home_ip` reachable, Pi-hole running. Run in console mode and watch for `[heur]`/log activity. |
| Other device can't reach this as DNS | Confirm it's pointed at this machine's LAN IP. Check firewall UDP:53 rule + adapter profile is Private. |
| Pi-hole gravity not working | API path is `/api/search/<domain>` (Pi-hole v6, unauthenticated) — may differ on v5. |
| `learned.tsv`/`review.tsv` not loading/writing | Both live next to `blocklist_path`, not a fixed `lists/` folder — wherever you pointed `blocklist_path`, that's the directory nyet reads/writes them from. If that directory doesn't exist, both fail silently (missing files are fine, missing *directories* are not). |
| No logs written | Check write permissions; run as Administrator. |
| `review.tsv` filling with legit domains | Expected — heuristics are advisory-only. Triage with `review_tool.py`; add persistent false-positives to `PROTECTED_DOMAINS`. Nothing auto-blocks from a heuristic hit alone. |
| Everything suddenly resolves to `0.0.0.0` | Check for a blocked entry matching your ISP's DNS suffix (see above), OR check that `config.local.bat` (or your CLI args) actually have your real `WG_IP`/`HOME_IP` values, not the template placeholders — leaving them unset means nyet has no real upstream to forward to, so every allowed/unmatched query effectively goes nowhere too. |
| A domain resolves to a stale/wrong IP after you changed something | Should self-correct within the real record's TTL either way, but for an immediate fix: hot-reload (edit `blocklist.tsv`, wait up to 5s) already clears `dns_answer_cache` entirely, and a gravity-confirmed block invalidates that one domain's cached answer immediately — see [`DESIGN.md`](DESIGN.md#answer-cache-answer_cachec). If neither applies and it's still stale, check `log_path` for `C` (cached-answer) rows on that domain to confirm the cache is actually what's serving it. |

---

## Emergency Recovery

If nyet crashes or stops, DNS resolution fails immediately.

1. `ncpa.cpl` → adapter → Properties → IPv4 Properties.
2. **Obtain DNS server address automatically** (or set `1.1.1.1`).
