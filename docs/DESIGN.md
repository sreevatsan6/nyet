# Design Notes

Why nyet's domain-decision pipeline and heuristics engine work the way
they do. Nothing here is a setting you'd change per-install — for the
actual TSV format and what to configure, see
[`CONFIGURATION.md`](CONFIGURATION.md).

---

## How Domain Decisions Get Made

1. **Radix-tree lookup**, suffix-matched root → TLD → most specific. `A` anywhere in the path wins over `B` further up.
2. **First time a domain has no tree entry:**
   - Async, rate-limited (max 8 concurrent) Pi-hole gravity check. If confirmed, promoted to `learned.tsv` (`source=G`) — never asked again.
   - Separately, an advisory heuristic score is computed and cached as `status=R` regardless of score (never re-scored). Only scores crossing `REVIEW_THRESHOLD` (0.5) get written to `review.tsv`.
3. Neither signal blocks or clears anything on the first pass by itself — they only feed `review.tsv` / the promotion path. The deterministic blocklist + your curation via `review_tool.py` is what actually decides.

---

## Answer Cache (`answer_cache.c`)

Solves a specific real problem: without this, a non-blocked query pays a full round-trip through your own network topology every single time, even querying the exact same domain seconds apart — e.g. a phone on WireGuard resolving something already resolved moments ago still goes phone → nyet → upstream resolver → [gravity check] → upstream → nyet → phone, in full, every time. Since the overwhelming majority of any real traffic is non-blocked, this was the common case paying the expensive path.

**What it caches, and how that's different from `query_cache` (`dns_cache.c`):** `query_cache` answers "is this domain blocked or allowed" — a verdict. `answer_cache` answers "what did this domain actually resolve to, and is that still fresh" — a real DNS answer (the IP(s)), keyed on `(domain, qtype)` rather than just `domain`, with the real upstream TTL governing freshness rather than a locally-chosen policy constant. They're deliberately separate caches with different contracts; see `answer_cache.h` for the full module contract.

**Eligibility** — which domains actually get cached, checked identically on both the lookup and the insert side in `process_request()`:
- Query must be `A` or `28`/`AAAA` — the only two record shapes this module knows how to store.
- Domain must be either `STATUS_ALLOWED` (explicit blocklist entry) **or genuinely unmatched** (no tree entry at all yet). `STATUS_REVIEW` domains are deliberately excluded — a domain the heuristics engine has already flagged as suspicious doesn't get the speed-up treatment, even though it's still being forwarded like an unmatched one would be.

**Population and invalidation:**
- Populated from a real upstream reply (`parse_answer_records()`), never from anything nyet invents itself — only `NOERROR` replies with at least one matching A/AAAA record get cached, and the stored TTL is the *minimum* across all cached records for that answer.
- Cleared entirely on every hot-reload swap, same as `query_cache` (`reload_thread_proc`).
- Invalidated per-domain the moment a domain gets promoted to `BLOCKED` via Pi-hole gravity confirmation (`gravity_check_thread`) — this is the one case where a domain could have been actively serving cached answers right up until the exact moment it needed to stop.

**Observability:** cache hits log as a new `RESULT_CACHED` outcome (`C` in `log_path` — see [`OPERATIONS.md`](OPERATIONS.md#log_path-format)), and hit/miss/eviction/insert counts print in the shutdown summary alongside the existing heuristics stats.

---

## Advisory Heuristics (`heuristics.c`)

Scores the **whole domain**, not just its leftmost label — some evasion patterns (e.g. `ln-0007.ln-msedge.net`) only show up once you look at more than one label or at the domain's overall shape. All cheap, deterministic, zero-training checks, combined as a weighted sum — no ML. (Three trained-model approaches were tried and dropped: they couldn't reliably separate real infra — CDN nodes, cert-validation hosts — from tracking infra, since both are auto-generated non-human-readable strings.)

**Per-label checks** (run over every non-TLD label, not just the first):
- Entropy (`is_suspicious_label`, in `nyet.c`)
- Longest consonant run > 4
- Vowel ratio outside normal range
- Digit ratio > 40% (only at label length ≥ 8, to avoid flagging short CDN labels like `t1`/`x2`)
- Recognizable tech-word substrings (`google`, `api`, `auth`, ...) — the one signal that *reduces* the score

**Domain-wide shape checks:**
- Too many labels (more than a normal domain legitimately needs)
- Label-length variance (one long random-looking label next to otherwise-short ones — the `(50-char-token).domain.com` shape)
- Symbol density (dots + hyphens + other non-alphanumeric characters as a fraction of total length)
- Hyphen-flattened labels (few real dot-separated labels, but one of them heavily hyphen-segmented, as if several subdomains got flattened into one)
- Excessive hyphen count overall — deliberately the **lowest-weighted** signal, since plenty of legitimate CDN/infra hostnames are hyphen-heavy by convention (`apple-native-relay.apple.com`, `amp-api-edge.apps.apple.com` are both real and fine)

Each check alone sits below threshold; it takes ~2 agreeing signals to land in `review.tsv`. Weights are a starting point, not gospel — retune against your own `review.tsv` signal-to-noise over time.

**Known limitation:** a domain deliberately designed to mimic legitimate hyphenated infra naming (registering a lookalike like `ln-msedge.net` to slip past a `msedge.net` block) is largely indistinguishable from real infra by shape alone — that's what makes it a good evasion. Heuristics catch *novel* shapes; a deliberate lookalike of a name you already know to block is better handled by adding it directly to `blocklist.tsv` once you spot it. Suffix-matching then catches it and every subdomain under it going forward.

`scripts/review_tool.py` has a `PROTECTED_DOMAINS` allowlist (suffix-matched, currently `cloudflare.com` + `googlevideo.com`) for legit infra whose real CDN/edge labels are high-entropy by nature — extend it as you find more false-positive-prone infra, rather than triaging the same domains repeatedly.
