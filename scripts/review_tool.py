#!/usr/bin/env python3
import sys
import os
import re
import time
import unicodedata
import argparse
from collections import Counter
from math import log2

# Paths -- default to a sibling "lists/" dir (matches this repo's layout
# when run from repo root), but every one of these is overridable via CLI
# flags below. BLOCK_FILE's directory is what LEARNED/REVIEW default to
# when not given explicitly -- same "derive from blocklist_path" model
# nyet.c itself uses now, so the .tsv trio always stays together.
_DEFAULT_DIR = "lists"
REVIEW_FILE = os.path.join(_DEFAULT_DIR, "review.tsv")
BLOCK_FILE = os.path.join(_DEFAULT_DIR, "blocklist.tsv")
LEARNED_FILE = os.path.join(_DEFAULT_DIR, "learned.tsv")

DNS_EPOCH = 1577836800  # 2020-01-01 00:00:00 UTC

# Matches DEFAULT_BLOCK_TTL_SECONDS in nyet.c -- written into every new
# entry's ttl column so append_to_list() output stays loadable by the new
# 8-column format instead of silently reverting to the old 7-column shape.
DEFAULT_TTL_SECONDS = 60

# Legit infra whose auto-generated node/CDN labels trip the high-entropy
# heuristic constantly (real hostnames, not tracking IDs) -- suffix-matched
# the same way nyet.c's radix tree suffix-matches blocklist entries, so
# "edge.googlevideo.com" and "foo.bar.cloudflare.com" both match without
# needing every subdomain listed individually. Extend this list rather
# than hand-waving away individual high-entropy hits as they show up.
PROTECTED_DOMAINS = {
    "cloudflare.com",
    "googlevideo.com",
}

def is_protected_domain(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in PROTECTED_DOMAINS)

# Pulling classification engine from your create_blocklist_tsv.py
SUSPICIOUS_PATTERNS = [
    (r'doubleclick',        'contains "doubleclick" (ad serving)'),
    (r'googleadservices',   'contains "googleadservices" (ad services)'),
    (r'pagead\d*',          'contains "pagead" (ad serving)'),
    (r'adsystem',           'contains "adsystem" (ad system)'),
    (r'advertising',        'contains "advertising"'),
    (r'aax-',               'contains "aax" (ad exchange)'),
    (r'\bads\b',            'contains "ads" (advertising)'),
    (r'\bad\b',             'contains "ad" (advertising)'),
    (r'impression',         'contains "impression" (ad measurement)'),
    (r'conversion',         'contains "conversion" (ad tracking)'),
    (r'click',              'contains "click" (click tracking)'),
    (r'pixel',              'contains "pixel" (tracking pixel)'),
    (r'beacon',             'contains "beacon" (tracking beacon)'),
    (r'\btag\b',            'contains "tag" (tag management)'),
    (r'telemetry',          'contains "telemetry"'),
    (r'analytics',          'contains "analytics"'),
    (r'metrics',            'contains "metrics"'),
    (r'stat(?!ic)',         'contains "stat" (statistics)'),
    (r'measure',            'contains "measure" (measurement)'),
    (r'ingest',             'contains "ingest" (data ingestion)'),
    (r'collector',          'contains "collector" (data collection)'),
    (r'events',             'contains "events" (event tracking)'),
    (r'event',              'contains "event" (event tracking)'),
    (r'\bdata\b',           'contains "data" (data endpoint)'),
    (r'\blog\b',            'contains "log" (logging)'),
    (r'report',             'contains "report" (reporting)'),
    (r'crash',              'contains "crash" (crash reporting)'),
    (r'error',              'contains "error" (error reporting)'),
    (r'diagnostics',        'contains "diagnostics"'),
    (r'insights',           'contains "insights" (analytics)'),
    (r'track',              'contains "track" (tracking)'),
    (r'capture',            'contains "capture" (data capture)'),
    (r'instrumentation',    'contains "instrumentation"'),
    (r'monitor(?!\.mozilla\.org)', 'contains "monitor" (monitoring)'),
    (r'sentry\.io',         'contains "sentry.io" (error tracking)'),
    (r'bugsnag',            'contains "bugsnag" (error monitoring)'),
    (r'datadoghq',          'contains "datadoghq" (monitoring)'),
    (r'datadog',            'contains "datadog" (monitoring)'),
    (r'newrelic',           'contains "newrelic" (APM)'),
    (r'appdynamics',        'contains "appdynamics" (APM)'),
    (r'dynatrace',          'contains "dynatrace" (APM)'),
    (r'amplitude',          'contains "amplitude" (analytics)'),
    (r'mixpanel',           'contains "mixpanel" (analytics)'),
    (r'segment\.com',       'contains "segment.com" (customer data platform)'),
    (r'heap',               'contains "heap" (analytics)'),
    (r'hotjar',             'contains "hotjar" (user analytics)'),
    (r'fullstory',          'contains "fullstory" (session replay)'),
    (r'pendo\.io',          'contains "pendo.io" (product analytics)'),
    (r'intercom',           'contains "intercom" (customer messaging)'),
    (r'widget',             'contains "widget" (embedded chat/tracking)'),
    (r'nexus-websocket',    'contains "nexus-websocket" (real-time messaging)'),
    (r'helpcenter',         'contains "helpcenter" (knowledge base tracking)'),
    (r'appsflyer',          'contains "appsflyer" (mobile attribution)'),
    (r'adjust\.com',        'contains "adjust.com" (mobile attribution)'),
    (r'branch\.io',         'contains "branch.io" (deep linking/tracking)'),
    (r'kochava',            'contains "kochava" (mobile attribution)'),
    (r'singular\.net',      'contains "singular.net" (mobile attribution)'),
    (r'mparticle',          'contains "mparticle" (data platform)'),
    (r'rudderstack',        'contains "rudderstack" (data pipeline)'),
    (r'snowplow',           'contains "snowplow" (event analytics)'),
    (r'posthog',            'contains "posthog" (product analytics)'),
    (r'telemetrydeck',      'contains "telemetrydeck" (analytics)'),
    (r'crashlytics',        'contains "crashlytics" (crash reporting)'),
    (r'fabric\.io',         'contains "fabric.io" (mobile app platform)'),
    (r'hockeyapp',          'contains "hockeyapp" (crash reporting)'),
    (r'appcenter',          'contains "appcenter" (app diagnostics)'),
    (r'instabug',           'contains "instabug" (bug reporting)'),
    (r'rollbar',            'contains "rollbar" (error tracking)'),
    (r'raygun',             'contains "raygun" (error tracking)'),
    (r'airbrake',           'contains "airbrake" (error tracking)'),
    (r'trackjs',            'contains "trackjs" (error tracking)'),
    (r'loggly',             'contains "loggly" (log management)'),
    (r'papertrail',         'contains "papertrail" (log management)'),
    (r'sumologic',          'contains "sumologic" (log analytics)'),
    (r'splunk',             'contains "splunk" (log analytics)'),
    (r'opensearch',         'contains "opensearch" (search/analytics)'),
    (r'elastic\.co',        'contains "elastic.co" (search/analytics)'),
    (r'grafana',            'contains "grafana" (observability)'),
    (r'prometheus',         'contains "prometheus" (monitoring)'),
    (r'influxdata',         'contains "influxdata" (time-series monitoring)'),
    (r'lightstep',          'contains "lightstep" (tracing)'),
    (r'honeycomb',          'contains "honeycomb" (observability)'),
    (r'signalfx',           'contains "signalfx" (monitoring)'),
    (r'wavefront',          'contains "wavefront" (monitoring)'),
    (r'firebase',           'contains "firebase" (app platform/analytics)'),
    (r'firebaselogging',    'contains "firebaselogging" (analytics logging)'),
    (r'google-analytics',   'contains "google-analytics" (analytics)'),
    (r'googletagmanager',   'contains "googletagmanager" (tag management)'),
    (r'app-measurement',    'contains "app-measurement" (analytics)'),
    (r'app-analytics',      'contains "app-analytics" (analytics)'),
    (r'visualstudio',       'contains "visualstudio" (development telemetry)'),
    (r'c\.media-amazon',    'contains "c.media-amazon" (ad/media tracking)'),
    (r'fls-na\.amazon',     'contains "fls-na.amazon" (Frontier Log Service)'),
    (r'dc-telemetry',       'contains "dc-telemetry" (telemetry)'),
    (r'ohttp-gateway',      'contains "ohttp-gateway" (telemetry gateway)'),
    (r'loc-[a-z]{2}-[a-z]{2}', 'contains locale subdomain (structured telemetry)'),
    (r'chk-webapp',         'contains "chk-webapp" (experimentation/telemetry)'),
    (r'res-ok',             'contains "res-ok" (A/B test/telemetry)'),
    (r'dur-\d+',            'contains duration subdomain (telemetry)'),
    (r'v\d+\.dc-telemetry', 'contains versioned telemetry subdomain'),
    (r'prod\.service\.minerva', 'contains "prod.service.minerva" (device telemetry)'),
    (r'googlesyndication',  'contains "googlesyndication" (ad syndication)'),
    (r'c\.amazon-adsystem', 'contains "c.amazon-adsystem" (ad system)'),
    (r's\.amazon-adsystem', 'contains "s.amazon-adsystem" (ad system)'),
    (r'csp[-.]',            'contains "csp" (Content Security Policy reporting)'),
]

HEX_PATTERN = re.compile(r'^[0-9a-f]{32,}$', re.IGNORECASE)

def strict_ascii_clean(text: str) -> str:
    replacements = {
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
        "\u2014": "-", "\u2015": "-", "\u2212": "-", "\u00A0": " ",
        "\u2018": "'", "\u2019": "'", "\u201C": '"', "\u201D": '"',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text.encode("ascii", errors="ignore").decode("ascii") if 32 <= ord(c) <= 126)

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((cnt / n) * log2(cnt / n) for cnt in counts.values())

def classify_domain(domain: str) -> str:
    domain_lower = domain.lower()
    for label in domain_lower.split('.'):
        if HEX_PATTERN.fullmatch(label): return 'contains long hexadecimal label (device telemetry)'
    for pattern, note in SUSPICIOUS_PATTERNS:
        if re.search(pattern, domain_lower): return note
    for label in domain_lower.split('.'):
        if len(label) > 10 and not label.startswith('xn--'):
            if shannon_entropy(label) > 3.5: return 'contains high-entropy label (random tracking ID)'
    return 'suspicious / telemetry domain'

def get_nyet_time() -> int:
    return int(time.time() - DNS_EPOCH)

def load_processed_domains():
    """Builds an active set of domains already categorized to skip prompting."""
    seen = set()
    for filepath in [BLOCK_FILE, LEARNED_FILE]:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) > 1:
                        seen.add(parts[1].strip().lower())
    return seen

def append_to_list(filepath, domain, flag, note):
    t = get_nyet_time()
    with open(filepath, 'a', encoding='ascii') as f:
        f.write(f"B\t{domain}\t{flag}\t{t}\t{t}\t1\t{DEFAULT_TTL_SECONDS}\t{note}\n")

def direct_add_domains(domains):
    """Direct inline pipeline functionality to expand blocklist instantly."""
    added = 0
    for raw_domain in domains:
        domain = strict_ascii_clean(raw_domain.strip().lower())
        if not domain or domain.startswith('#'):
            continue
        note = classify_domain(domain)
        append_to_list(BLOCK_FILE, domain, 'S', note)
        print(f"🚫 Directly added to blocklist: {domain} -> ({note})")
        added += 1
    print(f"Successfully appended {added} entry/entries.")

def interactive_review():
    """Runs the full interactive TUI review processing queue."""
    if not os.path.exists(REVIEW_FILE) or os.stat(REVIEW_FILE).st_size == 0:
        print("Nothing to review. Queue is completely empty.")
        return

    processed_domains = load_processed_domains()

    with open(REVIEW_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    domain_counts = Counter()
    raw_entries_map = {}

    for line in lines:
        parts = line.strip().split('\t')
        if len(parts) > 1:
            domain = parts[1].strip().lower()
            domain_counts[domain] += 1
            if domain not in raw_entries_map:
                raw_entries_map[domain] = line

    queue = [d for d in domain_counts if d not in processed_domains]
    auto_skipped = len(domain_counts) - len(queue)

    protected_hits = [d for d in queue if is_protected_domain(d)]
    if protected_hits:
        queue = [d for d in queue if d not in protected_hits]
        print(f"🛡️  Auto-skipped {len(protected_hits)} domain(s) matching protected infra "
              f"({', '.join(sorted(PROTECTED_DOMAINS))}).")

    if auto_skipped > 0:
        print(f"💡 Auto-skipped {auto_skipped} unique domains already matched in blocklist/learned files.")

    if not queue:
        print("All raw logs matched existing rules. Clearing out the review backlog...")
        open(REVIEW_FILE, 'w').close()
        return

    # Sort the queue by hit count, highest first.
    queue.sort(key=lambda d: domain_counts[d], reverse=True)

    print(f"--- Loaded {len(queue)} unique tracking domains to audit ---")

    handled_domains = set(protected_hits)
    nuked_roots = set() # Track what we kill in this run so we don't ask again
    aborted = False

    for idx, domain in enumerate(queue, 1):
        # If we already nuked the root domain or blocked a parent in this session, skip this child.
        if any(domain == r or domain.endswith("." + r) for r in nuked_roots):
            handled_domains.add(domain)
            continue

        count = domain_counts[domain]
        suggested_note = classify_domain(domain)

        print(f"\n[{idx}/{len(queue)}] Domain: {domain}")
        print(f"    Hits in Log: {count}")
        print(f"    Auto-Heuristic Reason: {suggested_note}")

        while True:
            choice = input("    Action ([b]lock / [n]uke root / [l]earn / [s]kip / [q]uit): ").strip().lower()
            if choice == 'b':
                append_to_list(BLOCK_FILE, domain, 'S', suggested_note)
                print(f"    🚫 Appended to blocklist.tsv")
                handled_domains.add(domain)
                nuked_roots.add(domain) # Prevent prompts for subdomains later in queue
                break
            elif choice == 'n':
                parts = domain.split('.')
                suggested_root = ".".join(parts[-2:]) if len(parts) > 1 else domain
                nuke_target = input(f"    ☢️  Nuke which base domain? [{suggested_root}]: ").strip().lower() or suggested_root
                append_to_list(BLOCK_FILE, nuke_target, 'S', f"blanket_nuke ({suggested_note})")
                print(f"    ☢️  Nuked {nuke_target}. Any subdomains remaining in this queue are dead meat.")
                handled_domains.add(domain)
                nuked_roots.add(nuke_target)
                break
            elif choice == 'l':
                append_to_list(LEARNED_FILE, domain, 'G', f"manually_allowed ({suggested_note})")
                print(f"    ✅ Appended to learned.tsv")
                handled_domains.add(domain)
                break
            elif choice == 's':
                print(f"    ⏭️ Skipped.")
                handled_domains.add(domain) # Drops from queue file
                break
            elif choice == 'q':
                print("Aborting audit session.")
                aborted = True
                break
            else:
                print("Invalid input. Select 'b', 'n', 'l', 's', or 'q'.")

        if aborted:
            break

    # Rewrite review.tsv safely
    with open(REVIEW_FILE, 'w', encoding='utf-8') as f:
        for line in lines:
            parts = line.strip().split('\t')
            if len(parts) > 1:
                domain = parts[1].strip().lower()
                if domain not in handled_domains and domain not in processed_domains:
                    f.write(line)

    print("\nQueue updated successfully.")

def _apply_path_overrides():
    """Scan sys.argv for --blocklist/--review/--learned, apply them to the
    module globals, and strip them out so the existing --add/piped-domain
    parsing below never has to know they exist.

    Priority per path: CLI flag > matching env var (BLOCKLIST_PATH, set via
    config.local.bat) > hardcoded lists/ default. --review/--learned each
    default to sitting next to whatever BLOCK_FILE resolves to, unless
    given explicitly -- same derive-from-blocklist-directory model as
    nyet.c's proxy_init()."""
    global REVIEW_FILE, BLOCK_FILE, LEARNED_FILE
    remaining = []
    explicit_review = explicit_learned = None
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--blocklist" and i + 1 < len(sys.argv):
            BLOCK_FILE = sys.argv[i + 1]
            i += 2
        elif arg == "--review" and i + 1 < len(sys.argv):
            explicit_review = sys.argv[i + 1]
            i += 2
        elif arg == "--learned" and i + 1 < len(sys.argv):
            explicit_learned = sys.argv[i + 1]
            i += 2
        else:
            remaining.append(arg)
            i += 1

    if BLOCK_FILE == os.path.join(_DEFAULT_DIR, "blocklist.tsv") and os.environ.get("BLOCKLIST_PATH"):
        BLOCK_FILE = os.environ["BLOCKLIST_PATH"]

    block_dir = os.path.dirname(BLOCK_FILE) or "."
    REVIEW_FILE = explicit_review or os.path.join(block_dir, "review.tsv")
    LEARNED_FILE = explicit_learned or os.path.join(block_dir, "learned.tsv")
    sys.argv[1:] = remaining


if __name__ == "__main__":
    _apply_path_overrides()

    if not sys.stdin.isatty():
        piped_domains = sys.stdin.read().splitlines()
        if piped_domains:
            direct_add_domains(piped_domains)
            sys.exit(0)

    if len(sys.argv) > 1:
        if sys.argv[1] == "--add":
            if len(sys.argv) < 3:
                print("Error: Specify at least one domain to add. (e.g., --add domain.com)")
                sys.exit(1)
            direct_add_domains(sys.argv[2:])
        else:
            print("Usage Options:\n  Interactive Mode: python scripts/review_tool.py\n  Direct Block:     python scripts/review_tool.py --add domain1.com [domain2.com ...]\n\n  Path overrides (default: lists/{blocklist,learned,review}.tsv relative to cwd):\n    --blocklist PATH   --review PATH   --learned PATH")
    else:
        interactive_review()