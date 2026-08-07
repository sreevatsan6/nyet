#!/usr/bin/env python3
"""
Convert a raw list of domains into a TSV blocklist for nyet.c.

Usage:
    python3 create_blocklist_tsv.py input.txt

The note field contains a short reason determined entirely from the domain name,
without mentioning any company or service organisation.

Output is always written to output.tsv.
"""

import sys
import re
import time
from collections import Counter
from math import log2
import unicodedata

# ---------- Color helpers ----------
def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

COLORS = {
    "HEADER": "\033[95m",
    "OKBLUE": "\033[94m",
    "OKCYAN": "\033[96m",
    "OKGREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m",
    "ENDC": "\033[0m",
}

if not supports_color():
    for k in COLORS:
        COLORS[k] = ""

def c(text, color="ENDC"):
    return f"{COLORS.get(color, '')}{text}{COLORS['ENDC']}"

# ---------------------------------------------------------------------------
# The core logic – DO NOT CHANGE ANYTHING BELOW
# ---------------------------------------------------------------------------

# Epoch offset used in nyet.c: 2020-01-01 00:00:00 UTC
DNS_EPOCH = 1577836800  # Unix timestamp for 2020-01-01

# Default TTL (seconds) written into the new `ttl` column for every
# freshly-generated row -- matches DEFAULT_BLOCK_TTL_SECONDS in nyet.c.
# Bulk-created domains from a raw list have no per-domain signal to base
# a custom TTL on, so they all get the default; go bump specific rows by
# hand afterward for chatty repeat offenders.
DEFAULT_TTL_SECONDS = 60

# Suspicious keyword / pattern list – first match wins.
SUSPICIOUS_PATTERNS = [
    # -- Ad-serving / advertising --
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

    # -- Telemetry / analytics / metrics --
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

    # -- Known monitoring / error-tracking services --
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

    # -- Special telemetry patterns --
    (r'dc-telemetry',       'contains "dc-telemetry" (telemetry)'),
    (r'ohttp-gateway',      'contains "ohttp-gateway" (telemetry gateway)'),
    (r'loc-[a-z]{2}-[a-z]{2}', 'contains locale subdomain (structured telemetry)'),
    (r'chk-webapp',         'contains "chk-webapp" (experimentation/telemetry)'),
    (r'res-ok',             'contains "res-ok" (A/B test/telemetry)'),
    (r'dur-\d+',            'contains duration subdomain (telemetry)'),
    (r'v\d+\.dc-telemetry', 'contains versioned telemetry subdomain'),
    (r'prod\.service\.minerva', 'contains "prod.service.minerva" (device telemetry)'),

    # -- Generic advertising / tracking platforms --
    (r'googleadservices',   'contains "googleadservices"'),
    (r'googlesyndication',  'contains "googlesyndication" (ad syndication)'),
    (r'c\.amazon-adsystem', 'contains "c.amazon-adsystem" (ad system)'),
    (r's\.amazon-adsystem', 'contains "s.amazon-adsystem" (ad system)'),

    # -- Content Security Policy reporting --
    (r'csp[-.]',            'contains "csp" (Content Security Policy reporting)'),
]

def strict_ascii_clean(text: str) -> str:
    """Force transform strings into absolute standard printable ASCII."""
    replacements = {
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
        "\u2014": "-", "\u2015": "-", "\u2212": "-", "\u00A0": " ",
        "\u2018": "'", "\u2019": "'", "\u201C": '"', "\u201D": '"',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    text = unicodedata.normalize("NFKD", text)
    clean_bytes = text.encode("ascii", errors="ignore")
    text = clean_bytes.decode("ascii")

    return "".join(c for c in text if 32 <= ord(c) <= 126)

HEX_PATTERN = re.compile(r'^[0-9a-f]{32,}$', re.IGNORECASE)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / n
        entropy -= p * log2(p)
    return entropy

def classify_domain(domain: str) -> str:
    """Return a short note purely from domain content."""
    domain_lower = domain.lower()

    # 1. Long hex label
    for label in domain_lower.split('.'):
        if HEX_PATTERN.fullmatch(label):
            return 'contains long hexadecimal label (device telemetry)'

    # 2. Keyword patterns – first match wins
    for pattern, note in SUSPICIOUS_PATTERNS:
        if re.search(pattern, domain_lower):
            return note

    # 3. High-entropy label
    for label in domain_lower.split('.'):
        if len(label) > 10 and not label.startswith('xn--'):
            ent = shannon_entropy(label)
            if ent > 3.5:
                return 'contains high-entropy label (random tracking ID)'

    return 'suspicious / telemetry domain'

def current_seconds_since_2020() -> int:
    return int(time.time() - DNS_EPOCH)

# ---------------------------------------------------------------------------
# Main function – only UI enhancements, no logic changes
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print(c("Usage: python3 create_blocklist_tsv.py input.txt", "WARNING"), file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "output.tsv"

    print(c("\n[+] Starting blocklist creation", "OKCYAN"))
    print(c(f"    Input  : {input_file}", "OKBLUE"))
    print(c(f"    Output : {output_file}", "OKBLUE"))

    current_time = current_seconds_since_2020()
    out_lines = []
    total_lines = 0
    valid_domains = 0
    skipped_empty = 0
    skipped_comments = 0
    start_time = time.time()

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                raw = line.strip()

                # Progress indicator every 1000 lines
                if total_lines % 1000 == 0:
                    sys.stderr.write(
                        f"\r{c('[PROGRESS]', 'OKCYAN')} Processed {total_lines:,} lines, "
                        f"found {valid_domains:,} valid domains..."
                    )
                    sys.stderr.flush()

                if not raw:
                    skipped_empty += 1
                    continue
                if raw.startswith('#'):
                    skipped_comments += 1
                    continue

                domain = strict_ascii_clean(raw)
                if not domain:
                    continue

                note = classify_domain(domain)
                note = note.replace('\t', ' ').replace('\n', ' ')
                note = strict_ascii_clean(note)

                out_lines.append(
                    f"B\t{domain}\tS\t{current_time}\t{current_time}\t1\t{DEFAULT_TTL_SECONDS}\t{note}"
                )
                valid_domains += 1

    except IOError as e:
        print(c(f"\n[FATAL] Error reading input: {e}", "FAIL"), file=sys.stderr)
        sys.exit(1)

    elapsed = time.time() - start_time
    # Clear progress line
    sys.stderr.write("\r" + " " * 80 + "\r")

    # Summary
    print(c("\n" + "=" * 60, "OKCYAN"))
    print(c("  Blocklist Creation Report", "BOLD"))
    print(c("=" * 60, "OKCYAN"))
    print(f"  Total lines read     : {total_lines:,}")
    print(f"  Valid domains written: {c(valid_domains, 'OKGREEN')}")
    print(f"  Empty lines skipped  : {skipped_empty:,}")
    print(f"  Comment lines skipped: {skipped_comments:,}")
    print(f"  Elapsed time         : {elapsed:.2f} seconds")
    print(c("=" * 60, "OKCYAN"))

    if not out_lines:
        print(c("\n[WARNING] No valid domains found; output file will be empty.", "WARNING"), file=sys.stderr)

    try:
        with open(output_file, 'w', encoding='ascii') as f:
            f.write('\n'.join(out_lines))
            if out_lines:
                f.write('\n')
        print(c(f"\n[SUCCESS] Output written to {output_file}", "OKGREEN"))
    except IOError as e:
        print(c(f"\n[FATAL] Error writing output: {e}", "FAIL"), file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()