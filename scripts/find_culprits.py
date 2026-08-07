#!/usr/bin/env python3
"""
Classify a raw list of domains into a simple 2-column TSV (domain, reason),
using the same pattern/entropy heuristics as create_blocklist_tsv.py but
without the status/source/timestamp columns -- useful for a quick pass to
see *why* each domain would get flagged before committing to the full
8-column blocklist format.

Usage:
    python3 find_culprits.py input.txt

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
# Core Domain Classification
# ---------------------------------------------------------------------------

SUSPICIOUS_PATTERNS = [
    # -- Real-Time Bidding (RTB), Cookie-Syncing & Header Bidding --
    (r'(^|\.)csync\.',                      'contains "csync" subdomain (cookie syncing)'),
    (r'(^|\.)sync\.',                       'contains "sync" subdomain (ad identity sync)'),
    (r'cookie[-_]?sync',                    'contains "cookie-sync" (identity matching)'),
    (r'app-ads-services\.com',              'app-ads-services ad supply chain network'),
    (r'pub\.network',                        'pub.network programmatic ad infrastructure'),
    (r'everestengagement\.com',             'everestengagement (ad tech tracking proxy)'),
    (r'riverdrop\.com',                     'riverdrop (ad tech pixel network)'),
    (r'yellowblue\.io',                     'yellowblue RTB/header bidding endpoint'),
    (r'openwebmp\.com',                     'openwebmp RTB infrastructure'),
    (r'smartadserver',                      'smartadserver ad exchange'),
    (r'stackadapt',                         'stackadapt DSP/native ad network'),
    (r'ipredictive',                        'ipredictive DSP infrastructure'),
    (r'krushmedia',                         'krushmedia ad exchange'),
    (r'loopme\.me',                         'loopme ad targeter'),
    (r'presage\.io',                        'presage mobile ad platform'),
    (r'richaudience',                       'richaudience ad tech network'),
    (r'resetdigital',                       'resetdigital ad marketplace'),
    (r'rbstsystems',                        'rbstsystems ad serving relay'),

    # -- Standard Ad Networks / Core Ad-Tech --
    (r'googleadservices',                   'contains "googleadservices" (ad services)'),
    (r'googlesyndication',                  'contains "googlesyndication" (ad syndication)'),
    (r'doubleclick',                        'contains "doubleclick" (ad serving)'),
    (r'pagead\d*',                          'contains "pagead" (ad serving)'),
    (r'c\.amazon-adsystem',                 'contains "c.amazon-adsystem" (ad system)'),
    (r's\.amazon-adsystem',                 'contains "s.amazon-adsystem" (ad system)'),
    (r'adsystem',                           'contains "adsystem" (ad system)'),
    (r'advertising',                        'contains "advertising"'),
    (r'aax-',                               'contains "aax" (ad exchange)'),
    (r'(^|\.)ads?\.',                       'subdomain starts with ad/ads'),
    (r'impression',                         'contains "impression" (ad measurement)'),
    (r'conversion',                         'contains "conversion" (ad tracking)'),
    (r'click',                              'contains "click" (click tracking)'),
    (r'pixel',                              'contains "pixel" (tracking pixel)'),
    (r'beacon',                             'contains "beacon" (tracking beacon)'),
    (r'(^|\.)tag\.',                        'contains "tag" subdomain (tag management)'),

    # -- Anti-Bot / First-Party Telemetry Proxies & Obfuscators --
    (r'px-cloud\.net|hsprotect\.net',       'PerimeterX/HUMAN bot protection & fingerprinting'),
    (r'ckapis\.com',                        'Credit Karma telemetry API proxy'),
    (r'sponge\.creditkarma\.com',           'Credit Karma ingestion funnel'),
    (r'csp[-.]',                            'contains "csp" (CSP violation reporting)'),

    # -- OS, Platform & Big-Tech Telemetry Endpoints --
    (r'-[pa]\.googleapis\.com',             'Google PA telemetry / service endpoint'),
    (r'dc-telemetry',                       'contains "dc-telemetry" (Meta/Instagram device telemetry)'),
    (r'ohttp-gateway',                      'contains "ohttp-gateway" (telemetry gateway)'),
    (r'prod\.service\.minerva',            'contains "prod.service.minerva" (device telemetry)'),
    (r'apple-native-relay',                 'apple native telemetry relay'),
    (r'diagnostics\.apple\.com',            'apple diagnostic reporting'),
    (r'metrics\.icloud\.com',               'iCloud metrics logger'),
    (r'data-edge\.smartscreen',             'Microsoft SmartScreen telemetry'),
    (r'ris\.api\.iris\.microsoft',          'Microsoft Iris telemetry service'),
    (r'in\.appcenter\.ms',                  'Microsoft AppCenter diagnostic collector'),
    (r'fls-na\.amazon',                     'contains "fls-na.amazon" (Frontier Log Service)'),

    # -- Generic Telemetry / Analytics / Ingestion Keywords --
    (r'telemetry',                          'contains "telemetry"'),
    (r'analytics',                          'contains "analytics"'),
    (r'metrics',                            'contains "metrics"'),
    (r'stat(?!ic)',                         'contains "stat" (statistics)'),
    (r'measure',                            'contains "measure" (measurement)'),
    (r'ingest',                             'contains "ingest" (data ingestion)'),
    (r'collector',                          'contains "collector" (data collection)'),
    (r'events?',                            'contains "event/events" (event tracking)'),
    (r'(^|\.)data\.',                       'data collection endpoint'),
    (r'(^|\.)log\.',                        'logging endpoint'),
    (r'report',                             'contains "report" (reporting)'),
    (r'crash',                              'contains "crash" (crash reporting)'),
    (r'error',                              'contains "error" (error reporting)'),
    (r'diagnostics',                        'contains "diagnostics"'),
    (r'insights',                           'contains "insights" (analytics)'),
    (r'track',                              'contains "track" (tracking)'),
    (r'capture',                            'contains "capture" (data capture)'),
    (r'instrumentation',                    'contains "instrumentation"'),
    (r'monitor(?!\.mozilla)',              'contains "monitor" (monitoring)'),

    # -- Third-Party SaaS Telemetry & Monitoring Vendors --
    (r'datadog(hq)?',                       'contains "datadog" (log/metric ingestion)'),
    (r'sentry\.io',                         'contains "sentry.io" (error tracking)'),
    (r'bugsnag',                            'contains "bugsnag" (error monitoring)'),
    (r'newrelic',                           'contains "newrelic" (APM)'),
    (r'appdynamics',                        'contains "appdynamics" (APM)'),
    (r'dynatrace',                          'contains "dynatrace" (APM)'),
    (r'amplitude',                          'contains "amplitude" (analytics)'),
    (r'mixpanel',                           'contains "mixpanel" (analytics)'),
    (r'segment\.com|\.segment\.io',        'contains "segment" (CDP/telemetry pipeline)'),
    (r'heap',                               'contains "heap" (analytics)'),
    (r'hotjar',                             'contains "hotjar" (user analytics)'),
    (r'fullstory',                          'contains "fullstory" (session replay)'),
    (r'pendo\.io',                          'contains "pendo.io" (product analytics)'),
    (r'appsflyer',                          'contains "appsflyer" (mobile attribution)'),
    (r'adjust\.com',                        'contains "adjust.com" (mobile attribution)'),
    (r'branch\.io',                         'contains "branch.io" (deep linking/tracking)'),
    (r'kochava',                            'contains "kochava" (mobile attribution)'),
    (r'singular\.net',                      'contains "singular.net" (mobile attribution)'),
    (r'mparticle',                          'contains "mparticle" (data platform)'),
    (r'rudderstack',                        'contains "rudderstack" (data pipeline)'),
    (r'snowplow',                           'contains "snowplow" (event analytics)'),
    (r'posthog',                            'contains "posthog" (product analytics)'),
    (r'telemetrydeck',                      'contains "telemetrydeck" (analytics)'),
    (r'crashlytics',                        'contains "crashlytics" (crash reporting)'),
    (r'appcenter',                          'contains "appcenter" (app diagnostics)'),
    (r'rollbar',                            'contains "rollbar" (error tracking)'),
    (r'raygun',                             'contains "raygun" (error tracking)'),
    (r'airbrake',                           'contains "airbrake" (error tracking)'),
    (r'sumologic',                          'contains "sumologic" (log analytics)'),
    (r'splunk',                             'contains "splunk" (log analytics)'),
    (r'firebase(logging)?',                 'contains "firebase" (analytics/logging)'),
    (r'google-analytics',                   'contains "google-analytics" (analytics)'),
    (r'googletagmanager',                   'contains "googletagmanager" (tag management)'),
    (r'app-measurement',                    'contains "app-measurement" (analytics)'),
    (r'app-analytics',                      'contains "app-analytics" (analytics)'),
    (r'visualstudio',                       'contains "visualstudio" (development telemetry)'),
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
    """Return a short reason purely from domain content."""
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

    return 'no_suspicious_pattern_found'

# ---------------------------------------------------------------------------
# Main Routine
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print(c("Usage: python3 find_culprits.py input.txt", "WARNING"), file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "output.tsv"

    print(c("\n[+] Starting 2-column TSV creation", "OKCYAN"))
    print(c(f"    Input  : {input_file}", "OKBLUE"))
    print(c(f"    Output : {output_file}", "OKBLUE"))

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

                reason = classify_domain(domain)
                reason = reason.replace('\t', ' ').replace('\n', ' ')
                reason = strict_ascii_clean(reason)

                # Output schema: domain <TAB> reason
                out_lines.append(f"{domain}\t{reason}")
                valid_domains += 1

    except IOError as e:
        print(c(f"\n[FATAL] Error reading input: {e}", "FAIL"), file=sys.stderr)
        sys.exit(1)

    elapsed = time.time() - start_time
    sys.stderr.write("\r" + " " * 80 + "\r")

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