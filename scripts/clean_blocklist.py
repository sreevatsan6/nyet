#!/usr/bin/env python3

import sys
import os
import time
import shutil
import tempfile
from collections import defaultdict


# ---------------------------------------------------------------------------
# Terminal color helpers
# ---------------------------------------------------------------------------

def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


COLORS = {
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "BOLD": "\033[1m",
    "END": "\033[0m",
}

if not supports_color():
    for key in COLORS:
        COLORS[key] = ""


def c(text, color="END"):
    return f"{COLORS.get(color, '')}{text}{COLORS['END']}"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BLOCK_FILE = None  # resolved at startup below -- CLI arg > BLOCKLIST_PATH env var, no hardcoded fallback

# Never collapse these domains into their base domain.
# Example: ads.google.com must not become google.com.
PROTECTED_DOMAINS = {
    "google.com",
    "amazonaws.com",
    "cloudfront.net",
    "mozilla.org",
    "mozilla.net",
    "gstatic.com",
    "apple.com",
    "microsoft.com",
    "github.com",
}


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def get_ancestor_candidates(domain):
    """
    Return possible parent domains while skipping the TLD itself.

    Example:
        a.b.c.com -> b.c.com, c.com
    """
    parts = domain.split(".")

    if len(parts) <= 2:
        return []

    return [
        ".".join(parts[i:])
        for i in range(1, len(parts) - 1)
    ]


# ---------------------------------------------------------------------------
# Optimization logic
# ---------------------------------------------------------------------------

def optimize_blocklist():
    if not os.path.exists(BLOCK_FILE):
        print(c(f"ERROR: {BLOCK_FILE} not found.", "FAIL"))
        return

    print("Reading blocklist for optimization...")

    try:
        with open(
            BLOCK_FILE,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as f:
            lines = f.readlines()

    except Exception as e:
        print(c(f"FATAL: Could not read blocklist: {e}", "FAIL"))
        return

    active_entries = {}
    ancestor_map = defaultdict(list)
    lines_map = {}
    ttl_map = {}  # domain -> explicit ttl (int) if the line had one, else None

    for line in lines:
        parts = line.strip().split("\t")

        if len(parts) < 2:
            continue

        domain = parts[1].strip().lower()

        active_entries[domain] = line
        lines_map[domain] = line

        # 8-column (new) format has ttl at index 6; 7-column (old) format
        # doesn't have one at all. Track it so a rollup can carry forward
        # the strictest (max) TTL a collapsed child actually had instead
        # of silently dropping it back to the 60s default.
        ttl_map[domain] = int(parts[6]) if len(parts) >= 8 and parts[6].isdigit() else None

        for ancestor in get_ancestor_candidates(domain):
            if ancestor not in PROTECTED_DOMAINS:
                ancestor_map[ancestor].append(domain)

    rollups = {}

    for ancestor in sorted(
        ancestor_map.keys(),
        key=len,
        reverse=True,
    ):
        children = [
            child
            for child in ancestor_map[ancestor]
            if child in active_entries
        ]

        if len(children) >= 3:
            rollups[ancestor] = children

            for child in children:
                active_entries.pop(child, None)

    if not rollups:
        print(c("Blocklist is already optimized. No compression candidates found.", "GREEN"))
        return

    print(f"\nFound {len(rollups)} compression candidates.")

    new_lines = list(active_entries.values())
    changes_made = 0
    skipped = 0

    for index, (ancestor, children) in enumerate(rollups.items(), 1):

        print(f"\nCandidate {index}/{len(rollups)}")
        print(f"    Parent rule: {c(ancestor, 'BLUE')}")

        print(f"    Child entries: {len(children)}")

        for number, child in enumerate(children[:10], 1):
            print(f"      {number:2}. {child}")

        if len(children) > 10:
            print(f"      ... and {len(children) - 10} more")

        # If any collapsed child had a hand-set TTL, collapsing them away
        # would silently erase it. Surface that before asking, and carry
        # the strictest (max) one forward onto the new parent rule rather
        # than quietly resetting everything to the 60s default.
        child_ttls = [ttl_map[child] for child in children if ttl_map.get(child)]
        rollup_ttl = max(child_ttls) if child_ttls else None
        if child_ttls:
            print(
                c(
                    f"    NOTE: {len(child_ttls)} child(ren) have a custom ttl set "
                    f"(max={rollup_ttl}s) -- if you collapse, the parent rule will "
                    f"be written with ttl={rollup_ttl}s instead of the default, so "
                    "this doesn't just vanish.",
                    "WARNING",
                )
            )

        while True:
            answer = input(
                c(
                    f"    Replace these entries with '{ancestor}'? (y/n): ",
                    "WARNING",
                )
            ).strip().lower()

            if answer in ("y", "yes"):

                timestamp = int(time.time() - 1577836800)
                ttl_field = str(rollup_ttl) if rollup_ttl else "60"

                new_lines.append(
                    f"B\t{ancestor}\tS\t{timestamp}\t{timestamp}\t1\t{ttl_field}\t"
                    "consolidated lineage rollup\n"
                )

                changes_made += 1

                print(
                    c(
                        f"    Added parent rule: {ancestor}",
                        "GREEN",
                    )
                )
                break

            if answer in ("n", "no"):

                for child in children:
                    original = lines_map.get(child)

                    if original:
                        new_lines.append(original)

                skipped += 1

                print(
                    f"    Skipped compression for {ancestor}"
                )
                break

            print("    Please answer 'y' or 'n'.")


    print("\nWriting optimized blocklist...")

    temp_path = None

    try:
        fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(BLOCK_FILE) or ".",
            prefix="blocklist_tmp_",
            suffix=".tsv",
        )

        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.writelines(new_lines)

        shutil.move(temp_path, BLOCK_FILE)

        print(
            c(
                f"SUCCESS: Wrote {len(new_lines)} entries to {BLOCK_FILE}",
                "GREEN",
            )
        )

    except Exception as e:

        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        print(c(f"FATAL: Failed to write blocklist: {e}", "FAIL"))
        print("    Original file was not modified.")
        sys.exit(1)


    print("\nOptimization summary")
    print("--------------------")
    print(f"Total candidates found : {len(rollups)}")
    print(f"Consolidated           : {c(changes_made, 'GREEN')}")
    print(f"Skipped                : {c(skipped, 'WARNING')}")

    print(c("\nYour Radix tree will thank you.", "GREEN"))


if __name__ == "__main__":
    # Priority: CLI arg > BLOCKLIST_PATH env var (set via config.local.bat).
    # No hardcoded fallback path -- a relative "../lists/blocklist.tsv"
    # default only works if you happen to run this from inside scripts/
    # with a sibling lists/ dir, which silently breaks from anywhere else.
    if len(sys.argv) > 1:
        BLOCK_FILE = sys.argv[1]
    elif os.environ.get("BLOCKLIST_PATH"):
        BLOCK_FILE = os.environ["BLOCKLIST_PATH"]
    else:
        print("usage: clean_blocklist.py <blocklist.tsv>", file=sys.stderr)
        print("       (or set BLOCKLIST_PATH, e.g. via config.local.bat)", file=sys.stderr)
        sys.exit(1)
    try:
        optimize_blocklist()
    except KeyboardInterrupt:
        print(c("\nWARNING: Interrupted by user. No changes were saved.", "WARNING"))
        sys.exit(1)