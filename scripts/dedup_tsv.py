#!/usr/bin/env python3
"""
Deduplicate a nyet TSV blocklist based strictly on the domain column.
Prevents duplicate entries caused by varying timestamps or rule IDs.

Usage:
    python3 dedup_tsv.py input.tsv output_deduped.tsv
"""

import sys
import os
import tempfile
import time

# ---------- Color helpers ----------
def supports_color():
    """Return True if the terminal supports ANSI color codes."""
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
    # Disable colors for non‑TTY (e.g., pipes, logs)
    for k in COLORS:
        COLORS[k] = ""

def c(text, color="ENDC"):
    """Wrap text with the given color."""
    return f"{COLORS.get(color, '')}{text}{COLORS['ENDC']}"

def deduplicate_tsv(input_path: str, output_path: str):
    seen_domains = set()
    unique_rows = []
    duplicate_count = 0
    malformed_count = 0
    line_count = 0
    start_time = time.time()
    duplicate_examples = []  # store first few duplicates for info

    print(c("\n[+] Starting deduplication", "OKCYAN"))
    print(c(f"    Input : {input_path}", "OKBLUE"))
    print(c(f"    Output: {output_path}", "OKBLUE"))

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line_idx, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                line_count += 1

                # Progress report every 10k lines
                if line_idx % 10000 == 0:
                    sys.stderr.write(
                        f"\r{c('[PROGRESS]', 'OKCYAN')} Processed {line_idx:,} lines, "
                        f"found {len(seen_domains):,} unique so far..."
                    )
                    sys.stderr.flush()

                # Preserve empty lines or comments
                if not line or line.startswith('#'):
                    unique_rows.append(raw_line)
                    continue

                columns = line.split('\t')
                if len(columns) < 2:
                    malformed_count += 1
                    # Optionally print a warning (but too many could flood)
                    if malformed_count <= 5:  # only first few warnings
                        print(c(f"\n[WARN] Line {line_idx} malformed (no tab). Skipping.", "WARNING"))
                    continue

                domain = columns[1].strip().lower()

                if domain in seen_domains:
                    duplicate_count += 1
                    # Store first few duplicate domains for reporting
                    if len(duplicate_examples) < 5:
                        duplicate_examples.append(domain)
                    continue

                seen_domains.add(domain)
                unique_rows.append(raw_line)

    except FileNotFoundError:
        print(c(f"\n[FATAL] Input file not found: {input_path}", "FAIL"))
        sys.exit(1)
    except IOError as e:
        print(c(f"\n[FATAL] Failed to read input file: {e}", "FAIL"))
        sys.exit(1)

    elapsed = time.time() - start_time

    # Clear progress line
    sys.stderr.write("\r" + " " * 80 + "\r")

    # Summary
    print(c("\n" + "=" * 60, "OKCYAN"))
    print(c("  Deduplication Report", "BOLD"))
    print(c("=" * 60, "OKCYAN"))
    print(f"  Total lines read    : {line_count:,}")
    print(f"  Unique domains kept : {c(len(seen_domains), 'OKGREEN')}")
    print(f"  Duplicates dropped  : {c(duplicate_count, 'WARNING')}")
    if duplicate_examples:
        print(f"  Example duplicates  : {', '.join(duplicate_examples)}")
    if malformed_count:
        print(f"  Malformed lines     : {c(malformed_count, 'FAIL')}")
    print(f"  Elapsed time        : {elapsed:.2f} seconds")
    print(c("=" * 60, "OKCYAN"))

    # Write the deduplicated content. In-place (output_path == input_path)
    # writes via a temp file in the same directory + os.replace(), so a
    # crash mid-write can't corrupt the real file -- the input was already
    # fully read and closed above, so this is safe even for in-place use.
    in_place = os.path.abspath(output_path) == os.path.abspath(input_path)
    write_target = output_path
    tmp_path = None
    if in_place:
        fd, tmp_path = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(output_path)) or ".",
            prefix=".dedup_tmp_",
            suffix=".tsv",
        )
        os.close(fd)
        write_target = tmp_path

    try:
        with open(write_target, 'w', encoding='utf-8') as f:
            f.writelines(unique_rows)
        if in_place:
            os.replace(tmp_path, output_path)
        print(c(f"\n[SUCCESS] Cleaned output written to {output_path}", "OKGREEN"))
    except IOError as e:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        print(c(f"\n[FATAL] Failed to write deduplicated file: {e}", "FAIL"))
        sys.exit(1)

def main():
    if len(sys.argv) not in (2, 3):
        print(c("Usage: python3 dedup_tsv.py <file.tsv>                 # in-place", "WARNING"))
        print(c("       python3 dedup_tsv.py <input.tsv> <output.tsv>   # separate output", "WARNING"))
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else sys.argv[1]

    deduplicate_tsv(input_file, output_file)

if __name__ == '__main__':
    main()