#!/usr/bin/env python3
"""
Verify the structural integrity of a nyet blocklist TSV file.
Catches malformed columns, bad timestamps, non-ASCII data, and structural corruption.

Accepts both the old 7-column format and the new 8-column format that adds
an optional `ttl` column (see nyet.c's load_blocklist / BlockEntry.ttl):

    old (7): action  domain  type_flag  time1  time2  rule_id  reason
    new (8): action  domain  type_flag  time1  time2  rule_id  ttl  reason

Usage:
    python3 check_tsv.py output.tsv
"""

import sys
import re
from collections import defaultdict

_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def _colored(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else str(text)

def red(text):    return _colored(text, "91")
def yellow(text): return _colored(text, "93")
def green(text):  return _colored(text, "92")
def bold(text):   return _colored(text, "1")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)

_ERROR_HINTS = {
    "non_ascii":          "Convert non-ASCII characters to punycode or strip them.",
    "column_count":       "Each line must have exactly 7 fields (old format) or 8 (new format, with ttl) tab-separated.",
    "domain_format":      "Domain must be a valid hostname (letters, digits, hyphens; no underscores or spaces).",
    "flag_length":        "Type flag must be exactly one character (e.g. 'S').",
    "timestamp_numeric":  "Timestamps must be numeric epoch values.",
    "timestamp_zero":     "Timestamps must be greater than zero.",
    "rule_id_numeric":    "Rule ID must be an integer.",
    "ttl_numeric":        "ttl column (8-column format only) must be a non-negative integer; 0 means \"use the default\", not \"invalid\".",
    "empty_reason":       "Reason field must not be empty or whitespace.",
}

_WARNING_HINTS = {
    "action": "nyet.c expects action 'B'; other values may be silently ignored.",
    "ambiguous_ttl_note": (
        "nyet.c's loader sniffs the 7th field: if it's all-digit, it's read as "
        "ttl (and the note is dropped) even in an old-format 7-column line. "
        "Quote/prefix this reason with a non-digit, or add an explicit ttl column."
    ),
}


def _is_ascii_printable(line: str) -> bool:
    """Return True only if every character is a printable ASCII value or a tab."""
    return all(32 <= ord(ch) <= 126 or ch == '\t' for ch in line)


def verify_tsv(filepath: str) -> bool:
    errors:   defaultdict[str, list] = defaultdict(list)
    warnings: defaultdict[str, list] = defaultdict(list)

    total_lines = 0
    skipped_lines: list[int] = []      # lines that failed the column-count check

    try:
        with open(filepath, encoding="utf-8") as fh:
            for line_num, raw_line in enumerate(fh, start=1):
                total_lines = line_num

                if line_num % 1000 == 0:
                    sys.stderr.write(
                        f"\rProcessed {line_num:,} lines — "
                        f"{sum(len(v) for v in errors.values())} errors, "
                        f"{sum(len(v) for v in warnings.values())} warnings"
                    )
                    sys.stderr.flush()

                line = raw_line.rstrip("\r\n")
                if not line:
                    continue

                if not _is_ascii_printable(line):
                    errors["non_ascii"].append((line_num, (line[:50] + "…") if len(line) > 50 else line))

                columns = line.split("\t")

                if len(columns) not in (7, 8):
                    errors["column_count"].append((line_num, f"{len(columns)} columns found"))
                    skipped_lines.append(line_num)
                    continue

                if len(columns) == 8:
                    action, domain, type_flag, time1, time2, rule_id, ttl, reason = columns
                else:
                    action, domain, type_flag, time1, time2, rule_id, reason = columns
                    ttl = None  # old format, no ttl column -- not an error

                if action != "B":
                    warnings["action"].append((line_num, f"action='{action}'"))

                if not _DOMAIN_RE.match(domain) or len(domain) > 253:
                    errors["domain_format"].append((line_num, domain))

                if len(type_flag) != 1:
                    errors["flag_length"].append((line_num, f"flag='{type_flag}'"))

                if not time1.isdigit() or not time2.isdigit():
                    errors["timestamp_numeric"].append((line_num, f"time1='{time1}', time2='{time2}'"))
                elif int(time1) <= 0 or int(time2) <= 0:
                    errors["timestamp_zero"].append((line_num, f"time1={time1}, time2={time2}"))

                if not rule_id.isdigit():
                    errors["rule_id_numeric"].append((line_num, f"rule_id='{rule_id}'"))

                # ttl is optional (old 7-column format has none at all), but
                # if the column IS present it must parse as a non-negative
                # int -- nyet.c's loader does atoll() on it with zero
                # validation of its own, so a stray "60s" or "unset" here
                # sails straight past load_blocklist and lands as whatever
                # garbage atoll() decides that string means.
                if ttl is not None and not ttl.isdigit():
                    errors["ttl_numeric"].append((line_num, f"ttl='{ttl}'"))

                if not reason.strip():
                    errors["empty_reason"].append((line_num, "empty"))

                # This is the one real "fat-fingered TSV silently
                # segfault-adjacent-behavior-changes" case: nyet.c's loader
                # doesn't know about column counts, it just sniffs whether
                # the field right after hit_count is all-digit. A 7-column
                # line whose reason happens to be e.g. "12345" gets its
                # "reason" silently reinterpreted as a ttl override with no
                # note at all -- not a crash, but very much not what you
                # meant.
                if len(columns) == 7 and reason.isdigit():
                    warnings["ambiguous_ttl_note"].append((line_num, f"reason='{reason}'"))

    except FileNotFoundError:
        print(f"error: file not found: {filepath}", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"error: could not read file: {exc}", file=sys.stderr)
        return False

    if total_lines >= 1000:
        sys.stderr.write("\r" + " " * 72 + "\r")

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------

    total_errors   = sum(len(v) for v in errors.values())
    total_warnings = sum(len(v) for v in warnings.values())

    print(f"\nFile            : {filepath}")
    print(f"Lines scanned   : {total_lines:,}")
    print(f"Errors          : {red(total_errors) if total_errors else total_errors}")
    print(f"Warnings        : {yellow(total_warnings) if total_warnings else total_warnings}")
    if skipped_lines:
        print(f"Skipped (malformed column count) : {len(skipped_lines)}")

    if errors or warnings:
        print()
        for category, occurrences in errors.items():
            label = category.replace("_", " ").title()
            print(f"  {red(bold(f'[error] {label}'))}  ({len(occurrences)} occurrence{'s' if len(occurrences) != 1 else ''})")
            for line_num, value in occurrences[:5]:
                print(f"    line {line_num}: {value}")
            if len(occurrences) > 5:
                print(f"    … and {len(occurrences) - 5} more")
            if category in _ERROR_HINTS:
                print(f"    hint: {_ERROR_HINTS[category]}")

        for category, occurrences in warnings.items():
            label = category.replace("_", " ").title()
            print(f"  {yellow(bold(f'[warning] {label}'))}  ({len(occurrences)} occurrence{'s' if len(occurrences) != 1 else ''})")
            for line_num, value in occurrences[:5]:
                print(f"    line {line_num}: {value}")
            if len(occurrences) > 5:
                print(f"    … and {len(occurrences) - 5} more")
            if category in _WARNING_HINTS:
                print(f"    hint: {_WARNING_HINTS[category]}")

    is_valid = total_errors == 0
    verdict = green("PASS") if is_valid else red("FAIL")
    print(f"\nResult: {verdict}")
    return is_valid

def main() -> None:
    if len(sys.argv) != 2:
        print("usage: check_tsv.py <file.tsv>", file=sys.stderr)
        sys.exit(1)

    if not verify_tsv(sys.argv[1]):
        sys.exit(1)


if __name__ == "__main__":
    main()