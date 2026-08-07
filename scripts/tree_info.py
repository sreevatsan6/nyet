#!/usr/bin/env python3

import os
import sys
from collections import defaultdict
from pathlib import Path

# (depth, parent_path) -> set(children)
children = defaultdict(set)

# Priority: CLI arg > BLOCKLIST_PATH env var (set via config.local.bat).
# No hardcoded fallback path -- a relative "../lists/blocklist.tsv" default
# only works if you happen to run this from inside scripts/ with a sibling
# lists/ dir, which silently breaks from anywhere else. Give a real path.
if len(sys.argv) > 1:
    blocklist_path = Path(sys.argv[1])
elif os.environ.get("BLOCKLIST_PATH"):
    blocklist_path = Path(os.environ["BLOCKLIST_PATH"])
else:
    print("usage: tree_info.py <blocklist.tsv>", file=sys.stderr)
    print("       (or set BLOCKLIST_PATH, e.g. via config.local.bat)", file=sys.stderr)
    sys.exit(1)

with blocklist_path.open(encoding="utf-8") as f:
    for line in f:
        cols = line.rstrip().split("\t")
        if len(cols) < 2:
            continue

        labels = cols[1].lower().split(".")[::-1]

        parent = ()

        for depth, label in enumerate(labels):
            children[(depth, parent)].add(label)
            parent = parent + (label,)

# Print statistics
current_depth = -1

for (depth, parent), kids in sorted(children.items()):
    if depth != current_depth:
        current_depth = depth
        print()
        print(f"Depth {depth}")

    if parent:
        name = ".".join(reversed(parent))
    else:
        name = "<root>"

    print(f"{name:<40} {len(kids):5} children")