import os
import sys
from collections import defaultdict
from pathlib import Path

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
    print("usage: tree_stats.py <blocklist.tsv>", file=sys.stderr)
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
            parent += (label,)

levels = defaultdict(list)

for (depth, _), kids in children.items():
    levels[depth].append(len(kids))

print(f"{'Depth':>5} {'Parents':>8} {'Avg':>8} {'Max':>8}")

for depth in sorted(levels):
    vals = levels[depth]
    print(f"{depth:5} {len(vals):8} {sum(vals)/len(vals):8.2f} {max(vals):8}")