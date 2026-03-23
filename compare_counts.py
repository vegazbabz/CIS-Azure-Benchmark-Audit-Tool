# mypy: ignore-errors
import json
import os
from collections import Counter


def load_counts(base):
    counts = Counter()
    for f in os.listdir(os.path.join(base, "cis_checkpoints")):
        if not f.endswith(".json"):
            continue
        with open(os.path.join(base, "cis_checkpoints", f)) as fh:
            cp = json.load(fh)
        results = cp.get("results", cp.get("Results", []))
        for r in results:
            cid = r.get("control_id", r.get("ControlId", ""))
            counts[cid] += 1
    return counts


ps = load_counts(r"C:\Temp\CISAzureBenchmark-PS")
py = load_counts(r"C:\Temp\cis")
all_keys = sorted(set(ps) | set(py), key=lambda x: [int(p) if p.isdigit() else p for p in x.split(".")])
print(f"{'Control':<14} {'PS':>4} {'PY':>4} {'Diff':>5}  Note")
print("-" * 50)
for k in all_keys:
    p, y = ps.get(k, 0), py.get(k, 0)
    d = p - y
    if d != 0:
        note = "PS only" if y == 0 else ("PY only" if p == 0 else "count diff")
        print(f"{k:<14} {p:>4} {y:>4} {d:>+5}  {note}")
print("-" * 50)
print(f"{'TOTAL':<14} {sum(ps.values()):>4} {sum(py.values()):>4} {sum(ps.values())-sum(py.values()):>+5}")
