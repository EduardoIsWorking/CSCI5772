"""Run every scenario x defense x seed, plus monitor-mode ROC analysis.

Outputs (in evidence/):
  thresholds.json          calibrated thresholds per detector
  results_runs.csv         one row per (scenario, defense, seed) enforcement run
  results_summary.csv      mean over seeds
  roc_points.csv           detection rate at fixed benign FPR, per detector & scenario (monitor mode)
  account_scores.csv       per-account max D, B, R (monitor mode) for score plots

Usage:  python scripts/run_experiments.py [--seeds 5]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from botshield.calibrate import calibrate          # noqa: E402
from botshield.scenarios import SCENARIOS          # noqa: E402
from botshield.sim import run                      # noqa: E402

DEFENSES = ["none", "rate_limit", "device_only", "behavior_only", "botshield"]
SCORE_DEFENSES = ["device_only", "behavior_only", "botshield"]
EVID = os.path.join(os.path.dirname(__file__), "..", "evidence")
FPR_POINTS = (0.01, 0.02, 0.05)


def auc(pos, neg):
    """Probability a random bot outranks a random benign account (ties = 0.5)."""
    if not pos or not neg:
        return float("nan")
    neg_sorted = sorted(neg)
    import bisect
    tot = 0.0
    for p in pos:
        lo = bisect.bisect_left(neg_sorted, p)
        hi = bisect.bisect_right(neg_sorted, p)
        tot += lo + 0.5 * (hi - lo)
    return tot / (len(pos) * len(neg))


def tpr_at_fpr(pos, neg, fpr):
    neg_sorted = sorted(neg, reverse=True)
    k = int(math.floor(fpr * len(neg_sorted)))
    thr = neg_sorted[k] if k < len(neg_sorted) else -1
    return sum(p > thr for p in pos) / len(pos)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    args = ap.parse_args()
    seeds = list(range(1, args.seeds + 1))
    os.makedirs(EVID, exist_ok=True)
    t0 = time.time()

    print("Calibrating thresholds on benign-only traffic (seeds 101-105)...")
    th = calibrate(seeds=(101, 102, 103, 104, 105))
    json.dump(th, open(os.path.join(EVID, "thresholds.json"), "w"), indent=2)
    print(json.dumps(th, indent=2))

    # ---------------------------------------------------- enforcement runs
    rows = []
    for sc in SCENARIOS:
        for d in DEFENSES:
            for s in seeds:
                r = run(sc, d, s, th.get(d))
                r.pop("_scores", None)
                rows.append(r)
        print(f"  {sc:24s} done ({time.time() - t0:.0f}s)")
    keys = list(rows[0].keys())
    with open(os.path.join(EVID, "results_runs.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, keys); w.writeheader(); w.writerows(rows)

    num = [k for k in keys if k not in ("scenario", "defense", "seed")]
    summ = []
    for sc in SCENARIOS:
        for d in DEFENSES:
            grp = [r for r in rows if r["scenario"] == sc and r["defense"] == d]
            out = {"scenario": sc, "defense": d}
            for k in num:
                vals = [r[k] for r in grp if not (isinstance(r[k], float) and math.isnan(r[k]))]
                out[k] = round(statistics.fmean(vals), 4) if vals else ""
            summ.append(out)
    with open(os.path.join(EVID, "results_summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, ["scenario", "defense"] + num); w.writeheader(); w.writerows(summ)

    # ---------------------------------------------------- monitor-mode ROC
    roc, acc_rows = [], []
    for sc in SCENARIOS:
        if sc == "benign_only":
            continue
        for d in SCORE_DEFENSES:
            pos, neg = [], []
            for s in seeds:
                r = run(sc, d, s)           # no thresholds -> observe only, attacker unimpeded
                for acct, (score, D, B, is_bot) in r["_scores"].items():
                    (pos if is_bot else neg).append(score)
                    if d == "botshield" and s == 1:
                        acc_rows.append({"scenario": sc, "account": acct, "is_bot": int(is_bot),
                                         "R": round(score, 4), "D": round(D, 4), "B": round(B, 4)})
            row = {"scenario": sc, "detector": d, "auc": round(auc(pos, neg), 4)}
            for fp in FPR_POINTS:
                row[f"tpr_at_fpr_{int(fp*100)}pct"] = round(tpr_at_fpr(pos, neg, fp), 4)
            roc.append(row)
        print(f"  ROC {sc:20s} done ({time.time() - t0:.0f}s)")
    with open(os.path.join(EVID, "roc_points.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, list(roc[0].keys())); w.writeheader(); w.writerows(roc)
    with open(os.path.join(EVID, "account_scores.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, list(acc_rows[0].keys())); w.writeheader(); w.writerows(acc_rows)
    print(f"Done in {time.time() - t0:.0f}s. Results in evidence/")


if __name__ == "__main__":
    main()
