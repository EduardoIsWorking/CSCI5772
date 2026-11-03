"""Calibrate each detector's thresholds on benign-only traffic.

No attacker labels are used: thresholds are the score quantiles of benign
accounts (drop-time rushers, enthusiasts, shared household phones, carrier
NAT, campus networks, rooted and brand-new phones) at fixed false-positive
budgets.  Calibration seeds are disjoint from evaluation seeds.
"""
from __future__ import annotations

import json

from .sim import run

CAL_SEEDS = (101, 102, 103)
BUDGET = {"throttle": 0.95, "challenge": 0.98}   # benign quantiles (FP budgets)
BLOCK_MARGIN = 0.05   # hard block only above every benign calibration score + margin


def _q(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def calibrate(defenses=("device_only", "behavior_only", "botshield"), seeds=CAL_SEEDS) -> dict:
    out = {}
    for d in defenses:
        scores = []
        for s in seeds:
            r = run("benign_only", d, s)        # thresholds = inf -> monitor only
            scores += [v[0] for v in r["_scores"].values()]
        th = {k: round(_q(scores, q) + 1e-6, 4) for k, q in BUDGET.items()}
        th["block"] = round(max(scores) + BLOCK_MARGIN, 4)
        out[d] = th
    return out


if __name__ == "__main__":
    print(json.dumps(calibrate(), indent=2))
