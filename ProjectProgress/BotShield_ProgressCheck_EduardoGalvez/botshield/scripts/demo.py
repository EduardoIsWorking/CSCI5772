"""Narrated end-to-end demo: Normal system -> Attack -> Defense -> Measured result.

    python scripts/demo.py                       # default attack: S6 timing mimicry
    python scripts/demo.py --scenario phone_farm_rotation
    python scripts/demo.py --list

Writes request-level telemetry for the defended run to evidence/telemetry_demo.sqlite.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from botshield.calibrate import calibrate             # noqa: E402
from botshield.core import Request                    # noqa: E402
from botshield.scenarios import SCENARIOS, build      # noqa: E402
from botshield.sim import run                         # noqa: E402

EVID = os.path.join(os.path.dirname(__file__), "..", "evidence")


def line(r, label):
    det = "  n/a" if r["detection_rate"] != r["detection_rate"] else f"{100*r['detection_rate']:4.0f}%"
    print(f"  {label:26s} bots got {r['bot_units']:3d}/{r['inventory']}  humans got {r['human_units']:3d}"
          f"   bots detected {det}   benign flagged {100*r['false_positive_rate']:4.1f}%"
          f"   scoring {r['latency_us_mean']:5.1f} us/req")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="timing_mimicry")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for k, v in SCENARIOS.items():
            print(f"{k:24s} {v}")
        return

    th_path = os.path.join(EVID, "thresholds.json")
    if os.path.exists(th_path):
        th = json.load(open(th_path))
    else:
        print("Calibrating thresholds on benign traffic...")
        th = calibrate()

    print("\n=== BotShield demo ===")
    print("Store: mobile-app product drop, 100 units at t=60s + 50 restock at t=360s, limit 2 per account")
    print("Benign: 250 drop-day shoppers (20% fast 'enthusiasts', shared household phones, carrier NAT,")
    print("        campus Wi-Fi, 4% rooted phones, 10% brand-new phones) + 150 background shoppers\n")

    print("[1] NORMAL SYSTEM (no attacker)")
    line(run("benign_only", "none", a.seed), "no defense")

    print(f"\n[2] ATTACK: {SCENARIOS[a.scenario]}")
    line(run(a.scenario, "none", a.seed), "no defense")
    line(run(a.scenario, "rate_limit", a.seed), "rate limit (baseline)")

    print("\n[3] DEFENSE (thresholds calibrated on benign traffic only)")
    line(run(a.scenario, "device_only", a.seed, th["device_only"]), "device-only")
    line(run(a.scenario, "behavior_only", a.seed, th["behavior_only"]), "behavior-only")
    os.makedirs(EVID, exist_ok=True)
    db = os.path.join(EVID, "telemetry_demo.sqlite")
    r = run(a.scenario, "botshield", a.seed, th["botshield"], telemetry_db=db)
    line(r, "BotShield (combined)")

    print(f"\n[4] WHY: score breakdown (monitor mode, max score per account)")
    m = run(a.scenario, "botshield", a.seed)
    sc = m["_scores"]
    bots = sorted([(v[0], k, v) for k, v in sc.items() if v[3]], reverse=True)
    ben = sorted([(v[0], k, v) for k, v in sc.items() if not v[3]], reverse=True)
    t = th["botshield"]
    print(f"  thresholds: throttle R>={t['throttle']}, challenge R>={t['challenge']}, block R>={t['block']}")
    if bots:
        s, k, v = bots[len(bots) // 2]
        print(f"  median bot account   {k:12s} D={v[1]:.2f}  B={v[2]:.2f}  R=1-(1-D)(1-B)={s:.2f}")
    s, k, v = ben[len(ben) // 50]
    print(f"  98th-pct benign acct {k:12s} D={v[1]:.2f}  B={v[2]:.2f}  R={s:.2f}")
    print(f"\nTelemetry for the BotShield run written to {os.path.relpath(db)} (table 'requests').")


if __name__ == "__main__":
    main()
