"""Discrete-event simulator: drives every client on one clock against the store."""
from __future__ import annotations

import heapq
import math
import random
import sqlite3
import statistics
import time
from typing import Optional

from . import attestation
from .core import Act, Request, Response, Store, StoreConfig
from .defenses import NoDefense, RateLimiter, ScoreDefense, Thresholds
from .scenarios import build

UI = {"poll", "view", "cart", "checkout"}


def _telemetry(c, action, rng):
    """Client-side signals the mobile app SDK attaches to each request."""
    if action in UI:
        touches = rng.randint(1, 4) if c.touches == "real" else rng.randint(1, 3) if c.touches == "injected" else 0
    else:
        touches = 0
    prof = c.device.accel_profile
    accel = {
        "handheld": lambda: rng.lognormvariate(math.log(0.05), 1.0),
        "spoofed": lambda: rng.lognormvariate(math.log(0.05), 1.0),
        "desk": lambda: rng.lognormvariate(math.log(4e-4), 0.5),
        "rack": lambda: rng.lognormvariate(math.log(3e-5), 0.5),
        "none": lambda: 0.0,
    }[prof]()
    return touches, accel


def _token(c, nonce):
    d = c.device
    if d.kind == "phone":
        return attestation.sign_genuine(d.device_id, d.hw_serial, nonce, d.rooted)
    if d.kind == "emulator":
        return attestation.forge(d.device_id, nonce)
    if d.kind == "spoofed":
        return attestation.forge(d.device_id, nonce, claimed_hw_id=d.claimed_hw)
    return None   # headless script: no attestation at all


def make_defense(name: str, pop, thresholds: Optional[dict] = None):
    if name == "none":
        return NoDefense()
    if name == "rate_limit":
        return RateLimiter()
    mode = {"device_only": "device", "behavior_only": "behavior", "botshield": "combined"}[name]
    th = Thresholds(**(thresholds or {}))
    return ScoreDefense(mode, th, pop.device_history, pop.hw_registry)


def run(scenario: str, defense_name: str, seed: int, thresholds: Optional[dict] = None,
        end_t: float = 600.0, telemetry_db: Optional[str] = None) -> dict:
    pop = build(scenario, seed, end_t=end_t)
    store = Store(StoreConfig())
    defense = make_defense(defense_name, pop, thresholds)
    rng = random.Random(seed * 7919 + 1)

    heap, seq = [], 0
    pending = {}
    for i, g in enumerate(pop.gens):
        act = next(g)
        pending[i] = act
        heapq.heappush(heap, (act.delay, seq, i)); seq += 1

    lat_ns = []
    log_rows = [] if telemetry_db else None
    n_req = 0
    decisions = {"throttle": set(), "challenge": set(), "block": set(), "rate_limited": set()}

    while heap:
        t, _, i = heapq.heappop(heap)
        if t > end_t:
            break
        c, act = pop.clients[i], pending[i]
        agg = Response("ok", t=t)
        bought, max_delay = 0, 0.0
        for _ in range(act.parallel):
            nonce = f"{c.account}:{int(t)}"
            touches, accel = _telemetry(c, act.action, rng)
            req = Request(t, c, act.action, touches, accel, _token(c, nonce), nonce)
            t0 = time.perf_counter_ns()
            dec = defense.evaluate(req)
            lat_ns.append(time.perf_counter_ns() - t0)
            if dec.action in decisions:
                if not (dec.action == "challenge" and act.action != "checkout"):
                    decisions[dec.action].add(c.account)
            if act.action == "solve":
                store.record_challenge(c.account, t, bool(act.success))
            resp = store.handle(req, dec)
            defense.observe(req, resp)
            n_req += 1
            bought += resp.purchased
            max_delay = max(max_delay, resp.server_delay)
            if log_rows is not None:
                log_rows.append((round(t, 3), c.account, c.device.device_id, c.subnet, int(c.is_bot), c.kind,
                                 act.action, touches, accel, dec.action, round(dec.score, 4),
                                 round(dec.d_score, 4), round(dec.b_score, 4), resp.status))
            agg = resp
        agg.purchased = bought
        if bought and agg.status != "purchased":
            agg.status = "purchased"
        agg.t = t
        try:
            nxt: Act = pop.gens[i].send(agg)
        except StopIteration:
            continue
        pending[i] = nxt
        heapq.heappush(heap, (t + max_delay + nxt.delay, seq, i)); seq += 1

    # ------------------------------------------------ metrics
    bots = [c.account for c in pop.clients if c.is_bot]
    benign = [c.account for c in pop.clients if not c.is_bot]
    bot_set = set(bots)
    bot_units = sum(1 for (_, a, b) in store.sales_log if b)
    human_units = sum(1 for (_, a, b) in store.sales_log if not b)
    flagged = getattr(defense, "flagged", set())
    out = {
        "scenario": scenario, "defense": defense_name, "seed": seed,
        "n_bots": len(bots), "n_benign": len(benign), "requests": n_req,
        "inventory": store.released(end_t), "bot_units": bot_units, "human_units": human_units,
        "bot_share": bot_units / max(1, bot_units + human_units),
        "detection_rate": (sum(a in flagged for a in bots) / len(bots)) if bots else float("nan"),
        "false_positive_rate": sum(a in flagged for a in benign) / len(benign),
        "benign_challenged": len(decisions["challenge"] - bot_set) / len(benign),
        "benign_blocked": len(decisions["block"] - bot_set) / len(benign),
        "benign_throttled": len(decisions["throttle"] - bot_set) / len(benign),
        "benign_rate_limited": len(decisions["rate_limited"] - bot_set) / len(benign),
        "latency_us_mean": statistics.fmean(lat_ns) / 1000,
        "latency_us_p95": sorted(lat_ns)[int(0.95 * (len(lat_ns) - 1))] / 1000,
    }
    # time-to-detect for bots (seconds from the bot's first request)
    if isinstance(defense, ScoreDefense) and bots:
        ttd = [defense.first_flag_t[a] - defense.first_seen_t[a] for a in bots if a in defense.first_flag_t]
        out["ttd_median_s"] = statistics.median(ttd) if ttd else float("nan")
        out["flagged_before_drop"] = sum(1 for a in bots if defense.first_flag_t.get(a, 1e9) < 60.0) / len(bots)
    else:
        out["ttd_median_s"] = float("nan")
        out["flagged_before_drop"] = float("nan")
    if isinstance(defense, ScoreDefense):
        out["_scores"] = {a: (defense.max_score[a], *defense.max_parts.get(a, (0, 0)), a in bot_set)
                          for a in [c.account for c in pop.clients]}
    if telemetry_db:
        con = sqlite3.connect(telemetry_db)
        con.execute("DROP TABLE IF EXISTS requests")
        con.execute("""CREATE TABLE requests (t REAL, account TEXT, device_id TEXT, subnet TEXT, is_bot INT,
                       kind TEXT, action TEXT, touches INT, accel_var REAL, decision TEXT, score REAL,
                       d_score REAL, b_score REAL, status TEXT)""")
        con.executemany("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", log_rows)
        con.commit(); con.close()
    return out
