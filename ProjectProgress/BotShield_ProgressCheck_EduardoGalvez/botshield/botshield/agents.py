"""Client behaviour models (benign shoppers and purchasing bots).

Each agent is a Python generator: it yields ``Act`` (what to do and after
how long) and receives the backend ``Response``.  The simulator drives all
agents on a shared clock.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .core import Act, Client


# ---------------------------------------------------------------- helpers
def _u(rng, lo_hi):
    lo, hi = lo_hi
    return rng.uniform(lo, hi)


def buy_flow(c: Client, rng, delays: dict, full_path: bool, parallel: int = 1):
    """view -> cart -> checkout (or direct checkout), handling 429/challenges.

    Returns (units_bought, final_status).
    """
    steps = (["view", "cart", "checkout"] if full_path else ["checkout"])
    for step in steps:
        while True:
            resp = yield Act(_u(rng, delays[step]), step, parallel=parallel if step == "checkout" else 1)
            if resp.status == "429":
                yield Act(_u(rng, (2, 6)), "poll")  # wait, then refresh page
                continue
            break
        if resp.status == "blocked":
            return 0, "blocked"
        if step != "checkout" and not resp.in_stock:
            return 0, "soldout"
    # checkout outcome (possibly after challenges)
    tries = 0
    while resp.status == "challenge" and tries < 4:
        tries += 1
        ok = rng.random() < c.solver_p
        yield Act(_u(rng, c.solver_delay), "solve", success=ok)
        resp = yield Act(_u(rng, (0.3, 1.5)), "checkout", parallel=parallel)
        while resp.status == "429":
            resp = yield Act(_u(rng, (2, 6)), "checkout", parallel=parallel)
    if resp.status == "purchased":
        return resp.purchased, "purchased"
    return 0, resp.status


# ---------------------------------------------------------------- benign
@dataclass
class HumanProfile:
    enthusiast: bool = False     # refreshes fast, saved payment (realistic benign burst)
    keeps_checking: bool = False # keeps checking for restock after sell-out


def human_rusher(c: Client, rng, prof: HumanProfile, end_t: float, drop_t: float = 60.0):
    """A real customer waiting for the drop in the mobile app."""
    want = 1 if rng.random() < 0.85 else 2
    got = 0
    if prof.enthusiast:
        refresh = lambda: rng.uniform(1.2, 3.0)
        delays = {"view": (0.6, 1.5), "cart": (0.8, 2.0), "checkout": (1.0, 3.0)}
    else:
        mu = math.log(rng.uniform(4, 9))
        refresh = lambda: rng.lognormvariate(mu, 0.5)
        delays = {"view": (1.0, 3.0), "cart": (2.0, 5.0), "checkout": (3.0, 10.0)}
    resp = yield Act(rng.uniform(5, 58), "poll")
    while got < want:
        if resp.status == "429":
            resp = yield Act(rng.uniform(5, 15), "poll")
            continue
        if resp.in_stock:
            n, status = yield from buy_flow(c, rng, delays, full_path=True)
            got += n
            if status in ("blocked", "limit", "challenge"):
                return
            resp = yield Act(rng.uniform(1, 3), "poll")
            continue
        # not in stock
        sold_out_a_while = resp.t > drop_t + 40
        if sold_out_a_while and not prof.keeps_checking:
            return
        wait = rng.uniform(15, 45) if sold_out_a_while else refresh()
        resp = yield Act(wait, "poll")


def regular_shopper(c: Client, rng, end_t: float):
    """Background traffic: browses other products; occasionally buys the item."""
    resp = yield Act(rng.uniform(0, end_t - 60), "browse")
    n_actions = rng.randint(4, 25)
    interested = rng.random() < 0.2
    for _ in range(n_actions):
        if interested and resp.in_stock and rng.random() < 0.3:
            yield from buy_flow(c, rng, {"view": (1, 4), "cart": (2, 6), "checkout": (4, 12)}, True)
            return
        resp = yield Act(rng.lognormvariate(math.log(12), 0.7), "poll" if interested else "browse")


# ---------------------------------------------------------------- bots
@dataclass
class BotProfile:
    poll: tuple                  # (lo, hi) seconds between inventory checks
    full_path: bool              # go through view/cart like the UI, or hit checkout API directly
    delays: dict                 # per-step delays once stock appears
    parallel: int = 1            # concurrent checkout requests
    human_timing: bool = False   # sample poll interval from a human-like lognormal
    want: int = 2


def bot(c: Client, rng, p: BotProfile, end_t: float):
    got = 0
    if p.human_timing:
        mu = math.log(rng.uniform(4, 8))
        nxt = lambda: rng.lognormvariate(mu, 0.5)
    else:
        nxt = lambda: _u(rng, p.poll)
    resp = yield Act(rng.uniform(0, 20), "poll")
    while got < p.want:
        if resp.status == "429":
            resp = yield Act(rng.uniform(1, 3), "poll")
            continue
        if resp.in_stock:
            n, status = yield from buy_flow(c, rng, p.delays, p.full_path, p.parallel)
            got += n
            if status == "blocked" or (status == "challenge" and c.solver_p == 0):
                # account is burned; keep probing in case the block is lifted
                resp = yield Act(rng.uniform(20, 40), "poll")
                continue
            resp = yield Act(_u(rng, (0.1, 0.5)), "poll")
            continue
        resp = yield Act(nxt(), "poll")
