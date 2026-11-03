"""Defenses compared in the experiments.

none          -- no protection (purchase limit only, which the store always enforces)
rate_limit    -- conventional baseline: per-account and per-subnet sliding-window limits
device_only   -- rate_limit + device/identity score D           (ablation)
behavior_only -- rate_limit + behaviour score B                 (ablation)
botshield     -- rate_limit + combined score R = 1-(1-D)(1-B)   (proposed)

Score-based defenses apply graduated mitigation using thresholds calibrated
on benign traffic:
  score >= t_throttle  -> add server-side delay to responses
  score >= t_challenge -> checkout requires a step-up challenge
  score >= t_block     -> cart/checkout denied
An account's score is sticky (max so far): once an account looks like a bot
it does not get to "cool off" right before the drop.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from .core import Decision, Request, Response
from .features import FeatureState

INF = float("inf")


class NoDefense:
    name = "none"

    def evaluate(self, req: Request) -> Decision:
        return Decision()

    def observe(self, req: Request, resp: Response) -> None:
        pass


class RateLimiter:
    """Conventional baseline (token-bucket style sliding windows)."""
    name = "rate_limit"

    def __init__(self, acct_limit=20, subnet_limit=200, window=10.0, cooldown=10.0):
        self.acct_limit, self.subnet_limit = acct_limit, subnet_limit
        self.window, self.cooldown = window, cooldown
        self.acct = defaultdict(deque)
        self.subnet = defaultdict(deque)
        self.blocked_until = {}
        self.flagged = set()

    def _hit(self, dq, t, limit) -> bool:
        dq.append(t)
        while dq and dq[0] < t - self.window:
            dq.popleft()
        return len(dq) > limit

    def evaluate(self, req: Request) -> Decision:
        t, a, s = req.t, req.client.account, req.client.subnet
        if self.blocked_until.get(a, -1) > t:
            return Decision("rate_limited")
        over_a = self._hit(self.acct[a], t, self.acct_limit)
        over_s = self._hit(self.subnet[s], t, self.subnet_limit)
        if over_a or over_s:
            self.blocked_until[a] = t + self.cooldown
            self.flagged.add(a)
            return Decision("rate_limited")
        return Decision()

    def observe(self, req, resp):
        pass


@dataclass
class Thresholds:
    throttle: float = INF
    challenge: float = INF
    block: float = INF
    throttle_delay: float = 2.0


class ScoreDefense:
    """Rate limiter + a risk score (device-only, behaviour-only or combined)."""

    def __init__(self, mode: str, thresholds: Thresholds, device_history, hw_registry):
        assert mode in ("device", "behavior", "combined")
        self.mode = mode
        self.name = {"device": "device_only", "behavior": "behavior_only", "combined": "botshield"}[mode]
        self.th = thresholds
        self.rl = RateLimiter()
        self.fs = FeatureState(device_history, hw_registry)
        self.max_score = defaultdict(float)
        self.max_parts = {}                 # account -> (D, B) at its max score
        self.first_flag_t = {}              # account -> time score first crossed challenge threshold
        self.first_seen_t = {}
        self.flagged = set()

    def pick(self, D, B, R):
        return D if self.mode == "device" else B if self.mode == "behavior" else R

    def evaluate(self, req: Request) -> Decision:
        a = req.client.account
        self.first_seen_t.setdefault(a, req.t)
        self.fs.update(req)
        D, B, R, _, _ = self.fs.scores(req)
        s = self.pick(D, B, R)
        if s > self.max_score[a]:
            self.max_score[a] = s
            self.max_parts[a] = (D, B)
        s = self.max_score[a]
        if s >= self.th.challenge and a not in self.first_flag_t:
            self.first_flag_t[a] = req.t
            self.flagged.add(a)
        base = self.rl.evaluate(req)
        if base.action == "rate_limited":
            self.flagged.add(a)
            return Decision("rate_limited", score=s, d_score=D, b_score=B)
        if s >= self.th.block and req.action in ("cart", "checkout"):
            return Decision("block", score=s, d_score=D, b_score=B)
        if s >= self.th.challenge and req.action == "checkout":
            return Decision("challenge", score=s, d_score=D, b_score=B)
        if s >= self.th.throttle:
            return Decision("throttle", self.th.throttle_delay, score=s, d_score=D, b_score=B)
        return Decision(score=s, d_score=D, b_score=B)

    def observe(self, req, resp):
        self.fs.observe(req, resp)
