"""Shared data types and the simulated mobile-commerce backend (store)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .attestation import AttestationToken


@dataclass
class Device:
    """A client device as the backend sees it.

    kind: "phone" (genuine hardware), "emulator" (Android emulator / headless
    script), or "spoofed" (emulator presenting another device's id).
    """
    device_id: str
    kind: str
    hw_serial: Optional[str] = None
    rooted: bool = False
    age_days: Optional[float] = None    # None = never seen before this run (first-seen = now)
    accel_profile: str = "handheld"     # handheld | desk | rack | none | spoofed
    claimed_hw: Optional[str] = None    # hw_id a spoofer claims (copied from a real phone)


@dataclass
class Client:
    """One account driving one app instance on one device."""
    account: str
    device: Device
    subnet: str
    is_bot: bool
    kind: str                     # population / attack label
    touches: str = "real"         # real | none | injected
    solver_p: float = 0.95        # probability of passing a step-up challenge
    solver_delay: tuple = (5.0, 15.0)


@dataclass
class Act:
    """What an agent wants to do next (yielded by agent generators)."""
    delay: float
    action: str                   # poll | view | cart | checkout | solve | browse
    parallel: int = 1
    success: Optional[bool] = None  # for "solve"


@dataclass
class Request:
    t: float
    client: Client
    action: str
    touches: int
    accel_var: float
    token: Optional[AttestationToken]
    nonce: str


@dataclass
class Decision:
    action: str = "allow"         # allow | throttle | rate_limited | challenge | block
    delay: float = 0.0
    score: float = 0.0
    d_score: float = 0.0
    b_score: float = 0.0


@dataclass
class Response:
    status: str                   # ok | 429 | challenge | blocked | purchased | soldout | limit
    in_stock: bool = False
    stock: int = 0
    purchased: int = 0
    server_delay: float = 0.0
    t: float = 0.0              # server clock (filled by simulator)


@dataclass
class StoreConfig:
    drops: tuple = ((60.0, 100), (360.0, 50))   # (time, units) inventory releases
    purchase_limit: int = 2
    challenge_valid_s: float = 120.0
    max_challenge_failures: int = 3


class Store:
    """Simulated backend: product page, cart, checkout, step-up challenge.

    Enforces the per-account purchase limit (a control most retailers already
    have) and honours the defense's Decision for each request.
    """

    def __init__(self, cfg: StoreConfig):
        self.cfg = cfg
        self.sold = 0
        self.purchases: dict[str, int] = {}
        self.cleared_until: dict[str, float] = {}
        self.chal_fail: dict[str, int] = {}
        self.locked: set[str] = set()
        self.sales_log: list[tuple[float, str, bool]] = []   # (t, account, is_bot)

    def released(self, t: float) -> int:
        return sum(u for (dt, u) in self.cfg.drops if dt <= t)

    def stock(self, t: float) -> int:
        return max(0, self.released(t) - self.sold)

    def handle(self, req: Request, dec: Decision) -> Response:
        t, acct = req.t, req.client.account
        stock = self.stock(t)
        delay = dec.delay if dec.action == "throttle" else 0.0

        if dec.action == "rate_limited":
            return Response("429", server_delay=0.0)

        if req.action in ("poll", "view", "browse", "cart"):
            if req.action == "cart" and (dec.action == "block" or acct in self.locked):
                return Response("blocked", stock > 0, stock, server_delay=delay)
            return Response("ok", stock > 0, stock, server_delay=delay)

        if req.action == "solve":
            return Response("ok", stock > 0, stock, server_delay=delay)

        if req.action == "checkout":
            if acct in self.locked or dec.action == "block":
                return Response("blocked", stock > 0, stock, server_delay=delay)
            if dec.action == "challenge" and self.cleared_until.get(acct, -1) < t:
                return Response("challenge", stock > 0, stock, server_delay=delay)
            if self.purchases.get(acct, 0) >= self.cfg.purchase_limit:
                return Response("limit", stock > 0, stock, server_delay=delay)
            if stock <= 0:
                return Response("soldout", False, 0, server_delay=delay)
            self.sold += 1
            self.purchases[acct] = self.purchases.get(acct, 0) + 1
            self.sales_log.append((t, acct, req.client.is_bot))
            return Response("purchased", self.stock(t) > 0, self.stock(t), purchased=1, server_delay=delay)

        raise ValueError(req.action)

    def record_challenge(self, acct: str, t: float, success: bool) -> None:
        if success:
            self.cleared_until[acct] = t + self.cfg.challenge_valid_s
        else:
            self.chal_fail[acct] = self.chal_fail.get(acct, 0) + 1
            if self.chal_fail[acct] >= self.cfg.max_challenge_failures:
                self.locked.add(acct)
