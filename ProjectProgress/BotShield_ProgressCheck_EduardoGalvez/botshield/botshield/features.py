"""Online feature extraction and the BotShield risk score.

Every request updates per-account, per-device, per-hardware and per-subnet
state in O(1) amortised time, then two sub-scores are computed:

  D (device / identity score)  -- is this a genuine, stable, uniquely-owned phone?
  B (behaviour score)          -- does this account act like a person in the app?

Each sub-score is a weighted sum of components in [0, 1] (weights sum to 1):

  D = .30*attest + .15*hw_fanout + .15*acct_fanout + .15*fresh + .15*sensor + .10*subnet
  B = .25*rate   + .20*regular   + .25*speed       + .15*funnel + .15*no_touch

and the combined BotShield score is a noisy-OR:

  R = 1 - (1 - D) * (1 - B)

i.e. "probability that at least one view says bot" if D and B were
independent bot probabilities.  Noisy-OR keeps a strong signal from either
view (an emulator farm with perfect human timing still has high D) while
letting two moderate signals add up (0.4 and 0.4 -> 0.64).

Thresholds are NOT hand-picked: each detector (D-only, B-only, R) is
calibrated on benign-only traffic -- including the drop-time rush, shared
household devices, carrier NAT and campus networks -- at fixed false-positive
budgets (see calibrate.py).
"""
from __future__ import annotations

import statistics
from collections import defaultdict, deque

from .attestation import verify
from .core import Request, Response


def clip01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


DEVICE_W = {"attest": .30, "hw_fanout": .15, "acct_fanout": .15, "fresh": .15, "sensor": .15, "subnet": .10}
BEHAV_W = {"rate": .25, "regular": .20, "speed": .25, "funnel": .15, "no_touch": .15}
ATTEST_SCORE = {"ok": 0.0, "weak": 0.5, "invalid": 1.0, "missing": 1.0}
UI_ACTIONS = {"poll", "view", "cart", "checkout"}


class FeatureState:
    def __init__(self, device_history: dict[str, float], hw_registry: dict[str, str]):
        # server-side history (devices seen before this sale) and the
        # platform's attestation verification service
        self.device_history = device_history
        self.hw_registry = hw_registry
        # per account
        self.req_times = defaultdict(lambda: deque())
        self.gaps = defaultdict(lambda: deque(maxlen=20))
        self.last_t = {}
        self.touch_hist = defaultdict(lambda: deque(maxlen=20))
        self.instock_seen = {}            # first time this account was shown stock (current window)
        self.imposed = defaultdict(float) # server-side throttle delay added since instock_seen
        self.funnel = defaultdict(set)    # actions since last checkout
        self.sticky = defaultdict(lambda: {"speed": 0.0, "funnel": 0.0})
        # per device / hardware / subnet
        self.dev_accounts = defaultdict(set)
        self.dev_first_seen = {}
        self.dev_attest = {}
        self.dev_accel = defaultdict(lambda: deque(maxlen=10))
        self.hw_devices = defaultdict(set)
        self.subnet_devs = defaultdict(dict)

    # ------------------------------------------------------------ update
    def update(self, req: Request) -> None:
        t, c = req.t, req.client
        a, dev = c.account, c.device.device_id
        # account timing
        dq = self.req_times[a]
        dq.append(t)
        while dq and dq[0] < t - 10:
            dq.popleft()
        if a in self.last_t:
            self.gaps[a].append(t - self.last_t[a])
        self.last_t[a] = t
        if req.action in UI_ACTIONS:
            self.touch_hist[a].append(req.touches > 0)
        if req.action in ("view", "cart"):
            self.funnel[a].add(req.action)
        # device identity.  The attestation verdict is kept per (device_id, account):
        # a spoofer who copies a real customer's device_id gets "invalid" for
        # ITSELF but cannot poison the victim's verdict, and only accounts that
        # proved possession of the device's hardware key count toward fan-out.
        key = (dev, a)
        if key not in self.dev_attest or self.dev_attest[key] == "ok":
            verdict = verify(req.token, req.nonce, self.hw_registry.get)
            self.dev_attest[key] = verdict
            if req.token is not None and req.token.hw_id and verdict in ("ok", "weak"):
                self.hw_devices[req.token.hw_id].add(dev)
        if self.dev_attest[key] in ("ok", "weak"):
            self.dev_accounts[dev].add(a)
        if dev not in self.dev_first_seen:
            age = self.device_history.get(dev)
            self.dev_first_seen[dev] = t - (age * 86400 if age is not None else 0.0)
        self.dev_accel[dev].append(req.accel_var)
        sd = self.subnet_devs[c.subnet]
        sd[dev] = t
        if len(sd) > 40:  # prune stale entries occasionally
            for k in [k for k, v in sd.items() if v < t - 60]:
                del sd[k]

    def observe(self, req: Request, resp: Response) -> None:
        a = req.client.account
        if resp.in_stock and a not in self.instock_seen:
            self.instock_seen[a] = req.t
            self.imposed[a] = 0.0
        if a in self.instock_seen:
            self.imposed[a] += resp.server_delay
        if not resp.in_stock and req.action in ("poll", "view"):
            self.instock_seen.pop(a, None)
        if req.action == "checkout" and resp.status in ("purchased", "soldout", "limit"):
            self.funnel[a] = set()   # funnel restarts after a completed checkout attempt

    # ------------------------------------------------------------ scores
    def device_components(self, req: Request) -> dict:
        t, c = req.t, req.client
        dev = c.device.device_id
        tok = req.token
        hw_n = len(self.hw_devices.get(tok.hw_id, ())) if (tok and tok.hw_id) else 0
        age_s = t - self.dev_first_seen[dev]
        accel = statistics.median(self.dev_accel[dev])
        n_sub = sum(1 for v in self.subnet_devs[c.subnet].values() if v >= t - 60)
        return {
            "attest": ATTEST_SCORE[self.dev_attest[(dev, c.account)]],
            "hw_fanout": clip01((hw_n - 1) / 2),
            # unattested clients cannot prove they share a device, so fan-out is
            # only measured among attested accounts (attest already scores the rest)
            "acct_fanout": clip01((len(self.dev_accounts[dev]) - 1) / 3),
            "fresh": 1.0 if age_s < 3600 else 0.5 if age_s < 86400 else 0.0,
            "sensor": 1.0 if accel < 1e-4 else 0.5 if accel < 1e-3 else 0.0,
            "subnet": clip01((n_sub - 10) / 30),
        }

    def behavior_components(self, req: Request) -> dict:
        t, a = req.t, req.client.account
        rate = len(self.req_times[a]) / 10.0
        g = self.gaps[a]
        regular = 0.0
        if len(g) >= 6:
            m = statistics.fmean(g)
            if m > 0:
                cv = statistics.pstdev(g) / m
                regular = clip01((0.6 - cv) / 0.5)
        st = self.sticky[a]
        if req.action == "checkout":
            seen = self.instock_seen.get(a)
            if seen is not None:
                # measure the CLIENT's reaction time: subtract delay our own throttle added,
                # otherwise throttling a bot would hide its speed signal
                think = t - seen - self.imposed[a]
                st["speed"] = max(st["speed"], clip01((6.0 - think) / 5.0))
            f = self.funnel[a]
            st["funnel"] = max(st["funnel"], (0.6 if "cart" not in f else 0) + (0.4 if "view" not in f else 0))
        th = self.touch_hist[a]
        no_touch = (1 - sum(th) / len(th)) if len(th) >= 3 else 0.0
        return {
            "rate": clip01((rate - 0.5) / 2.5),
            "regular": regular,
            "speed": st["speed"],
            "funnel": st["funnel"],
            "no_touch": no_touch,
        }

    def scores(self, req: Request) -> tuple[float, float, float, dict, dict]:
        dc = self.device_components(req)
        bc = self.behavior_components(req)
        D = sum(DEVICE_W[k] * v for k, v in dc.items())
        B = sum(BEHAV_W[k] * v for k, v in bc.items())
        R = 1 - (1 - D) * (1 - B)
        return D, B, R, dc, bc
