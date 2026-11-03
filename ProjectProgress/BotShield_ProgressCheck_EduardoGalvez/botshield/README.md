# BotShield — Progress Check (CSCI 5772)

**Eduardo Galvez** · Detecting automated purchasing bots in a mobile-commerce app
by combining hardware-backed device signals with in-app behavior signals.

The project runs this path end to end:

**Normal system → Attack → Defense → Measured result**

1. A simulated **mobile shopping app backend** runs a limited product drop.
   It holds 100 units at t = 60 s and a 50-unit restock at t = 360 s, with a 2-per-account limit.
   400 legitimate shoppers use the app, including a realistic drop-time rush.
2. **Nine attack scenarios** reproduce automated scalping (OWASP OAT-005).
   Under the conventional rate-limiting baseline, bots capture up to **~40% of the inventory**.
3. **BotShield** scores every request. It applies a throttle, a step-up challenge or a block,
   using thresholds calibrated on benign traffic only.
4. Scripts measure inventory captured by bots, detection rate, benign false positives
   and friction, time to detect, and scoring latency.

The results are in `evidence/` and summarized in `docs/progress_summary.pdf`.

---

## Requirements

- Python **3.10+** (tested on 3.13)
- `matplotlib` and `numpy` are needed only for the plots.
  The simulator itself uses the standard library only (including `sqlite3` for telemetry).

```bash
python3 -m venv .venv && source .venv/bin/activate     # optional
pip install -r requirements.txt
```

## Reproduce the results

```bash
python scripts/demo.py                      # ~5 s narrated demo (normal -> attack -> defense)
python scripts/demo.py --list               # list attack scenarios
python scripts/demo.py --scenario phone_farm_rotation
python tests/test_botshield.py              # sanity tests (or: python -m pytest -q)
python scripts/run_experiments.py           # full suite: 10 scenarios (incl. benign-only) x 5 defenses x 5 seeds (~3 min)
python scripts/make_plots.py                # regenerate evidence/fig*.png from the CSVs
```

Every run is deterministic for a given seed.
Calibration seeds (101–105) are disjoint from evaluation seeds (1–5).

## Project layout

```
botshield/
  attestation.py   simulated hardware-backed attestation (Play Integrity / App Attest analogue)
  core.py          data types + Store (inventory drops, purchase limit, checkout, challenges)
  agents.py        benign shopper and bot behaviour models (generator-based agents)
  scenarios.py     benign population + the 9 attack scenarios
  features.py      online feature extraction, device score D, behaviour score B, combined R
  defenses.py      none / rate-limit baseline / device-only / behavior-only / BotShield
  calibrate.py     threshold calibration on benign-only traffic
  sim.py           discrete-event simulator, metrics, optional SQLite telemetry
scripts/
  demo.py          narrated demo used in the progress video
  run_experiments.py  full experiment + ROC analysis -> evidence/*.csv
  make_plots.py    figures -> evidence/fig*.png
tests/test_botshield.py
evidence/          thresholds, CSV results, figures, demo telemetry (SQLite), logs
docs/              progress summary (PDF + Markdown), presentation outline
```

## How the risk score works

These answer the "specify how the risk score is calculated" proposal feedback.

Each request updates per-account, per-device, per-hardware-key and per-subnet state.
Every component below is a number in [0, 1].

**Device score D** asks whether this is a genuine phone that belongs to one person.

| Component | Weight | Signal |
|---|---|---|
| `attest` | .30 | Attestation verdict: ok = 0, rooted / "basic" = 0.5, invalid or missing = 1 |
| `hw_fanout` | .15 | Number of app device IDs seen on the **same attested hardware key**: (n−1)/2 |
| `acct_fanout` | .15 | Number of *attested* accounts on one device: (n−1)/3 |
| `fresh` | .15 | Device first seen < 1 h ago = 1, < 1 day = 0.5 |
| `sensor` | .15 | Median accelerometer variance < 1e-4 (emulator or phone on a rack) = 1, < 1e-3 = 0.5 |
| `subnet` | .10 | Distinct devices on the same /24 in 60 s: (n−10)/30 |

**Behavior score B** asks whether this account acts like a person using the app.

| Component | Weight | Signal |
|---|---|---|
| `rate` | .25 | Requests/s over 10 s: (r−0.5)/2.5 |
| `regular` | .20 | Low coefficient of variation of inter-request gaps (CV < 0.6) |
| `speed` | .25 | Seconds from first seeing stock to checkout (≤ 1 s = 1, ≥ 6 s = 0) |
| `funnel` | .15 | Checkout without cart (+0.6) and/or without product view (+0.4) |
| `no_touch` | .15 | Fraction of UI requests with no touch events from the app SDK |

**Combined score:**

> R = 1 − (1 − D)(1 − B)

This is a noisy-OR. A strong signal from either view is kept: an emulator farm with perfect
human timing still has a high D. Two moderate signals also add up: D = 0.4 and B = 0.4 gives R = 0.64.

An account's score is **sticky**: it keeps the maximum seen so far.
The mitigation is graduated:

- R ≥ throttle: responses are delayed.
- R ≥ challenge: checkout requires a step-up challenge.
- R ≥ block: cart and checkout are denied.

Thresholds come from benign-only calibration:

- The throttle threshold is the 95th percentile of benign scores.
- The challenge threshold is the 98th percentile.
- The block threshold is the maximum benign score plus a 0.05 margin.

See `evidence/thresholds.json`.

## Why device signals survive ID rotation and spoofing

This answers the second proposal feedback item.

- **Rotating the app device ID is free, but the hardware key is not.**
  A reinstall or app clone on the same phone produces a new `device_id` with the same
  attested `hw_id`, so `hw_fanout` rises (scenario S7).
- **Copying a real customer's device ID fails attestation.**
  The spoofer cannot sign the server nonce with that phone's hardware key.
  Verdicts are tracked per *(device ID, account)*, so the spoofer is penalized and the
  victim is not (scenario S3).
- **Emulators and headless scripts** have no hardware key (`attest` = 1), and they report
  flat or no motion sensor data.
- **Fresh IDs look fresh.** A rotated ID has no server-side history at drop time.

## Mobile / edge connection

This answers the third proposal feedback item.

The protected system is a **mobile app** storefront.
The app SDK attaches device-side telemetry to each request:

- a hardware attestation token
- touch-event counts
- accelerometer variance

The two detection features that cannot exist for a plain web client come from this mobile side:
hardware attestation and physical-sensor liveness.
The attacker side is also mobile-specific: Android emulator farms, cloned or reinstalled app
instances, and racks of real phones driven by automation (phone farms).

## Limitations (current)

- This is a simulated testbed, not a live store.
  Attestation is simulated with HMAC instead of Google Play Integrity or Apple App Attest.
- Weights are hand-set and documented, not learned.
  Thresholds are calibrated, but the weights are not tuned on attacker data.
- **S9 (real aged phones plus human-like timing) remains the hard case.**
  At a 2% benign false-positive rate only about a third of these bots are detected.
  Purchase limits and queueing remain necessary controls.
- The step-up challenge is modeled with pass probabilities.
  Bots are assumed to use a CAPTCHA-solving service with a 60% pass rate.

See `docs/progress_summary.pdf` for current results and remaining work.

## References

- OWASP Automated Threats to Web Applications, OAT-005 Scalping
- OWASP Bot Management and Anti-Automation Cheat Sheet
- FingerprintJS BotD (browser-automation detection; a reference point for device signals)
- Google Play Integrity API and Apple App Attest, which the attestation simulation models
