"""Quick sanity tests:  python -m pytest -q   (or  python tests/test_botshield.py)"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from botshield import attestation as at                     # noqa: E402
from botshield.features import clip01                       # noqa: E402
from botshield.sim import run                               # noqa: E402


def test_attestation_genuine_and_rooted():
    reg = {at.hw_id_for("SN1"): "SN1"}
    assert at.verify(at.sign_genuine("d1", "SN1", "n"), "n", reg.get) == "ok"
    assert at.verify(at.sign_genuine("d1", "SN1", "n", rooted=True), "n", reg.get) == "weak"


def test_attestation_rejects_forgery_spoof_replay():
    reg = {at.hw_id_for("SN1"): "SN1"}
    assert at.verify(None, "n", reg.get) == "missing"
    assert at.verify(at.forge("emu", "n"), "n", reg.get) == "invalid"
    # spoofer copies the victim's device_id and hardware id but has no hardware key
    assert at.verify(at.forge("d1", "n", claimed_hw_id=at.hw_id_for("SN1")), "n", reg.get) == "invalid"
    # replayed token (stale nonce)
    assert at.verify(at.sign_genuine("d1", "SN1", "old"), "new", reg.get) == "invalid"


def test_id_rotation_keeps_hw_id():
    a = at.sign_genuine("install-1", "SN9", "n")
    b = at.sign_genuine("install-2", "SN9", "n")
    assert a.device_id != b.device_id and a.hw_id == b.hw_id


def test_clip():
    assert clip01(-1) == 0 and clip01(2) == 1 and clip01(0.3) == 0.3


def test_baseline_attack_succeeds_and_botshield_blocks():
    th = {"throttle": 0.25, "challenge": 0.28, "block": 0.47}
    r0 = run("timing_mimicry", "rate_limit", 1)
    r1 = run("timing_mimicry", "botshield", 1, th)
    assert r0["bot_units"] > 30                  # attack is real under the baseline
    assert r1["bot_units"] < r0["bot_units"] // 4
    assert r1["benign_blocked"] < 0.02


def test_each_view_has_a_blind_spot():
    th = {"device_only": {"throttle": 0.13, "challenge": 0.15, "block": 0.28},
          "behavior_only": {"throttle": 0.22, "challenge": 0.25, "block": 0.34}}
    # human-like timing evades behaviour-only, clean real phones evade device-only
    assert run("timing_mimicry", "behavior_only", 1, th["behavior_only"])["detection_rate"] < 0.2
    assert run("phone_farm_scripted", "device_only", 1, th["device_only"])["detection_rate"] < 0.2


def test_deterministic():
    a = run("single_bot", "botshield", 3)
    b = run("single_bot", "botshield", 3)
    for k in ("bot_units", "human_units", "requests"):
        assert a[k] == b[k]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
