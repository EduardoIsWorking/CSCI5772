"""Populations: benign shoppers (always present) plus one attack scenario."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from . import agents
from .attestation import hw_id_for
from .core import Client, Device

FAST = {"view": (0.05, 0.2), "cart": (0.05, 0.2), "checkout": (0.05, 0.3)}
HUMANISH = {"view": (0.6, 1.5), "cart": (0.8, 2.0), "checkout": (1.0, 3.0)}   # = enthusiast human

SCENARIOS = {
    "benign_only":           "No attacker (false-positive reference)",
    "single_bot":            "S1: one scripted bot, one account, direct checkout API",
    "multi_acct_same_device":"S2: 10 accounts on one emulator, datacenter IP",
    "rotating_ids":          "S3: 30 accounts, rotated/spoofed device IDs, residential proxies, fake sensors",
    "high_freq_monitor":     "S4: 5 accounts polling inventory every ~0.1 s",
    "parallel_checkout":     "S5: 10 accounts firing 8 concurrent checkouts each",
    "timing_mimicry":        "S6: 30 emulators with human-like timing, injected touches, fake sensors",
    "phone_farm_rotation":   "S7: 10 real phones x 3 app reinstalls (device-ID rotation), scripted",
    "phone_farm_scripted":   "S8: 30 real aged phones on a motion rig, one account each, scripted fast checkout",
    "phone_farm_mimicry":    "S9: 30 real aged phones on a shelf, human-like timing (hardest case)",
}


@dataclass
class Population:
    clients: list = field(default_factory=list)
    gens: list = field(default_factory=list)
    device_history: dict = field(default_factory=dict)   # device_id -> age in days (server knew it before)
    hw_registry: dict = field(default_factory=dict)      # hw_id -> serial (attestation service)


def _phone(pop, rng, dev_id, serial, age_days, rooted=False, accel="handheld", known=True):
    d = Device(dev_id, "phone", hw_serial=serial, rooted=rooted, age_days=age_days if known else None,
               accel_profile=accel)
    pop.hw_registry[hw_id_for(serial)] = serial
    if known:
        pop.device_history[dev_id] = age_days
    return d


def build(scenario: str, seed: int, n_rushers=250, n_regular=150, end_t=600.0, drop_t=60.0) -> Population:
    rng = random.Random(seed)
    pop = Population()

    # ------------------------------------------------ benign users
    def subnet_for(i):
        r = rng.random()
        if r < 0.50:
            return f"home-{i}"
        if r < 0.85:
            return f"cgnat-{rng.randrange(15)}"
        return f"campus-{rng.randrange(3)}"

    benign_devices = []
    shared_pending = None
    for i in range(n_rushers + n_regular):
        rusher = i < n_rushers
        if rusher and shared_pending is not None:
            dev, sub = shared_pending            # household: second account on same phone
            shared_pending = None
        else:
            new_phone = rng.random() < 0.10
            age = rng.uniform(0.05, 3) if new_phone else rng.uniform(30, 900)
            dev = _phone(pop, rng, f"dev-b{i}", f"SN-b{i}", age,
                         rooted=rng.random() < 0.04,
                         accel="desk" if rng.random() < 0.12 else "handheld")
            sub = subnet_for(i)
            benign_devices.append(dev)
            if rusher and rng.random() < 0.08:
                shared_pending = (dev, sub)
        c = Client(f"acct-b{i}", dev, sub, False, "rusher" if rusher else "regular")
        pop.clients.append(c)
        crng = random.Random(rng.random())
        if rusher:
            prof = agents.HumanProfile(enthusiast=crng.random() < 0.20, keeps_checking=crng.random() < 0.40)
            pop.gens.append(agents.human_rusher(c, crng, prof, end_t, drop_t))
        else:
            pop.gens.append(agents.regular_shopper(c, crng, end_t))

    # ------------------------------------------------ attacker
    def add_bot(idx, dev, subnet, profile, touches="none", solver=0.0):
        c = Client(f"acct-x{idx}", dev, subnet, True, scenario, touches=touches,
                   solver_p=solver, solver_delay=(8.0, 20.0))
        pop.clients.append(c)
        pop.gens.append(agents.bot(c, random.Random(rng.random()), profile, end_t))

    direct = lambda poll, par=1: agents.BotProfile(poll=poll, full_path=False, delays=FAST, parallel=par)

    if scenario == "benign_only":
        pass
    elif scenario == "single_bot":
        add_bot(0, Device("script-0", "script", accel_profile="none"), "dc-1", direct((0.2, 0.4)))
    elif scenario == "multi_acct_same_device":
        emu = Device("emu-shared", "emulator", accel_profile="none")
        for k in range(10):
            add_bot(k, emu, "dc-1", direct((0.5, 1.0)))
    elif scenario == "rotating_ids":
        for k in range(30):
            if k % 2 == 0:   # spoof the device_id of a real customer's phone
                victim = rng.choice(benign_devices)
                dev = Device(victim.device_id, "spoofed", accel_profile="spoofed",
                             claimed_hw=hw_id_for(victim.hw_serial))
            else:            # brand-new random id each account
                dev = Device(f"emu-r{k}-{rng.randrange(10**6)}", "emulator", accel_profile="spoofed")
            add_bot(k, dev, f"resproxy-{k}", direct((0.8, 1.5)), solver=0.6)
    elif scenario == "high_freq_monitor":
        for k in range(5):
            add_bot(k, Device(f"emu-h{k}", "emulator", accel_profile="none"), "dc-2", direct((0.08, 0.15)))
    elif scenario == "parallel_checkout":
        for k in range(10):
            add_bot(k, Device(f"emu-p{k}", "emulator", accel_profile="none"), "dc-3", direct((0.5, 1.0), par=8))
    elif scenario == "timing_mimicry":
        prof = agents.BotProfile(poll=(0, 0), full_path=True, delays=HUMANISH, human_timing=True)
        for k in range(30):
            add_bot(k, Device(f"emu-m{k}", "emulator", accel_profile="spoofed"), f"resproxy-{k}", prof,
                    touches="injected", solver=0.6)
    elif scenario == "phone_farm_rotation":
        prof = agents.BotProfile(poll=(0.8, 1.5), full_path=True, delays=FAST)
        k = 0
        for p in range(10):
            for inst in range(3):   # app cloned/reinstalled -> new device_id, same hardware
                dev = _phone(pop, rng, f"farm-{p}-i{inst}-{rng.randrange(10**6)}", f"SN-farm{p}", 200,
                             accel="rack", known=False)
                add_bot(k, dev, "farm-wifi", prof, touches="injected", solver=0.6)
                k += 1
    elif scenario == "phone_farm_scripted":
        # every device signal looks clean: genuine attested hardware, months of
        # history, one account per phone, carrier IPs, and the rack sits on a
        # motion rig so accelerometer liveness passes.  Only behaviour gives it away.
        prof = agents.BotProfile(poll=(0.8, 1.5), full_path=True, delays=FAST)
        for k in range(30):
            dev = _phone(pop, rng, f"farms-{k}", f"SN-farms{k}", rng.uniform(60, 400), accel="handheld")
            add_bot(k, dev, f"cgnat-{rng.randrange(15)}", prof, touches="injected", solver=0.6)
    elif scenario == "phone_farm_mimicry":
        prof = agents.BotProfile(poll=(0, 0), full_path=True, delays=HUMANISH, human_timing=True)
        for k in range(30):
            dev = _phone(pop, rng, f"farmm-{k}", f"SN-farmm{k}", rng.uniform(60, 400), accel="rack")
            add_bot(k, dev, f"cgnat-{rng.randrange(15)}", prof, touches="injected", solver=0.6)
    else:
        raise KeyError(scenario)
    return pop
