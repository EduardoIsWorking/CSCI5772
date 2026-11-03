# Progress video script (about 4 minutes)

Record your screen. Use a terminal at the project root, with the `evidence/` figures open in an
image viewer. Run `python scripts/demo.py` once before recording so it starts instantly.

---

**1. Problem and threat model (about 45 s).** *Show the README's opening section.*

> "BotShield protects a mobile shopping app during limited product drops, the kind where I couldn't get a Zelda Switch 2 because it sold out in seconds.
> The attacker is a scalper who controls many accounts, runs Android emulators or racks of real phones, rotates or spoofs device IDs, uses proxies, and can mimic human timing.
> The protected assets are the limited inventory and fair access for real customers.
> Payment fraud and resale are out of scope."

**2. Architecture (about 30 s).** *Show the project layout in the README.*

> "It's a discrete-event testbed.
> There's a store backend with two inventory drops and a two-per-account limit, 400 simulated app users including a real drop-time rush, and nine attack scenarios.
> Every request goes through a defense.
> I compare no defense, a conventional rate-limit baseline, device-only, behavior-only, and BotShield, which combines the two."

**3–6. Live demo: normal run, attack, defense, measured result (about 90 s).** *Run* `python scripts/demo.py`.

- **[1] Normal.** "With no attacker, humans get all 150 units."
- **[2] Attack.** "S6 is 30 emulators with human-like timing and fake touches.
  They take about a third of the inventory, and the rate limiter doesn't flag a single account."
- **[3] Defense.** "Behavior-only also misses them, because the timing looks human.
  Device-only and BotShield catch every bot, because emulators can't produce a valid hardware attestation."
- **[4] Why.** "Here's the score.
  D is the device score, B is the behavior score, and R is 1 minus (1 minus D) times (1 minus B).
  Thresholds are calibrated only on benign traffic, so 2% of real shoppers would see a challenge."

*(Optional, about 20 s.)* Run `python scripts/demo.py --scenario phone_farm_scripted`.

> "This is the opposite case.
> Real attested phones defeat device-only, but behavior catches them.
> That's why I combine both."

**6. Results (about 40 s).** *Show the figures.*

- `fig1_bot_inventory_share.png`: "Under the baseline, bots get 39 to 40 percent in the hard scenarios. BotShield gets that to 0 in S1 through S7."
- `fig2_ablation_detection.png`: "At the same 2 percent false-positive rate, each single view has a blind spot. Only the combined score covers both S6 and S8."
- "Scoring costs about 50 microseconds per request."

**7. Remaining work (about 30 s).** *Show* `fig3_score_space.png`*, S9 panel.*

> "The honest failure is S9: real aged phones with human timing.
> They sit inside the benign cloud, and we only detect about 35 percent at a 2 percent false-positive rate.
> Next I'll add sensor time-series and cross-account synchronization features, learn the weights, sweep attacker budgets, and build an HTTP/Playwright version to measure real latency and compare against FingerprintJS BotD.
> I also fixed two bugs testing found: spoofed IDs poisoning the victim's device record, and our own throttle hiding bot speed."

**8. Contributions (about 5 s).**

> "This is an individual project. I did the architecture, simulation, attacks, detector, and evaluation."
