"""Turn evidence/*.csv into the figures used in the progress summary."""
from __future__ import annotations

import csv
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt   # noqa: E402
import numpy as np                # noqa: E402

EVID = os.path.join(os.path.dirname(__file__), "..", "evidence")
COL = {"none": "#8a8984", "rate_limit": "#eb6834", "device_only": "#1baf7a",
       "behavior_only": "#eda100", "botshield": "#2a78d6"}
LABEL = {"none": "No defense", "rate_limit": "Rate limit (baseline)", "device_only": "Device-only",
         "behavior_only": "Behavior-only", "botshield": "BotShield (combined)"}
SHORT = {"single_bot": "S1 single bot", "multi_acct_same_device": "S2 multi-acct\n1 device",
         "rotating_ids": "S3 rotated /\nspoofed IDs", "high_freq_monitor": "S4 high-freq\npolling",
         "parallel_checkout": "S5 parallel\ncheckout", "timing_mimicry": "S6 timing\nmimicry",
         "phone_farm_rotation": "S7 phone farm\nID rotation", "phone_farm_scripted": "S8 phone farm\nscripted",
         "phone_farm_mimicry": "S9 phone farm\nmimicry"}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({"font.size": 9, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
                     "axes.spines.right": False, "figure.facecolor": "#fcfcfb",
                     "axes.facecolor": "#fcfcfb", "savefig.facecolor": "#fcfcfb"})


def load(name):
    return list(csv.DictReader(open(os.path.join(EVID, name))))


def grouped(ax, cats, series, values, ylabel, pct=True, label_series=None):
    n = len(series)
    w = 0.8 / n
    x = np.arange(len(cats))
    for i, s in enumerate(series):
        v = [values[(c, s)] for c in cats]
        bars = ax.bar(x + (i - (n - 1) / 2) * w, v, w - 0.02, color=COL[s], label=LABEL[s],
                      edgecolor="#fcfcfb", linewidth=1)
        if label_series and s in label_series:
            for b, val in zip(bars, v):
                ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{val:.0f}",
                        ha="center", va="bottom", fontsize=7, color=INK2)
    ax.set_xticks(x, [SHORT.get(c, c) for c in cats], fontsize=8)
    ax.set_ylabel(ylabel)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def fig_inventory():
    rows = load("results_summary.csv")
    cats = [c for c in SHORT]
    defs = ["none", "rate_limit", "device_only", "behavior_only", "botshield"]
    vals = {(r["scenario"], r["defense"]): 100 * float(r["bot_share"]) for r in rows if r["scenario"] in SHORT}
    fig, ax = plt.subplots(figsize=(10, 3.8))
    grouped(ax, cats, defs, vals, "% of inventory bought by bots", label_series=["rate_limit", "botshield"])
    ax.set_ylim(0, 50)
    ax.set_title("Inventory captured by bots (150 units, mean of 5 seeds)", loc="left", color=INK, fontsize=11)
    ax.legend(ncol=5, frameon=False, loc="upper left", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(EVID, "fig1_bot_inventory_share.png"), dpi=160)


def fig_ablation():
    rows = load("roc_points.csv")
    cats = [c for c in SHORT]
    defs = ["device_only", "behavior_only", "botshield"]
    vals = {(r["scenario"], r["detector"]): 100 * float(r["tpr_at_fpr_2pct"]) for r in rows}
    fig, ax = plt.subplots(figsize=(10, 3.6))
    grouped(ax, cats, defs, vals, "Bot accounts detected (%)", label_series=defs)
    ax.set_ylim(0, 115)
    ax.set_title("Detection rate at a 2% benign false-positive rate (monitor mode, 5 seeds)",
                 loc="left", color=INK, fontsize=11)
    ax.legend(ncol=3, frameon=False, loc="upper left", bbox_to_anchor=(0, 1.0), fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(EVID, "fig2_ablation_detection.png"), dpi=160)


def fig_score_space():
    rows = load("account_scores.csv")
    th = json.load(open(os.path.join(EVID, "thresholds.json")))["botshield"]["challenge"]
    show = ["rotating_ids", "timing_mimicry", "phone_farm_scripted", "phone_farm_mimicry"]
    fig, axes = plt.subplots(1, 4, figsize=(11, 3.1), sharex=True, sharey=True)
    for ax, sc in zip(axes, show):
        rs = [r for r in rows if r["scenario"] == sc]
        ben = [(float(r["D"]), float(r["B"])) for r in rs if r["is_bot"] == "0"]
        bot = [(float(r["D"]), float(r["B"])) for r in rs if r["is_bot"] == "1"]
        ax.scatter(*zip(*ben), s=9, color="#8a8984", alpha=0.45, label="Benign accounts", linewidths=0)
        ax.scatter(*zip(*bot), s=14, color="#e34948", label="Bot accounts", edgecolors="#fcfcfb", linewidths=0.6)
        d = np.linspace(0, 1, 200)
        with np.errstate(divide="ignore"):
            b = 1 - (1 - th) / (1 - d)
        m = b >= 0
        ax.plot(d[m], b[m], color="#2a78d6", lw=1.5, label=f"BotShield challenge threshold (R={th:.2f})")
        ax.set_title(SHORT[sc].replace("\n", " "), fontsize=9, color=INK, loc="left")
        ax.set_xlim(-0.02, 0.8); ax.set_ylim(-0.02, 0.8)
        ax.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
        ax.set_xlabel("Device score D")
    axes[0].set_ylabel("Behavior score B")
    axes[0].legend(frameon=False, fontsize=7, loc="upper right")
    fig.suptitle("Where accounts land in (D, B) space -- seed 1, monitor mode. Above/right of blue line = challenged.",
                 x=0.01, ha="left", fontsize=10, color=INK)
    fig.tight_layout()
    fig.savefig(os.path.join(EVID, "fig3_score_space.png"), dpi=160)


def fig_benign_cost():
    rows = load("results_summary.csv")
    defs = ["rate_limit", "device_only", "behavior_only", "botshield"]
    ben = {r["defense"]: r for r in rows if r["scenario"] == "benign_only"}
    metrics = [("benign_throttled", "Throttled"), ("benign_challenged", "Challenged at checkout"),
               ("benign_blocked", "Blocked"), ("benign_rate_limited", "Rate-limited (429)")]
    fig, ax = plt.subplots(figsize=(7, 3.2))
    x = np.arange(len(metrics)); w = 0.8 / len(defs)
    for i, d in enumerate(defs):
        v = [100 * float(ben[d][m]) for m, _ in metrics]
        bars = ax.bar(x + (i - 1.5) * w, v, w - 0.02, color=COL[d], label=LABEL[d], edgecolor="#fcfcfb")
        for b_, val in zip(bars, v):
            ax.text(b_.get_x() + b_.get_width() / 2, val + 0.1, f"{val:.1f}", ha="center", fontsize=7, color=INK2)
    ax.set_xticks(x, [l for _, l in metrics])
    ax.set_ylabel("% of 400 benign accounts")
    ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
    ax.set_title("Cost to legitimate shoppers (benign-only drop, incl. rush; 5 seeds)", loc="left", color=INK, fontsize=10)
    ax.legend(frameon=False, fontsize=7, ncol=2)
    fig.tight_layout()
    fig.savefig(os.path.join(EVID, "fig4_benign_cost.png"), dpi=160)


if __name__ == "__main__":
    fig_inventory(); fig_ablation(); fig_score_space(); fig_benign_cost()
    print("Figures written to evidence/")
