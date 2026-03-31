"""
SENTINEL — Refined Visualization Engine
=========================================
6 essential forensic plots with clean, professional dark theme.
"""

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# ── Clean dark theme ─────────────────────────────────────────
BG      = "#0b0f1a"
PANEL   = "#111827"
CYAN    = "#22d3ee"
RED     = "#f87171"
AMBER   = "#fbbf24"
GREEN   = "#34d399"
SLATE   = "#94a3b8"
BORDER  = "#1e293b"
WHITE   = "#e2e8f0"

SEVERITY_CLR = {"CRITICAL": RED, "HIGH": "#fb923c", "MEDIUM": AMBER, "LOW": GREEN}


def _style(fig, ax):
    fig.patch.set_facecolor(BG)
    for a in (ax if isinstance(ax, np.ndarray) else [ax]):
        a.set_facecolor(PANEL)
        a.tick_params(colors=SLATE, labelsize=8)
        for s in a.spines.values():
            s.set_color(BORDER)


# ═════════════════════════════════════════════════════════════
# 1. ATTACK HEATMAP — Hour × Day
# ═════════════════════════════════════════════════════════════
def plot_attack_heatmap(df):
    """Shows when attacks happen — reveals automated vs human patterns."""
    failed = df[df.Event == "FAILED_LOGIN"].copy()
    if failed.empty:
        return

    failed["hour"] = failed.Parsed_Time.dt.hour
    failed["dow"]  = failed.Parsed_Time.dt.day_name()

    days = ["Monday", "Tuesday", "Wednesday", "Thursday",
            "Friday", "Saturday", "Sunday"]
    pivot = failed.pivot_table(
        index="dow", columns="hour", values="Event", aggfunc="count"
    ).reindex(days).fillna(0)

    fig, ax = plt.subplots(figsize=(13, 4.5))
    _style(fig, ax)

    try:
        import seaborn as sns
        sns.heatmap(pivot, cmap="YlOrRd", annot=True, fmt=".0f",
                    linewidths=.4, ax=ax, cbar_kws={"shrink": .7})
    except ImportError:
        im = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto")
        ax.set_xticks(range(pivot.shape[1]))
        ax.set_xticklabels(pivot.columns, fontsize=7)
        ax.set_yticks(range(pivot.shape[0]))
        ax.set_yticklabels(pivot.index, fontsize=8)
        fig.colorbar(im, ax=ax, shrink=.7)

    ax.set_title("Failed Login Heatmap  —  Hour × Day",
                 color=CYAN, fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Hour of Day", color=SLATE, fontsize=9)
    ax.set_ylabel("")
    plt.tight_layout()
    plt.show()


# ═════════════════════════════════════════════════════════════
# 2. EVENT TIMELINE — Scatter by type
# ═════════════════════════════════════════════════════════════
def plot_event_timeline(df):
    """Chronological view of all events — spot attack bursts visually."""
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(14, 4.5))
    _style(fig, ax)

    mapping = {
        "FAILED_LOGIN":      (1, RED,    "x", 50),
        "SUCCESSFUL_LOGIN":  (2, GREEN,  "o", 30),
        "INVALID_USER":      (0, AMBER,  "s", 30),
        "ROOT_ACCESS":       (3, RED,    "D", 50),
        "SUDO_ATTEMPT":      (3, "#fb923c", "D", 40),
    }

    for ev, (y, color, marker, size) in mapping.items():
        sub = df[df.Event == ev]
        if sub.empty:
            continue
        ax.scatter(sub.Parsed_Time, [y]*len(sub),
                   c=color, marker=marker, s=size, alpha=.7,
                   label=ev.replace("_", " ").title(), zorder=3)

    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["Invalid User", "Failed", "Success", "Privilege"], fontsize=8)
    ax.legend(facecolor=PANEL, edgecolor=BORDER, labelcolor=WHITE,
              fontsize=7, loc="upper right", framealpha=.9)
    ax.set_title("Authentication Event Timeline",
                 color=CYAN, fontsize=12, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.show()


# ═════════════════════════════════════════════════════════════
# 3. SEVERITY DISTRIBUTION
# ═════════════════════════════════════════════════════════════
def plot_severity_distribution(severity_scores):
    """How many IPs fall into each threat tier."""
    levels = [d["level"] for d in severity_scores.values()]
    order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts = {lv: levels.count(lv) for lv in order}

    fig, ax = plt.subplots(figsize=(7, 4.5))
    _style(fig, ax)

    bars = ax.bar(counts.keys(), counts.values(),
                  color=[SEVERITY_CLR[lv] for lv in order],
                  edgecolor=BG, linewidth=1.5, width=.55)
    for bar, cnt in zip(bars, counts.values()):
        if cnt > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + .3,
                    str(cnt), ha="center", color=WHITE, fontweight="bold", fontsize=13)

    ax.set_title("Threat Severity Distribution",
                 color=CYAN, fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel("Number of IPs", color=SLATE, fontsize=9)
    ax.set_ylim(0, max(counts.values(), default=1) * 1.3)
    plt.tight_layout()
    plt.show()


# ═════════════════════════════════════════════════════════════
# 4. FAILED vs SUCCESS — Compromise Quadrant
# ═════════════════════════════════════════════════════════════
def plot_fail_success(df):
    """IPs with both high failures AND successes = confirmed breach."""
    per_ip = df.groupby("IP_Address").apply(
        lambda g: pd.Series({
            "failed":  (g.Event == "FAILED_LOGIN").sum(),
            "success": (g.Event == "SUCCESSFUL_LOGIN").sum(),
        })
    ).reset_index()

    if per_ip.empty:
        return

    fig, ax = plt.subplots(figsize=(8, 6))
    _style(fig, ax)

    ax.scatter(per_ip.failed, per_ip.success, c=CYAN, s=70,
               alpha=.8, edgecolors=BORDER, zorder=3)

    for _, r in per_ip.iterrows():
        ax.annotate(r.IP_Address, (r.failed, r.success),
                    fontsize=6, color=SLATE, alpha=.8,
                    textcoords="offset points", xytext=(5, 4))

    mf = per_ip.failed.max() or 10
    ms = per_ip.success.max() or 5
    if mf > 3 and ms > 0:
        ax.axvspan(mf * .35, mf * 1.1, ymin=.08, alpha=.06, color=RED)
        ax.text(mf * .65, ms * .85, "COMPROMISE\nZONE",
                color=RED, fontsize=10, fontweight="bold", ha="center", alpha=.6)

    ax.set_title("Failed vs Success Correlation  —  Compromise Map",
                 color=CYAN, fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Failed Logins", color=SLATE, fontsize=9)
    ax.set_ylabel("Successful Logins", color=SLATE, fontsize=9)
    plt.tight_layout()
    plt.show()


# ═════════════════════════════════════════════════════════════
# 5. LOGIN FREQUENCY — Spike Detection
# ═════════════════════════════════════════════════════════════
def plot_login_frequency(df):
    """Events per minute over time — spikes reveal active attack windows."""
    if df.empty:
        return

    ts = df.sort_values("Parsed_Time").set_index("Parsed_Time")
    freq = ts.resample("1min").size()

    fig, ax = plt.subplots(figsize=(14, 4))
    _style(fig, ax)

    ax.fill_between(freq.index, freq.values, alpha=.2, color=CYAN)
    ax.plot(freq.index, freq.values, color=CYAN, linewidth=1.2)

    mean, std = freq.mean(), freq.std()
    thresh = mean + 2 * std
    spikes = freq[freq > thresh]
    if not spikes.empty:
        ax.scatter(spikes.index, spikes.values, color=RED, s=40, zorder=5)
        ax.axhline(thresh, color=RED, linestyle="--", alpha=.4, linewidth=1)

    ax.set_title("Login Frequency  —  Events per Minute",
                 color=CYAN, fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel("Events/min", color=SLATE, fontsize=9)
    plt.tight_layout()
    plt.show()


# ═════════════════════════════════════════════════════════════
# 6. MITRE ATT&CK TECHNIQUE COVERAGE
# ═════════════════════════════════════════════════════════════
def plot_mitre_coverage(df):
    """Which MITRE techniques were observed and how often."""
    if "MITRE_Technique" not in df.columns:
        return

    counts = df.MITRE_Technique.value_counts()
    if counts.empty:
        return

    fig, ax = plt.subplots(figsize=(10, max(3.5, len(counts) * .55)))
    _style(fig, ax)

    colors = [RED if c > counts.median() else CYAN for c in counts.values]
    ax.barh(counts.index, counts.values, color=colors,
            edgecolor=BG, height=.55)

    for i, (tech, cnt) in enumerate(counts.items()):
        ax.text(cnt + .5, i, str(cnt), va="center", color=WHITE, fontsize=9)

    ax.set_title("MITRE ATT&CK Technique Coverage",
                 color=CYAN, fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Detections", color=SLATE, fontsize=9)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.show()


# ═════════════════════════════════════════════════════════════
# SHOW ALL
# ═════════════════════════════════════════════════════════════
def show_all_plots(df, severity_scores=None, cluster_df=None,
                   attack_chains=None):
    """Open the 6 essential forensic plots."""
    plt.style.use("dark_background")

    plot_event_timeline(df)
    plot_attack_heatmap(df)
    plot_login_frequency(df)
    plot_fail_success(df)

    if severity_scores:
        plot_severity_distribution(severity_scores)

    if "MITRE_Technique" in df.columns:
        plot_mitre_coverage(df)
