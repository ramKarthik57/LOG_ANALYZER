"""
Cyber Forensic Log Analyzer — Redesigned GUI
=============================================
A sleek, professional dark-themed forensic tool with:
  - Glassy sidebar with icon buttons
  - Tabbed notebook output (Report | Timeline | Severity)
  - Inline config editor
  - Animated status bar with live counters
  - Color-coded severity tags inside the text widget
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import re
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("TkAgg")
import os

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CONFIG = {
    "FAILED_THRESHOLD": 3,
    "YEAR": "2024",
    "NIGHT_END": 5,
}

# ─────────────────────────────────────────────────────────────
# COLOUR PALETTE  (CSS-style names for reference)
# ─────────────────────────────────────────────────────────────
C = {
    "bg":        "#0a0e1a",   # deepest background
    "panel":     "#0f1629",   # panel background
    "sidebar":   "#080c18",   # sidebar
    "card":      "#131d35",   # card / elevated surface
    "border":    "#1e2d4d",   # subtle border
    "accent":    "#00d4ff",   # primary cyan accent
    "accent2":   "#7c3aed",   # purple accent
    "accent3":   "#10b981",   # green success
    "warn":      "#f59e0b",   # amber warning
    "danger":    "#ef4444",   # red danger
    "text":      "#e2e8f0",   # primary text
    "muted":     "#64748b",   # muted / secondary text
    "critical":  "#ff2d55",
    "high":      "#ff6b35",
    "medium":    "#ffd60a",
    "low":       "#30d158",
}

FONT_HEADING  = ("Courier New", 13, "bold")
FONT_MONO     = ("Courier New", 10)
FONT_LABEL    = ("Courier New", 9)
FONT_TITLE    = ("Courier New", 20, "bold")
FONT_SUBTITLE = ("Courier New", 10)
FONT_BTN      = ("Courier New", 10, "bold")

# ─────────────────────────────────────────────────────────────
# PARSER
# ─────────────────────────────────────────────────────────────
def parse_auth_log(file):
    pattern = re.compile(
        r'([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+?):?\s(.*)'
    )
    rows = []
    with open(file, "r") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue
            timestamp, host, process, msg = m.groups()
            if "Failed password" in msg:
                event = "FAILED_LOGIN"
            elif "Accepted password" in msg:
                event = "SUCCESSFUL_LOGIN"
            else:
                event = "OTHER"
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', msg)
            ip = ip_match.group(0) if ip_match else "Internal"
            rows.append([timestamp, event, ip, msg])
    return pd.DataFrame(rows, columns=["Timestamp", "Event", "IP_Address", "Message"])


def add_time(df):
    df["Parsed_Time"] = df["Timestamp"].apply(
        lambda t: datetime.strptime(CONFIG["YEAR"] + " " + t, "%Y %b %d %H:%M:%S")
    )
    return df


# ─────────────────────────────────────────────────────────────
# DETECTION
# ─────────────────────────────────────────────────────────────
def detect_bruteforce(df):
    failed = df[df.Event == "FAILED_LOGIN"]
    counts = failed.IP_Address.value_counts()
    return counts[counts >= CONFIG["FAILED_THRESHOLD"]]


def detect_night(df):
    return df[
        (df.Event == "SUCCESSFUL_LOGIN") &
        (df.Parsed_Time.dt.hour < CONFIG["NIGHT_END"])
    ]


def severity(df):
    results = {}
    for ip in df.IP_Address.unique():
        iplogs = df[df.IP_Address == ip]
        failed  = len(iplogs[iplogs.Event == "FAILED_LOGIN"])
        success = len(iplogs[iplogs.Event == "SUCCESSFUL_LOGIN"])
        night   = len(
            iplogs[
                (iplogs.Event == "SUCCESSFUL_LOGIN") &
                (iplogs.Parsed_Time.dt.hour < CONFIG["NIGHT_END"])
            ]
        )
        score = failed * 2 + success * 3 + night * 5
        level = (
            "CRITICAL" if score >= 15 else
            "HIGH"     if score >= 8  else
            "MEDIUM"   if score >= 4  else
            "LOW"
        )
        results[ip] = (score, level)
    return results


# ─────────────────────────────────────────────────────────────
# CUSTOM WIDGETS
# ─────────────────────────────────────────────────────────────
class SidebarButton(tk.Frame):
    """A pill-shaped sidebar button with icon + label and hover glow."""

    def __init__(self, parent, icon, label, command, **kw):
        super().__init__(parent, bg=C["sidebar"], cursor="hand2", **kw)
        self._cmd = command
        self._active = False

        self._bar = tk.Frame(self, bg=C["sidebar"], width=3)
        self._bar.pack(side="left", fill="y")

        inner = tk.Frame(self, bg=C["sidebar"], pady=10, padx=14)
        inner.pack(side="left", fill="both", expand=True)

        tk.Label(inner, text=icon, font=("Courier New", 16),
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left", padx=(0, 10))
        self._lbl = tk.Label(inner, text=label, font=FONT_BTN,
                             bg=C["sidebar"], fg=C["muted"], anchor="w")
        self._lbl.pack(side="left", fill="x")

        # bind all children too
        for w in (self, inner, self._lbl):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _on_enter(self, _=None):
        self.configure(bg=C["card"])
        for c in self.winfo_children():
            c.configure(bg=C["card"])
            for cc in c.winfo_children():
                cc.configure(bg=C["card"], fg=C["accent"])
        self._bar.configure(bg=C["accent"])

    def _on_leave(self, _=None):
        if self._active:
            return
        self.configure(bg=C["sidebar"])
        for c in self.winfo_children():
            c.configure(bg=C["sidebar"])
            for cc in c.winfo_children():
                cc.configure(bg=C["sidebar"], fg=C["muted"])
        self._bar.configure(bg=C["sidebar"])

    def _on_click(self, _=None):
        self._cmd()

    def set_active(self, state):
        self._active = state
        if state:
            self._on_enter()
        else:
            self._on_leave()


class MetricCard(tk.Frame):
    """Small KPI card displayed in the top stat bar."""

    def __init__(self, parent, title, value="—", color=None, **kw):
        color = color or C["accent"]
        super().__init__(parent, bg=C["card"],
                         highlightbackground=C["border"], highlightthickness=1,
                         padx=18, pady=10, **kw)
        tk.Label(self, text=title.upper(), font=FONT_LABEL,
                 bg=C["card"], fg=C["muted"]).pack(anchor="w")
        self._val = tk.Label(self, text=value, font=("Courier New", 22, "bold"),
                             bg=C["card"], fg=color)
        self._val.pack(anchor="w")

    def update_val(self, v):
        self._val.configure(text=str(v))


# ─────────────────────────────────────────────────────────────
# MAIN GUI CLASS
# ─────────────────────────────────────────────────────────────
class ForensicGUI:

    def __init__(self, root):
        self.root  = root
        self.file  = None
        self.df    = None

        root.title("⬛  CYBER FORENSIC LOG ANALYZER")
        root.geometry("1280x760")
        root.minsize(960, 600)
        root.configure(bg=C["bg"])

        self._build_layout()
        self._pulse_cursor = 0
        self._blink()

    # ── LAYOUT ──────────────────────────────────────────────
    def _build_layout(self):
        # ── root grid: sidebar | content
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content()
        self._build_statusbar()

    def _build_sidebar(self):
        side = tk.Frame(self.root, bg=C["sidebar"], width=220)
        side.grid(row=0, column=0, sticky="nsew")
        side.pack_propagate(False)

        # ── branding
        brand = tk.Frame(side, bg=C["sidebar"], pady=24, padx=20)
        brand.pack(fill="x")

        tk.Label(brand, text="⬛", font=("Courier New", 28),
                 bg=C["sidebar"], fg=C["accent"]).pack(anchor="w")
        tk.Label(brand, text="FORENSIC", font=("Courier New", 14, "bold"),
                 bg=C["sidebar"], fg=C["text"]).pack(anchor="w")
        tk.Label(brand, text="L O G  A N A L Y Z E R", font=("Courier New", 8),
                 bg=C["sidebar"], fg=C["accent"]
                 ).pack(anchor="w")

        # thin separator
        tk.Frame(side, bg=C["border"], height=1).pack(fill="x", padx=20, pady=(0, 14))

        # ── nav buttons
        self._btn_load    = SidebarButton(side, "📂", "Load Log File", self.load_file)
        self._btn_run     = SidebarButton(side, "▶", "Run Analysis",  self.run_analysis)
        self._btn_graphs  = SidebarButton(side, "📊", "Show Graphs",   self.show_graphs)
        self._btn_export  = SidebarButton(side, "💾", "Export CSV",    self.export_csv)
        self._btn_config  = SidebarButton(side, "⚙", "Settings",      self.open_config)

        for btn in (self._btn_load, self._btn_run, self._btn_graphs,
                    self._btn_export, self._btn_config):
            btn.pack(fill="x")

        # ── file info at bottom
        tk.Frame(side, bg=C["border"], height=1).pack(fill="x", padx=20, pady=14, side="bottom")
        self._file_lbl = tk.Label(
            side, text="No file loaded", font=FONT_LABEL,
            bg=C["sidebar"], fg=C["muted"], wraplength=180, justify="left"
        )
        self._file_lbl.pack(side="bottom", padx=20, pady=(0, 12), anchor="w")
        tk.Label(side, text="FILE", font=FONT_LABEL,
                 bg=C["sidebar"], fg=C["accent"]).pack(side="bottom", padx=20, anchor="w")

    def _build_content(self):
        content = tk.Frame(self.root, bg=C["bg"])
        content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        content.rowconfigure(1, weight=1)
        content.columnconfigure(0, weight=1)

        # ── top header bar
        header = tk.Frame(content, bg=C["panel"], pady=16, padx=24,
                          highlightbackground=C["border"], highlightthickness=1)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        tk.Label(header, text="FORENSIC ANALYSIS DASHBOARD",
                 font=FONT_HEADING, bg=C["panel"], fg=C["text"]).grid(row=0, column=0, sticky="w")
        tk.Label(header, text="Authentication log parser · Threat detection · Severity scoring",
                 font=FONT_LABEL, bg=C["panel"], fg=C["muted"]).grid(row=1, column=0, sticky="w")

        # ── KPI cards
        cards_frame = tk.Frame(header, bg=C["panel"])
        cards_frame.grid(row=0, column=1, rowspan=2, sticky="e", padx=(20, 0))

        self._kpi_total    = MetricCard(cards_frame, "Total Events", color=C["accent"])
        self._kpi_failed   = MetricCard(cards_frame, "Failed Logins", color=C["danger"])
        self._kpi_suspects = MetricCard(cards_frame, "Suspects",     color=C["warn"])
        self._kpi_critical = MetricCard(cards_frame, "Critical IPs", color=C["critical"])

        for i, card in enumerate((self._kpi_total, self._kpi_failed,
                                   self._kpi_suspects, self._kpi_critical)):
            card.grid(row=0, column=i, padx=6)

        # ── tabbed notebook
        nb_frame = tk.Frame(content, bg=C["bg"])
        nb_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        nb_frame.rowconfigure(0, weight=1)
        nb_frame.columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.TNotebook",
                        background=C["bg"], borderwidth=0, tabmargins=0)
        style.configure("Dark.TNotebook.Tab",
                        background=C["card"], foreground=C["muted"],
                        font=FONT_BTN, padding=[16, 8],
                        borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", C["panel"])],
                  foreground=[("selected", C["accent"])])

        self._nb = ttk.Notebook(nb_frame, style="Dark.TNotebook")
        self._nb.grid(row=0, column=0, sticky="nsew")

        # TAB 1 – Full Report
        self._tab_report = self._make_tab(self._nb, "  ◼  FULL REPORT  ")
        # TAB 2 – Timeline
        self._tab_timeline = self._make_tab(self._nb, "  ◼  TIMELINE     ")
        # TAB 3 – Severity
        self._tab_severity = self._make_tab(self._nb, "  ◼  SEVERITY     ")

        self._nb.add(self._tab_report[0],   text="  ◼  FULL REPORT  ")
        self._nb.add(self._tab_timeline[0], text="  ◼  TIMELINE     ")
        self._nb.add(self._tab_severity[0], text="  ◼  SEVERITY     ")

        # text references
        self._txt_report   = self._tab_report[1]
        self._txt_timeline = self._tab_timeline[1]
        self._txt_severity = self._tab_severity[1]

        # configure text tags for colour coding
        for txt in (self._txt_report, self._txt_timeline, self._txt_severity):
            txt.tag_configure("CRITICAL", foreground=C["critical"])
            txt.tag_configure("HIGH",     foreground=C["high"])
            txt.tag_configure("MEDIUM",   foreground=C["medium"])
            txt.tag_configure("LOW",      foreground=C["low"])
            txt.tag_configure("HEADER",   foreground=C["accent"], font=("Courier New", 11, "bold"))
            txt.tag_configure("SECTION",  foreground=C["accent2"], font=("Courier New", 10, "bold"))
            txt.tag_configure("KEY",      foreground=C["muted"])
            txt.tag_configure("VAL",      foreground=C["text"])
            txt.tag_configure("FAIL",     foreground=C["danger"])
            txt.tag_configure("SUCCESS",  foreground=C["low"])
            txt.tag_configure("NIGHT",    foreground=C["warn"])
            txt.tag_configure("DIM",      foreground=C["border"])

    def _make_tab(self, nb, title):
        """Returns (frame, text_widget) for a notebook tab."""
        frame = tk.Frame(nb, bg=C["panel"])
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        txt = tk.Text(
            frame,
            font=FONT_MONO, bg=C["panel"], fg=C["text"],
            insertbackground=C["accent"],
            selectbackground=C["accent2"], selectforeground=C["text"],
            relief="flat", bd=0,
            wrap="none", padx=18, pady=14,
            cursor="xterm",
        )
        txt.grid(row=0, column=0, sticky="nsew")

        # horizontal + vertical scrollbars
        vsb = ttk.Scrollbar(frame, orient="vertical",   command=txt.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=txt.xview)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        style = ttk.Style()
        style.configure("Vertical.TScrollbar",
                        background=C["card"], troughcolor=C["sidebar"],
                        arrowcolor=C["muted"], borderwidth=0)
        style.configure("Horizontal.TScrollbar",
                        background=C["card"], troughcolor=C["sidebar"],
                        arrowcolor=C["muted"], borderwidth=0)

        return frame, txt

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C["sidebar"], height=28,
                       highlightbackground=C["border"], highlightthickness=1)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")

        self._status_dot = tk.Label(bar, text="●", font=FONT_LABEL,
                                    bg=C["sidebar"], fg=C["accent3"])
        self._status_dot.pack(side="left", padx=(14, 4))

        self._status_lbl = tk.Label(bar, text="READY — Awaiting log file.",
                                    font=FONT_LABEL, bg=C["sidebar"], fg=C["muted"])
        self._status_lbl.pack(side="left")

        tk.Label(bar, text="Cyber Forensic Analyzer v2.0",
                 font=FONT_LABEL, bg=C["sidebar"], fg=C["border"]).pack(side="right", padx=14)

    # ── BLINKING CURSOR in status bar ───────────────────────
    def _blink(self):
        colors = [C["accent"], C["sidebar"]]
        self._pulse_cursor ^= 1
        self._status_dot.configure(fg=colors[self._pulse_cursor])
        self.root.after(700, self._blink)

    # ── STATUS HELPERS ───────────────────────────────────────
    def _set_status(self, msg, color=None):
        self._status_lbl.configure(text=msg, fg=color or C["muted"])

    # ── TAB TEXT HELPERS ─────────────────────────────────────
    def _clear_all(self):
        for txt in (self._txt_report, self._txt_timeline, self._txt_severity):
            txt.configure(state="normal")
            txt.delete("1.0", "end")

    def _log(self, txt_widget, text, tag=None):
        txt_widget.configure(state="normal")
        if tag:
            txt_widget.insert("end", text, tag)
        else:
            txt_widget.insert("end", text)
        txt_widget.see("end")

    # ── ACTIONS ──────────────────────────────────────────────
    def load_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if path:
            self.file = path
            name = os.path.basename(path)
            self._file_lbl.configure(text=name)
            self._set_status(f"Loaded: {name}", C["accent"])
            self._log(self._txt_report,
                      f"[OK] File loaded: {path}\n     Ready to run analysis.\n", "HEADER")

    def run_analysis(self):
        if not self.file:
            messagebox.showwarning("No File", "Please load a log file first.")
            return

        self._set_status("Running analysis …", C["warn"])
        self._clear_all()

        df = parse_auth_log(self.file)
        df = add_time(df)
        self.df = df

        threshold = CONFIG["FAILED_THRESHOLD"]
        suspects  = detect_bruteforce(df)
        night     = detect_night(df)
        scores    = severity(df)

        # ── KPI update
        total_failed   = len(df[df.Event == "FAILED_LOGIN"])
        n_suspects     = len(suspects)
        n_critical     = sum(1 for _, (_, lv) in scores.items() if lv == "CRITICAL")

        self._kpi_total.update_val(len(df))
        self._kpi_failed.update_val(total_failed)
        self._kpi_suspects.update_val(n_suspects)
        self._kpi_critical.update_val(n_critical)

        # ── TAB 1: FULL REPORT ───────────────────────────────
        R   = self._txt_report
        SEP = "=" * 60 + "\n"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Header
        self._log(R, SEP, "DIM")
        self._log(R, "CYBER FORENSIC ANALYSIS REPORT\n", "HEADER")
        self._log(R, f"Generated: {now}\n", "KEY")
        self._log(R, SEP, "DIM")

        # ── Total entries
        self._log(R, f"📊 TOTAL ENTRIES ANALYZED: {len(df)}\n", "VAL")
        self._log(R, SEP, "DIM")

        # ── Brute Force
        self._log(R, "🔒 BRUTE FORCE ANALYSIS\n", "SECTION")
        self._log(R, SEP, "DIM")
        if suspects.empty:
            self._log(R, "✅ No brute force activity detected.\n", "LOW")
        else:
            for ip, count in suspects.items():
                self._log(R, f"⚠️ Suspicious IP: ", "KEY")
                self._log(R, f"{ip}\n", "FAIL")
                self._log(R, f"   Failed Attempts: {count}\n", "KEY")
                self._log(R, f"   Threshold: {threshold}\n", "KEY")
        self._log(R, SEP, "DIM")

        # ── Night logins
        self._log(R, "🌙 SUSPICIOUS LOGIN TIMES\n", "SECTION")
        self._log(R, SEP, "DIM")
        if night.empty:
            self._log(R, "✅ No abnormal login times detected.\n", "LOW")
        else:
            for _, row in night.iterrows():
                self._log(R, "⚠️ Night Login Detected\n", "NIGHT")
                self._log(R, f"   IP: ", "KEY");   self._log(R, f"{row.IP_Address}\n", "NIGHT")
                self._log(R, f"   Time: {row.Timestamp}\n", "KEY")
        self._log(R, SEP, "DIM")

        # ── Suspicious pattern (compromise)
        self._log(R, "⚠️ SUSPICIOUS PATTERN ANALYSIS\n", "SECTION")
        self._log(R, SEP, "DIM")
        found_any = False
        for ip in df.IP_Address.unique():
            iplogs  = df[df.IP_Address == ip]
            fails   = len(iplogs[iplogs.Event == "FAILED_LOGIN"])
            success = len(iplogs[iplogs.Event == "SUCCESSFUL_LOGIN"])
            total   = len(iplogs)
            if fails >= threshold and success > 0:
                found_any = True
                self._log(R, f"🚨 Suspicious Activity - IP: ", "KEY")
                self._log(R, f"{ip}\n", "CRITICAL")
                self._log(R, f"   Events: {total}\n", "KEY")
                self._log(R, "   Pattern: Failed followed by Successful login\n", "KEY")
        if not found_any:
            self._log(R, "✅ No compromise patterns detected.\n", "LOW")
        self._log(R, SEP, "DIM")

        # ── Threat Severity
        self._log(R, "🎯 THREAT SEVERITY ASSESSMENT\n", "SECTION")
        self._log(R, SEP, "DIM")

        level_icon = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
        }
        level_tag = {
            "CRITICAL": "CRITICAL",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
        }

        for ip, (score, level) in scores.items():
            icon = level_icon.get(level, "⚪")
            tag  = level_tag.get(level, "VAL")
            self._log(R, f"{icon} IP: ", "KEY")
            self._log(R, f"{ip}\n", tag)
            self._log(R, f"   Severity Score: {score}\n", "KEY")
            self._log(R, f"   Threat Level: ", "KEY")
            self._log(R, f"{level}\n", tag)

        self._log(R, SEP, "DIM")
        self._log(R, "✅ ANALYSIS COMPLETE\n", "LOW")
        self._log(R, SEP, "DIM")

        # ── TAB 2: TIMELINE ──────────────────────────────────
        T = self._txt_timeline
        self._log(T, "  TIMESTAMP                  IP ADDRESS         EVENT\n", "HEADER")
        self._log(T, "  " + "─" * 65 + "\n", "DIM")

        timeline = df.sort_values("Parsed_Time")
        for _, row in timeline.iterrows():
            ts   = f"{row.Timestamp:<26}"
            ip   = f"{row.IP_Address:<18}"
            ev   = row.Event

            tag = ("FAIL"    if ev == "FAILED_LOGIN"     else
                   "SUCCESS" if ev == "SUCCESSFUL_LOGIN" else
                   "DIM")

            self._log(T, f"  {ts}  {ip}  ", "KEY")
            self._log(T, f"{ev}\n", tag)

        # ── TAB 3: SEVERITY ──────────────────────────────────
        S = self._txt_severity
        self._log(S, "  THREAT SEVERITY ASSESSMENT\n\n", "HEADER")
        self._log(S, "  Scoring Model:\n", "SECTION")
        self._log(S, "    Failed Attempt    → +2 pts\n", "KEY")
        self._log(S, "    Successful Login  → +3 pts\n", "KEY")
        self._log(S, "    Night Login       → +5 pts\n\n", "KEY")
        self._log(S, "  " + "─" * 65 + "\n\n", "DIM")

        level_colors = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",     "LOW":  "LOW",
        }

        for ip, (score, level) in scores.items():
            iplogs      = df[df.IP_Address == ip]
            failed      = len(iplogs[iplogs.Event == "FAILED_LOGIN"])
            success     = len(iplogs[iplogs.Event == "SUCCESSFUL_LOGIN"])
            night_count = len(iplogs[
                (iplogs.Event == "SUCCESSFUL_LOGIN") &
                (iplogs.Parsed_Time.dt.hour < CONFIG["NIGHT_END"])
            ])

            self._log(S, f"  IP Address        : {ip}\n", "VAL")
            self._log(S, f"  Failed Attempts   : {failed}  (+{failed*2})\n", "KEY")
            self._log(S, f"  Successful Logins : {success}  (+{success*3})\n", "KEY")
            self._log(S, f"  Night Logins      : {night_count}  (+{night_count*5})\n", "KEY")
            self._log(S, f"  Total Score       : {score}\n", "VAL")
            self._log(S, f"  Threat Level      : ", "KEY")
            self._log(S, f"  ▌ {level}\n", level_colors.get(level, "VAL"))
            self._log(S, "  " + "─" * 65 + "\n\n", "DIM")

        self.export_csv(silent=True)
        self._set_status(
            f"Analysis complete — {len(df)} entries | {n_suspects} suspects | {n_critical} critical",
            C["accent3"]
        )
        # switch to report tab
        self._nb.select(0)

    def show_graphs(self):
        if self.df is None:
            messagebox.showwarning("No Data", "Run analysis first.")
            return

        df      = self.df
        failed  = df[df.Event == "FAILED_LOGIN"]
        success = df[df.Event == "SUCCESSFUL_LOGIN"]
        night   = detect_night(df)

        plt.style.use("dark_background")
        accent  = "#00d4ff"
        danger  = "#ef4444"
        warn    = "#f59e0b"

        # ── Chart 1: Failed logins per IP
        if not failed.empty:
            fig, ax = plt.subplots(figsize=(9, 4))
            fig.patch.set_facecolor("#0a0e1a")
            ax.set_facecolor("#0f1629")
            counts = failed.IP_Address.value_counts()
            bars   = ax.bar(counts.index, counts.values, color=danger, edgecolor="#0a0e1a", linewidth=0.5)
            ax.set_title("Failed Login Attempts per IP", color=accent, fontsize=13, pad=14)
            ax.set_xlabel("IP Address", color="#64748b")
            ax.set_ylabel("Count",      color="#64748b")
            ax.tick_params(colors="#64748b")
            ax.spines[:].set_color("#1e2d4d")
            plt.tight_layout()
            plt.show()

        # ── Chart 2: Timeline scatter
        fig, ax = plt.subplots(figsize=(11, 4))
        fig.patch.set_facecolor("#0a0e1a")
        ax.set_facecolor("#0f1629")

        ax.scatter(failed["Parsed_Time"],  [1] * len(failed),
                   marker="x", c=danger, s=60, label="Failed",  zorder=3)
        ax.scatter(success["Parsed_Time"], [2] * len(success),
                   marker="o", c="#10b981", s=40, label="Success", zorder=3)
        if not night.empty:
            ax.scatter(night["Parsed_Time"], [3] * len(night),
                       marker="D", c=warn, s=60, label="Night Login", zorder=4)

        ax.set_yticks([1, 2, 3])
        ax.set_yticklabels(["FAILED", "SUCCESS", "NIGHT"], color="#64748b")
        ax.set_title("Authentication Event Timeline", color=accent, fontsize=13, pad=14)
        ax.tick_params(colors="#64748b")
        ax.spines[:].set_color("#1e2d4d")
        legend = ax.legend(facecolor="#131d35", edgecolor="#1e2d4d", labelcolor="#e2e8f0")
        plt.tight_layout()
        plt.show()

        # ── Chart 3: Threat severity pie
        scores = severity(df)
        levels = [lv for _, (_, lv) in scores.items()]
        counts_s = pd.Series(levels).value_counts()

        level_colors_map = {
            "CRITICAL": "#ff2d55", "HIGH": "#ff6b35",
            "MEDIUM":   "#ffd60a", "LOW":  "#30d158"
        }
        clrs = [level_colors_map.get(l, accent) for l in counts_s.index]

        fig, ax = plt.subplots(figsize=(6, 5))
        fig.patch.set_facecolor("#0a0e1a")
        ax.set_facecolor("#0a0e1a")
        wedges, texts, autotexts = ax.pie(
            counts_s.values, labels=counts_s.index,
            colors=clrs, autopct="%1.0f%%",
            startangle=140, pctdistance=0.75,
            wedgeprops=dict(linewidth=2, edgecolor="#0a0e1a"),
        )
        for t in texts:
            t.set_color("#e2e8f0")
        for at in autotexts:
            at.set_color("#0a0e1a")
            at.set_fontweight("bold")

        ax.set_title("Threat Severity Distribution", color=accent, fontsize=13, pad=14)
        plt.tight_layout()
        plt.show()

    def export_csv(self, silent=False):
        if self.df is None:
            if not silent:
                messagebox.showwarning("No Data", "Run analysis first.")
            return

        base = os.path.dirname(self.file)
        path = os.path.join(base, "forensic_report.csv")

        export_df = self.df.copy()
        export_df["Parsed_Time"] = export_df["Parsed_Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
        export_df.to_csv(path, index=False)

        msg = f"\n  [EXPORT] Report saved → {path}\n"
        self._log(self._txt_report, msg, "SECTION")

        if not silent:
            messagebox.showinfo("Export Complete", f"CSV saved to:\n{path}")
            self._set_status(f"Exported → {path}", C["accent3"])

    # ── CONFIG DIALOG ────────────────────────────────────────
    def open_config(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("380x300")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.grab_set()

        tk.Label(win, text="⚙  SETTINGS", font=FONT_HEADING,
                 bg=C["bg"], fg=C["accent"]).pack(pady=(20, 14))

        frame = tk.Frame(win, bg=C["card"],
                         highlightbackground=C["border"], highlightthickness=1,
                         padx=24, pady=20)
        frame.pack(fill="x", padx=24)

        fields = [
            ("Failed Attempt Threshold",  "FAILED_THRESHOLD", CONFIG["FAILED_THRESHOLD"]),
            ("Log Year",                  "YEAR",             CONFIG["YEAR"]),
            ("Night-Hours End (0–23)",    "NIGHT_END",        CONFIG["NIGHT_END"]),
        ]

        entries = {}
        for row_i, (label, key, val) in enumerate(fields):
            tk.Label(frame, text=label, font=FONT_LABEL,
                     bg=C["card"], fg=C["muted"]).grid(row=row_i, column=0, sticky="w", pady=6)
            e = tk.Entry(frame, font=FONT_MONO, bg=C["panel"], fg=C["text"],
                         insertbackground=C["accent"], relief="flat", bd=0, width=10)
            e.insert(0, str(val))
            e.grid(row=row_i, column=1, sticky="e", padx=(16, 0))
            entries[key] = e

        def save():
            try:
                CONFIG["FAILED_THRESHOLD"] = int(entries["FAILED_THRESHOLD"].get())
                CONFIG["YEAR"]             = entries["YEAR"].get().strip()
                CONFIG["NIGHT_END"]        = int(entries["NIGHT_END"].get())
                self._set_status("Settings updated.", C["accent3"])
                win.destroy()
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter valid numeric values.", parent=win)

        tk.Button(win, text="SAVE SETTINGS", font=FONT_BTN, command=save,
                  bg=C["accent"], fg=C["bg"], activebackground=C["accent2"],
                  activeforeground=C["text"], relief="flat", pady=8, padx=20,
                  cursor="hand2").pack(pady=18)


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = ForensicGUI(root)
    root.mainloop()
