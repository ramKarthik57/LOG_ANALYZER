"""
SENTINEL — SOC Dashboard GUI (Refined)
========================================
Clean, professional forensic dashboard with:
  - System Logs for real-time process monitoring
  - Thread-safe simulation and pipeline
  - Hover tooltips [i] for research-level explanations
  - Advanced visual styling (ASCII blocks for data)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from datetime import datetime

from sentinel.parser import parse_log_file
from sentinel.enrichment import enrich_dataframe
from sentinel.detection import AdaptiveDetector
from sentinel.ai_engine import AIEngine
from sentinel.report import generate_html_report, generate_csv_report
from sentinel.simulator import generate_full_simulation
from sentinel.active_defense import SOAREngine
from sentinel.forensics import (
    build_all_attack_chains, detect_log_tampering,
    link_sessions, detect_insider_threats,
    ForensicNarrator, GraphForensics
)
from sentinel.scoring import RiskScoringEngine


# ── COLOR PALETTE (restrained) ───────────────────────────────
C = {
    "bg":      "#0b0f1a",
    "panel":   "#111827",
    "sidebar": "#0a0e18",
    "card":    "#1a2234",
    "border":  "#1e293b",
    "accent":  "#22d3ee",
    "text":    "#e2e8f0",
    "muted":   "#64748b",
    "dim":     "#334155",
    "red":     "#f87171",
    "amber":   "#fbbf24",
    "green":   "#34d399",
    "orange":  "#fb923c",
    "blue":    "#3b82f6",
}

FN_H = ("Consolas", 12, "bold")
FN_M = ("Consolas", 10)
FN_S = ("Consolas", 9)
FN_XS = ("Consolas", 8)
FN_BTN = ("Consolas", 9, "bold")


# ═══════════════════════════════════════════════════════════
# SIDEBAR BUTTON
# ═══════════════════════════════════════════════════════════
class SidebarButton(tk.Frame):
    def __init__(self, parent, icon, label, command, **kw):
        super().__init__(parent, bg=C["sidebar"], cursor="hand2", **kw)
        self._cmd, self._active = command, False
        self._bar = tk.Frame(self, bg=C["sidebar"], width=3)
        self._bar.pack(side="left", fill="y")
        inner = tk.Frame(self, bg=C["sidebar"], pady=9, padx=14)
        inner.pack(side="left", fill="both", expand=True)
        self._ico = tk.Label(inner, text=icon, font=("Consolas", 13),
                             bg=C["sidebar"], fg=C["dim"])
        self._ico.pack(side="left", padx=(0, 10))
        self._lbl = tk.Label(inner, text=label, font=FN_BTN,
                             bg=C["sidebar"], fg=C["muted"], anchor="w")
        self._lbl.pack(side="left", fill="x")
        for w in (self, inner, self._ico, self._lbl):
            w.bind("<Enter>", self._enter)
            w.bind("<Leave>", self._leave)
            w.bind("<Button-1>", lambda _: self._cmd())

    def _enter(self, _=None):
        for w in (self, *self.winfo_children()):
            w.configure(bg=C["card"])
            for c in w.winfo_children():
                c.configure(bg=C["card"])
                if isinstance(c, tk.Label):
                    c.configure(fg=C["accent"])
        self._bar.configure(bg=C["accent"])

    def _leave(self, _=None):
        if self._active:
            return
        for w in (self, *self.winfo_children()):
            w.configure(bg=C["sidebar"])
            for c in w.winfo_children():
                c.configure(bg=C["sidebar"])
                if isinstance(c, tk.Label):
                    c.configure(fg=C["muted"])
        self._ico.configure(fg=C["dim"])
        self._bar.configure(bg=C["sidebar"])


# ═══════════════════════════════════════════════════════════
# KPI CARD
# ═══════════════════════════════════════════════════════════
class KPI(tk.Frame):
    def __init__(self, parent, title, color=None, **kw):
        super().__init__(parent, bg=C["card"], padx=14, pady=6,
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        tk.Label(self, text=title.upper(), font=("Consolas", 7),
                 bg=C["card"], fg=C["muted"]).pack(anchor="w")
        self._v = tk.Label(self, text="—", font=("Consolas", 18, "bold"),
                           bg=C["card"], fg=color or C["accent"])
        self._v.pack(anchor="w")

    def set(self, v):
        self._v.configure(text=str(v))


# ═══════════════════════════════════════════════════════════
# MAIN GUI
# ═══════════════════════════════════════════════════════════
class SentinelGUI:

    def __init__(self, root):
        self.root = root
        self.file = self.df = None
        self.severity_scores = self.ai_results = None
        self.attack_chains = self.tamper_result = None
        self.insider_threats = self.bruteforce_df = None
        self.night_df = self.compromise_df = self.user_profiles = None
        self.soar_engine = SOAREngine()
        self.narrator = ForensicNarrator()
        self.graph_forensics = GraphForensics()

        root.title("SENTINEL  —  Forensic Intelligence Platform")
        root.geometry("1400x820")
        root.minsize(1100, 680)
        root.configure(bg=C["bg"])

        self.tooltip_window = None
        self.tag_counter = 0

        self._build()
        self._pulse = 0
        self._blink()

        self.log("SYSTEM", "Platform initialized. Awaiting log file or simulation command.")

    # ── BUILD ───────────────────────────────────────────
    def _build(self):
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_content()
        self._build_status()

    def _build_sidebar(self):
        s = tk.Frame(self.root, bg=C["sidebar"], width=220)
        s.grid(row=0, column=0, sticky="nsew")
        s.pack_propagate(False)

        # Brand
        b = tk.Frame(s, bg=C["sidebar"], pady=18, padx=18)
        b.pack(fill="x")
        tk.Label(b, text="SENTINEL", font=("Consolas", 16, "bold"),
                 bg=C["sidebar"], fg=C["text"]).pack(anchor="w")
        tk.Label(b, text="Forensic Intelligence", font=("Consolas", 8),
                 bg=C["sidebar"], fg=C["accent"]).pack(anchor="w")

        tk.Frame(s, bg=C["border"], height=1).pack(fill="x", padx=18, pady=(0, 8))

        # Buttons
        for icon, label, cmd in [
            (">>", "Load Log File",      self.load_file),
            ("~~", "Simulate Attack",    self.simulate_attack),
            ("=>", "Run Analysis",       self.run_analysis),
            ("::", "Show Graphs",        self.show_graphs),
            ("[]", "HTML Report",        self.generate_report),
            ("->", "Export CSV",         self.export_csv),
            ("##", "Settings",           self.open_config),
        ]:
            SidebarButton(s, icon, label, cmd).pack(fill="x")

        # File label at bottom
        tk.Frame(s, bg=C["border"], height=1).pack(
            fill="x", padx=18, pady=8, side="bottom")
        self._file_lbl = tk.Label(s, text="No file loaded", font=FN_XS,
                                  bg=C["sidebar"], fg=C["dim"],
                                  wraplength=190, justify="left")
        self._file_lbl.pack(side="bottom", padx=18, pady=(0, 8), anchor="w")

    def _build_content(self):
        c = tk.Frame(self.root, bg=C["bg"])
        c.grid(row=0, column=1, sticky="nsew")
        c.rowconfigure(1, weight=1)
        c.columnconfigure(0, weight=1)

        # Header
        h = tk.Frame(c, bg=C["panel"], pady=10, padx=18,
                     highlightbackground=C["border"], highlightthickness=1)
        h.grid(row=0, column=0, sticky="ew")
        h.columnconfigure(0, weight=1)

        tk.Label(h, text="FORENSIC ANALYSIS DASHBOARD", font=FN_H,
                 bg=C["panel"], fg=C["text"]).grid(row=0, column=0, sticky="w")
        tk.Label(h, text="AI-Powered Log Forensics  ·  Threat Intelligence  ·  Attack Chain Reconstruction",
                 font=FN_XS, bg=C["panel"], fg=C["muted"]).grid(row=1, column=0, sticky="w")

        # KPIs
        kf = tk.Frame(h, bg=C["panel"])
        kf.grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 0))
        self._k_total   = KPI(kf, "Events")
        self._k_failed  = KPI(kf, "Failed",    C["red"])
        self._k_suspects= KPI(kf, "Suspects",  C["amber"])
        self._k_critical= KPI(kf, "Critical",  C["red"])
        self._k_anomaly = KPI(kf, "Anomalies", C["orange"])
        for i, k in enumerate((self._k_total, self._k_failed,
                                self._k_suspects, self._k_critical, self._k_anomaly)):
            k.grid(row=0, column=i, padx=3)

        # Notebook
        nf = tk.Frame(c, bg=C["bg"])
        nf.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        nf.rowconfigure(0, weight=1)
        nf.columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("S.TNotebook", background=C["bg"], borderwidth=0)
        style.configure("S.TNotebook.Tab",
                        background=C["card"], foreground=C["muted"],
                        font=FN_BTN, padding=[14, 5], borderwidth=0)
        style.map("S.TNotebook.Tab",
                  background=[("selected", C["panel"])],
                  foreground=[("selected", C["accent"])])

        self._nb = ttk.Notebook(nf, style="S.TNotebook")
        self._nb.grid(row=0, column=0, sticky="nsew")

        tab_names = ["System Logs", "Report", "Timeline", "Severity",
                     "AI Analysis", "Forensics", "Active Defense", "Agent Narrative", "MITRE ATT&CK"]
        self._txts = {}
        for name in tab_names:
            frame, txt = self._make_tab()
            self._nb.add(frame, text=f"  {name}  ")
            self._txts[name] = txt

        # Tags setup
        for txt in self._txts.values():
            txt.tag_configure("H",    foreground=C["accent"], font=("Consolas", 11, "bold"))
            txt.tag_configure("S",    foreground=C["accent"], font=("Consolas", 10, "bold"))
            txt.tag_configure("K",    foreground=C["muted"])
            txt.tag_configure("V",    foreground=C["text"])
            txt.tag_configure("DIM",  foreground=C["dim"])
            txt.tag_configure("OK",   foreground=C["green"])
            txt.tag_configure("WARN", foreground=C["amber"])
            txt.tag_configure("FAIL", foreground=C["red"])
            txt.tag_configure("CRIT", foreground=C["red"],  font=("Consolas", 10, "bold"))
            txt.tag_configure("HIGH", foreground=C["orange"])
            txt.tag_configure("MED",  foreground=C["amber"])
            txt.tag_configure("LOW",  foreground=C["green"])
            txt.tag_configure("TIP",  foreground=C["blue"], font=("Consolas", 9, "bold"), underline=True)
            txt.tag_configure("BLOCK", foreground=C["accent"])

        self.log("SYSTEM", "Core UI generated successfully.")

    def _make_tab(self):
        f = tk.Frame(self._nb if hasattr(self, '_nb') else self.root, bg=C["panel"])
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)
        t = tk.Text(f, font=FN_M, bg=C["panel"], fg=C["text"],
                    insertbackground=C["accent"], selectbackground=C["accent"],
                    selectforeground=C["bg"], relief="flat", bd=0,
                    wrap="none", padx=18, pady=14)
        t.grid(row=0, column=0, sticky="nsew")
        vs = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        hs = ttk.Scrollbar(f, orient="horizontal", command=t.xview)
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        return f, t

    def _build_status(self):
        bar = tk.Frame(self.root, bg=C["sidebar"], height=26,
                       highlightbackground=C["border"], highlightthickness=1)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        self._dot = tk.Label(bar, text="●", font=FN_XS,
                             bg=C["sidebar"], fg=C["green"])
        self._dot.pack(side="left", padx=(12, 4))
        self._stat = tk.Label(bar, text="Ready", font=FN_XS,
                              bg=C["sidebar"], fg=C["muted"])
        self._stat.pack(side="left")
        tk.Label(bar, text="SENTINEL v1.0", font=FN_XS,
                 bg=C["sidebar"], fg=C["dim"]).pack(side="right", padx=12)

    # ── HELPERS & SYSTEM LOGS ──────────────────────────────
    def _blink(self):
        self._pulse ^= 1
        self._dot.configure(fg=C["green"] if self._pulse else C["sidebar"])
        self.root.after(800, self._blink)

    def _status(self, msg, color=None):
        self._stat.configure(text=msg, fg=color or C["muted"])

    def log(self, phase, msg, tag="V"):
        """Write to System Logs tab in real-time."""
        t = self._txts.get("System Logs")
        if not t: return
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        t.configure(state="normal")
        t.insert("end", f"[{now}] ", "DIM")
        t.insert("end", f"{phase:<12} ", "K")
        t.insert("end", f"{msg}\n", tag)
        t.see("end")
        t.configure(state="disabled")
        print(f"[{now}] {phase:<12} {msg}")

    def _clear_analysis_tabs(self):
        for name, t in self._txts.items():
            if name != "System Logs":
                t.configure(state="normal")
                t.delete("1.0", "end")

    def _w(self, tab, text, tag=None):
        t = self._txts.get(tab)
        if not t: return
        t.configure(state="normal")
        t.insert("end", text, tag) if tag else t.insert("end", text)
        t.see("end")

    def _tip(self, tab, tooltip_text):
        """Insert an [i] button that shows tooltip on hover"""
        self.tag_counter += 1
        tag_name = f"tip_{self.tag_counter}"

        t = self._txts.get(tab)
        t.configure(state="normal")
        t.insert("end", "[i]", ("TIP", tag_name))
        
        t.tag_bind(tag_name, "<Enter>", lambda e, txt=tooltip_text: self._show_tooltip(e, txt))
        t.tag_bind(tag_name, "<Leave>", lambda e: self._hide_tooltip())

    def _lock(self):
        for name, t in self._txts.items():
            if name != "System Logs":
                t.configure(state="disabled")

    def _sev_tag(self, level):
        return {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}.get(level, "V")

    # ── TOOLTIP LOGIC ──────────────────────────────────────
    def _show_tooltip(self, event, text):
        if self.tooltip_window:
            self._hide_tooltip()
            
        x = event.x_root + 15
        y = event.y_root + 10

        self.tooltip_window = tk.Toplevel(self.root)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        self.tooltip_window.configure(bg=C["border"])

        lbl = tk.Label(self.tooltip_window, text=text,
                       bg=C["panel"], fg=C["text"], font=("Consolas", 9),
                       justify="left", padx=10, pady=8, wraplength=450,
                       relief="solid", bd=1, highlightbackground=C["accent"])
        lbl.pack()

    def _hide_tooltip(self):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

    # ── ACTIONS ──────────────────────────────────────────
    def load_file(self):
        p = filedialog.askopenfilename(
            filetypes=[("Log Files", "*.log"), ("All", "*.*")])
        if p:
            self.file = p
            self._file_lbl.configure(text=os.path.basename(p))
            self._status(f"Loaded: {os.path.basename(p)}", C["accent"])
            self.log("FILE_LOAD", f"Successfully loaded external evidence log: {p}", "OK")
            self._nb.select(0) # jump to logs

    def simulate_attack(self):
        self._nb.select(0) # jump to Logs tab
        self._status("Generating simulation ...", C["amber"])
        self.log("SIMULATE", "Initiating attack simulation generation...", "WARN")
        threading.Thread(target=self._simulate_worker, daemon=True).start()

    def _simulate_worker(self):
        try:
            p = generate_full_simulation()
            self.file = p
            self.root.after(0, lambda: self._file_lbl.configure(text=f"[SIM] {os.path.basename(p)}"))
            self.root.after(0, lambda: self._status("Simulation ready", C["green"]))
            self.root.after(0, lambda: self.log("SIMULATE", f"Simulation compiled successfully to: {p}", "OK"))
        except Exception as e:
            self.root.after(0, lambda: self.log("ERROR", f"Simulation failed: {str(e)}", "FAIL"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

    def run_analysis(self):
        if not self.file:
            messagebox.showwarning("No File", "Load a log or simulate first.")
            return
        self._status("Running SENTINEL pipeline ...", C["amber"])
        self.log("PIPELINE", f"Commencing analytical pipeline on target: {os.path.basename(self.file)}")
        self._clear_analysis_tabs()
        self._nb.select(0) # show logs during operation
        threading.Thread(target=self._pipeline, daemon=True).start()

    def _pipeline(self):
        try:
            # Phase 1
            self.root.after(0, lambda: self._status("1/6  Parsing ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 1", "Multi-format log parsing and normalization"))
            df = parse_log_file(self.file)
            if df.empty:
                self.root.after(0, lambda: self.log("PHASE 1", "No valid events parsed from file.", "FAIL"))
                self.root.after(0, lambda: messagebox.showerror("Error", "No events parsed."))
                return

            # Phase 2
            self.root.after(0, lambda: self._status("2/6  Enriching ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 2", f"Enriching {len(df)} events with Threat Intel/GeoIP"))
            df = enrich_dataframe(df)
            self.df = df

            # Phase 3
            self.root.after(0, lambda: self._status("3/6  Detecting ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 3", "Running adaptive threshold detection heuristics"))
            det = AdaptiveDetector()
            self.bruteforce_df = det.detect_bruteforce(df)
            self.night_df = det.detect_night_logins(df)
            self.compromise_df = det.detect_compromise_pattern(df)

            # Phase 4
            self.root.after(0, lambda: self._status("4/6  AI Engine ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 4", "Executing ML models (Isolation Forest, DBSCAN, HMM)"))
            ai = AIEngine()
            self.ai_results = ai.run_full_analysis(df)
            self.user_profiles = self.ai_results.get("user_profiles", {})

            # Phase 5
            self.root.after(0, lambda: self._status("5/6  Scoring ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 5", "Evaluating multi-factor risk scores per IP"))
            scorer = RiskScoringEngine()
            self.severity_scores = scorer.score_all_ips(df, self.ai_results.get("anomaly"))

            # Phase 6
            self.root.after(0, lambda: self._status("6/6  Forensics ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 6", "Reconstructing MITRE attack chains and tracking sessions"))
            sev_map = {ip: d["level"] for ip, d in self.severity_scores.items()}
            self.attack_chains = build_all_attack_chains(df, sev_map)
            self.tamper_result = detect_log_tampering(df)
            self.df = link_sessions(df)
            self.insider_threats = detect_insider_threats(self.df, self.user_profiles)
            
            # Phase 7: Active Defense (SOAR)
            self.root.after(0, lambda: self._status("7/7  SOAR Active Defense ...", C["amber"]))
            self.root.after(0, lambda: self.log("PHASE 7", "Executing automated response orchestration"))
            self.soar_engine.execute_responses(self.severity_scores)

            self.root.after(0, lambda: self.log("SUCCESS", "Pipeline execution complete. Rendering forensic V2 views.", "OK"))

            self.root.after(0, lambda: self.log("SUCCESS", "Pipeline execution complete. Rendering forensic views.", "OK"))
            self.root.after(0, self._fill_tabs)

        except Exception as e:
            error_msg = str(e)
            import traceback; traceback.print_exc()
            self.root.after(0, lambda: self.log("FATAL", f"Exception in pipeline: {error_msg}", "CRIT"))
            self.root.after(0, lambda: messagebox.showerror("Error", error_msg))

    # ── TAB POPULATION ─────────────────────────────────
    def _fill_tabs(self):
        import numpy as np
        df = self.df
        bf = self.bruteforce_df
        scores = self.severity_scores
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        SEP = "─" * 80 + "\n"
        DSEP = "═" * 80 + "\n"

        bf_flagged = bf[bf.Is_Bruteforce] if "Is_Bruteforce" in bf.columns else bf.head(0)
        n_suspects = len(bf_flagged)
        n_crit = sum(1 for d in scores.values() if d["level"] == "CRITICAL")
        n_high = sum(1 for d in scores.values() if d["level"] == "HIGH")
        n_med  = sum(1 for d in scores.values() if d["level"] == "MEDIUM")
        n_low  = sum(1 for d in scores.values() if d["level"] == "LOW")
        anom_df = self.ai_results.get("anomaly")
        n_anom = len(anom_df[anom_df.is_anomaly]) if anom_df is not None and "is_anomaly" in anom_df.columns else 0

        n_total  = len(df)
        n_failed = len(df[df.Event == "FAILED_LOGIN"])
        n_success= len(df[df.Event == "SUCCESSFUL_LOGIN"])
        n_ips    = df.IP_Address.nunique()
        n_users  = df.Username.nunique()
        n_sessions = df.Session_ID.nunique() if "Session_ID" in df.columns else 0
        chains   = self.attack_chains or []

        self._k_total.set(n_total)
        self._k_failed.set(n_failed)
        self._k_suspects.set(n_suspects)
        self._k_critical.set(n_crit)
        self._k_anomaly.set(n_anom)

        sorted_scores = sorted(scores.items(), key=lambda x: x[1]["score"], reverse=True)

        def section(tab, title, tooltip=""):
            self._w(tab, f"\n  {title}  ", "S")
            if tooltip:
                self._tip(tab, tooltip)
            self._w(tab, f"\n  {SEP}", "DIM")

        def header(tab, title, tooltip=""):
            self._w(tab, f"\n  {DSEP}", "DIM")
            self._w(tab, f"  {title}  ", "H")
            if tooltip:
                self._tip(tab, tooltip)
            self._w(tab, f"\n  {DSEP}\n", "DIM")

        time_min = df.Parsed_Time.min()
        time_max = df.Parsed_Time.max()
        duration = time_max - time_min
        dur_h = duration.total_seconds() / 3600

        # ═══════════════════════════════════════════════
        # TAB 1: REPORT (Executive Summary + Full Findings)
        # ═══════════════════════════════════════════════
        R = "Report"
        header(R, "SENTINEL  —  FORENSIC INTELLIGENCE REPORT", "High-level managerial and executive summary of the entire investigation.")
        self._w(R, f"  Report ID       : SENT-{now[:10].replace('-','')}-001\n", "K")
        self._w(R, f"  Classification  : CONFIDENTIAL\n", "K")
        self._w(R, f"  Generated       : {now}\n", "K")
        self._w(R, f"  Analyst         : SENTINEL AI Engine v1.0\n", "K")
        self._w(R, f"  Log Source      : {os.path.basename(self.file)}\n", "K")
        self._w(R, f"  Time Window     : {time_min} → {time_max}\n", "K")
        self._w(R, f"  Duration        : {dur_h:.1f} hours\n", "K")

        section(R, "EXECUTIVE SUMMARY", "Distills the final automated assessments into actionable executive intelligence.")
        threat_level = "CRITICAL" if n_crit > 0 else "HIGH" if n_high > 0 else "MEDIUM" if n_med > 0 else "LOW"
        self._w(R, f"  Overall Threat Assessment: ", "K")
        self._w(R, f"{threat_level}\n\n", self._sev_tag(threat_level))

        self._w(R, f"  Analysis of {n_total} authentication events across {dur_h:.1f} hours reveals:\n\n", "V")

        finding_num = 1
        if n_crit > 0:
            self._w(R, f"  [{finding_num}] ", "CRIT")
            self._w(R, f"{n_crit} IP(s) classified CRITICAL — active compromise detected\n", "CRIT")
            finding_num += 1
        if n_suspects > 0:
            self._w(R, f"  [{finding_num}] ", "FAIL")
            self._w(R, f"{n_suspects} brute-force source(s) identified via dynamic thresholding\n", "FAIL")
            finding_num += 1
        if not self.compromise_df.empty:
            self._w(R, f"  [{finding_num}] ", "CRIT")
            self._w(R, f"{len(self.compromise_df)} confirmed FAIL→SUCCESS breach pattern(s)\n", "CRIT")
            finding_num += 1
        if n_anom > 0:
            self._w(R, f"  [{finding_num}] ", "HIGH")
            self._w(R, f"{n_anom} statistically anomalous IP(s) flagged by ML isolation layer\n", "HIGH")
            finding_num += 1
        if chains:
            max_progress = max(c["kill_chain_progress"] for c in chains)
            self._w(R, f"  [{finding_num}] ", "WARN")
            self._w(R, f"{len(chains)} attack chain(s) compiled (max killchain depth: {max_progress*100:.0f}%)\n", "WARN")

        # GeoIP Breakdown
        if "Geo_Country" in df.columns:
            section(R, "FOREIGN ACTOR PRESENCE", "Correlates attack sourcing with geographical IP assignments")
            geo_counts = df.drop_duplicates("IP_Address").Geo_Country.value_counts()
            self._w(R, f"  {'Country':<22} {'IPs':>6} {'Events':>8} {'Avg Risk':>10}\n", "K")
            self._w(R, f"  {'─'*22} {'─'*6} {'─'*8} {'─'*10}\n", "DIM")
            for country in geo_counts.index:
                c_ips = df[df.Geo_Country == country].IP_Address.nunique()
                c_events = len(df[df.Geo_Country == country])
                c_risk = df[df.Geo_Country == country]["Geo_Risk"].mean()
                tag = "FAIL" if c_risk > 0.6 else "WARN" if c_risk > 0.3 else "OK"
                self._w(R, f"  {country:<22} {c_ips:>6} {c_events:>8} ", "V")
                self._w(R, f"{c_risk:>9.2f}\n", tag)

        section(R, "BRUTE FORCE DETECTION", "Identifies rapid automated guessing mechanics against SSH/authentication portals.")
        det = self.bruteforce_df
        threshold = det.Threshold.iloc[0] if "Threshold" in det.columns and not det.empty else "N/A"
        self._w(R, f"  Methodology : Adaptive Z-Score (auto-calibrated threshold: {threshold} failed attempts)\n\n", "K")
        if bf_flagged.empty:
            self._w(R, "  Result: No brute force activity detected.\n", "OK")
        else:
            self._w(R, f"  {'IP Address':<22} {'Attempts':>10} {'Threshold':>11} {'Confidence':>12}\n", "K")
            self._w(R, f"  {'─'*22} {'─'*10} {'─'*11} {'─'*12}\n", "DIM")
            for _, row in bf_flagged.iterrows():
                self._w(R, f"  {row.IP_Address:<22} {row.Failed_Count:>10} {str(row.get('Threshold',''))[:11]:>11} {row.Confidence:>11.1%}\n", "FAIL")

        self._w(R, f"\n  {DSEP}", "DIM")
        self._w(R, "  END OF EXECUTIVE REPORT\n", "H")
        self._w(R, f"  {DSEP}", "DIM")

        # ═══════════════════════════════════════════════
        # TAB 2: TIMELINE (with session boundaries)
        # ═══════════════════════════════════════════════
        T = "Timeline"
        header(T, "EVENT TIMELINE", "Chronological logging of structural system access vectors.")
        self._w(T, f"  Records: {n_total}  |  Time Window: {dur_h:.1f}h  |  Sessions: {n_sessions}\n\n", "K")
        has_session = "Session_ID" in df.columns
        self._w(T, f"  {'Timestamp':<24} {'IP Address':<18} {'User':<14} {'Event':<18}", "K")
        if has_session: self._w(T, f" {'Session':<10}", "K")
        self._w(T, "\n  " + "─"*78 + "\n", "DIM")

        prev_session = None
        for _, row in df.sort_values("Parsed_Time").iterrows():
            cur_session = row.get("Session_ID", "")
            if has_session and prev_session and cur_session != prev_session:
                self._w(T, f"  {'·'*78}\n", "DIM")
            prev_session = cur_session

            tag = {"FAILED_LOGIN": "FAIL", "SUCCESSFUL_LOGIN": "OK",
                   "ROOT_ACCESS": "CRIT", "SUDO_ATTEMPT": "WARN",
                   "INVALID_USER": "WARN"}.get(row.Event, "K")
            self._w(T, f"  {str(row.Timestamp):<24} {row.IP_Address:<18} {row.get('Username','?'):<14} ", "K")
            self._w(T, f"{row.Event:<18}", tag)
            if has_session: self._w(T, f" {cur_session:<10}", "DIM")
            self._w(T, "\n")

        # ═══════════════════════════════════════════════
        # TAB 3: SEVERITY (Advanced visual blocks)
        # ═══════════════════════════════════════════════
        S = "Severity"
        header(S, "MULTI-FACTOR RISK ENGINE", "Deep-dives into weighted ensemble severity logic governing risk classification.")

        self._w(S, "  Ensemble Logic : Score = ∑ (w_i * f_i)\n", "K")
        self._w(S, "  Thresholding   : CRITICAL >= 40  |  HIGH >= 25  |  MEDIUM >= 12  |  LOW < 12\n\n", "K")
        
        self._w(S, f"  {'Rank':<6} {'IP Address':<20}  {'Score':<8}  {'Level':<12} {'Visual Heatmap'}\n", "K")
        self._w(S, f"  {'─'*6} {'─'*20}  {'─'*8}  {'─'*12} {'─'*24}\n", "DIM")
        
        for rank, (ip, d) in enumerate(sorted_scores, 1):
            score = d["score"]
            lvl = d["level"]
            ip_row = df[df.IP_Address == ip].iloc[0]
            
            # create ASCII bar logic
            max_s = 100
            blocks = int(min(score, 100) / 4.16) # up to 24 blocks
            bar = "▰" * blocks + "▱" * (24 - blocks)
            
            self._w(S, f"  #{rank:<5} {ip:<20}  {score:<8.1f}  ", "V")
            self._w(S, f"{lvl:<12} ", self._sev_tag(lvl))
            self._w(S, f"[{bar}]\n", self._sev_tag(lvl))

        self._w(S, f"\n  {SEP}", "DIM")
        
        section(S, "DETAILED DOSSIERS", "Forensic factor breakdown justifying individual IP severity scores.")
        for rank, (ip, d) in enumerate(sorted_scores, 1):
            if d["score"] < 5.0 and rank > 15: continue # only show top for dossiers
            ip_df = df[df.IP_Address == ip]
            self._w(S, f"\n  [ DOSSIER ] #{rank} — {ip} ", "V")
            self._w(S, f"[{d['level']}]\n", self._sev_tag(d['level']))
            
            factors = d.get("factors", {})
            if factors:
                self._w(S, f"    {'Factor Engine':<26} {'Raw':>6}  {'Wt.Pts':>7}   {'Risk Intensity'}\n", "K")
                self._w(S, f"    {'─'*26} {'─'*6}  {'─'*7}   {'─'*20}\n", "DIM")
                for name, (raw, weighted, desc) in factors.items():
                    wb = int(weighted)
                    bar2 = "▰" * min(wb, 20) + "▱" * (20 - min(wb, 20))
                    t2 = "FAIL" if wb > 8 else "WARN" if wb > 4 else "K"
                    self._w(S, f"    {name:<26} {raw:>6.1f}  {weighted:>7.1f}   ", "K")
                    self._w(S, f"[{bar2}]\n", t2)
            self._w(S, f"  {SEP}", "DIM")

        # ═══════════════════════════════════════════════
        # TAB 4: AI ANALYSIS
        # ═══════════════════════════════════════════════
        A = "AI Analysis"
        header(A, "AI / MACHINE LEARNING ENGINE", "Unsupervised algorithms targeting hidden statistical anomalies and multi-actor campaigns.")

        section(A, "ISOLATION FOREST", "Evaluates high-dimensional IP feature vectors against normal organizational behavior.")
        if anom_df is not None and not anom_df.empty:
            anomalies = anom_df.sort_values("anomaly_score", ascending=False)
            self._w(A, f"  {'IP Address':<18} {'Score':>10} {'Status':<12} {'Visual Contamination'}\n", "K")
            self._w(A, f"  {'─'*18} {'─'*10} {'─'*12} {'─'*24}\n", "DIM")
            for _, r in anomalies.iterrows():
                flag = "ANOMALY" if r.is_anomaly else "normal"
                tag = "FAIL" if r.is_anomaly else "OK"
                blocks = int(min(max(r.anomaly_score * 20 + 10, 0), 24))
                bar = "▰" * blocks + "▱" * (24 - blocks)
                self._w(A, f"  {r.IP_Address:<18} {r.anomaly_score:>10.4f} ", "V")
                self._w(A, f"{flag:<12} ", tag)
                self._w(A, f"[{bar}]\n", tag)
        self._w(A, "\n")

        section(A, "DBSCAN CLUSTERING", "Density-based spatial clustering to associate disparate IPs into coordinated campaigns.")
        cluster_df = self.ai_results.get("clusters")
        if cluster_df is not None and not cluster_df.empty:
            camps = cluster_df[cluster_df.campaign_cluster >= 0] if "campaign_cluster" in cluster_df.columns else cluster_df.head(0)
            if camps.empty:
                self._w(A, "  Result: No coordinated IP syndicates found (all lone actors).\n", "OK")
            else:
                for cid in sorted(camps.campaign_cluster.unique()):
                    grp = camps[camps.campaign_cluster == cid]
                    self._w(A, f"  [Campaign ID:{cid:<3}] Identified {len(grp)} cooperative nodes: ", "WARN")
                    self._w(A, f"{', '.join(grp.IP_Address.tolist())}\n", "V")

        section(A, "HIDDEN MARKOV MODEL", "Probabilistic Viterbi decoding of observed user behavioral streams over time.")
        self._w(A, f"  {'Username':<16} {'Current State':<16} {'Risk Probability'}\n", "K")
        self._w(A, f"  {'─'*16} {'─'*16} {'─'*24}\n", "DIM")
        for user, p in sorted(self.user_profiles.items(), key=lambda x: x[1]["risk"], reverse=True):
            tag = "CRIT" if p["current_state"] == "COMPROMISED" else "WARN" if p["current_state"] == "ELEVATED" else "OK"
            blocks = int(p["risk"] * 24)
            bar = "▰" * blocks + "▱" * (24 - blocks)
            self._w(A, f"  {user:<16} ", "V")
            self._w(A, f"{p['current_state']:<16} ", tag)
            self._w(A, f"[{bar}] {p['risk']:.2f}\n", tag)

        # ═══════════════════════════════════════════════
        # TAB 5: FORENSICS
        # ═══════════════════════════════════════════════
        F = "Forensics"
        header(F, "FORENSIC ANALYSIS ENGINE", "Cyber-forensic causality linking, session mapping, and cryptographic log verification.")

        section(F, "ATTACK CHAIN DAGs", "Directed acyclic graphs organizing events into the formal cyber kill chain framework.")
        if chains:
            for ch in chains[:5]: # top 5 chains
                pct = ch["kill_chain_progress"] * 100
                tag = "CRIT" if pct > 50 else "WARN" if pct > 20 else "OK"
                self._w(F, f"  Chain Vector : {ch['ip']}\n", "V")
                self._w(F, f"  Penetration  : {pct:.0f}%\n", tag)
                phases = ch['phases_reached']
                p_str = " ➔ ".join(phases)
                self._w(F, f"  Propagation  : {p_str}\n\n", "K")
        else:
            self._w(F, "  No chains reconstructed.\n", "K")

        section(F, "SHANNON ENTROPY TAMPER DETECT", "Calculates entropy fluctuations across chronological events to expose log scrubbing techniques.")
        if self.tamper_result and self.tamper_result.get("tampered"):
            self._w(F, "  CRITICAL TAMPERING WARNING\n", "CRIT")
            for r in self.tamper_result["tamper_regions"]:
                self._w(F, f"  Anomaly located bounding lines {r[0]} to {r[1]} (z={r[3]:.1f})\n", "FAIL")
        else:
            self._w(F, "  Log sequence structural integrity confirmed valid.\n", "OK")

        # ═══════════════════════════════════════════════
        # TAB 6: MITRE ATT&CK
        # ═══════════════════════════════════════════════
        M = "MITRE ATT&CK"
        header(M, "MITRE ATT&CK PIPELINE COVERAGE", "Direct translation of observed telemetry into standard MITRE operational taxonomies.")

        if "MITRE_Technique" in df.columns:
            section(M, "TACTIC PHASE INTENSITY", "Relative saturation analysis indicating attacker objectives.")
            tactics = df.MITRE_Tactic.value_counts()
            max_cnt = tactics.max() if not tactics.empty else 1
            for tactic, cnt in tactics.items():
                bar_len = int(cnt / max_cnt * 35)
                bar = "▰" * bar_len + "▱" * (35 - bar_len)
                pct = cnt / n_total * 100
                tag = "FAIL" if "Privilege" in tactic or "Execution" in tactic else "WARN"
                self._w(M, f"  {tactic:<24} {cnt:>5} ({pct:>4.1f}%)  ", "K")
                self._w(M, f"[{bar}]\n", tag)

            section(M, "OPERATIONAL TECHNIQUE DICTIONARY", "Isolated unique techniques mapped during forensic aggregation.")
            mitre = df.MITRE_Technique.value_counts()
            self._w(M, f"  {'Signature':<14} {'Formal Designation':<30} {'Occurrences':>11}\n", "K")
            self._w(M, f"  {'─'*14} {'─'*30} {'─'*11}\n", "DIM")
            for tech, cnt in mitre.items():
                parts = tech.split(" — ")
                tid = parts[0] if len(parts) > 1 else tech[:12]
                tname = parts[1] if len(parts) > 1 else ""
                self._w(M, f"  {tid:<14} {tname[:28]:<30} {cnt:>11}\n", "V")
        
        # ═══════════════════════════════════════════════
        # TAB 7: ACTIVE DEFENSE (SOAR)
        # ═══════════════════════════════════════════════
        AD = "Active Defense"
        header(AD, "SOAR - AUTONOMOUS RESPONSE LOG", "Live tracking of automated countermeasures executed by the SENTINEL active defense layer.")
        soar_history = self.soar_engine.get_soar_logs()
        if not soar_history:
            self._w(AD, "  No automated defensive actions required at this time.\n", "OK")
        else:
            self._w(AD, f"  {'Timestamp':<20} {'Action':<18} {'Target':<20} {'Status':<12}\n", "K")
            self._w(AD, f"  {'─'*20} {'─'*18} {'─'*20} {'─'*12}\n", "DIM")
            for entry in soar_history:
                tag = "CRIT" if entry["action"] == "ACCOUNT_LOCKOUT" else "HIGH"
                self._w(AD, f"  {entry['time']:<20} {entry['action']:<18} {entry['target']:<20} ", "V")
                self._w(AD, f"{entry['status']}\n", tag)

        # ═══════════════════════════════════════════════
        # TAB 8: AGENT NARRATIVE
        # ═══════════════════════════════════════════════
        AN = "Agent Narrative"
        header(AN, "AGENTIC FORENSIC NARRATIVE", "Agentic AI synthesis of technical evidence into natural language investigative reports.")
        
        # Sort by score and show top narrations
        for ip, d in sorted_scores:
            if d["score"] < 15.0: continue
            
            # Find the chain for this IP
            ip_chain = next((c for c in chains if c["ip"] == ip), {"ip": ip, "phases_reached": [], "kill_chain_progress": 0.0})
            
            narrative = self.narrator.generate_narrative(d | {"ip": ip}, ip_chain)
            self._w(AN, narrative + "\n")
            self._w(AN, f"  {SEP}\n", "DIM")

        self._lock()
        str_msg = f"Done — {n_total} events handled. Critical nodes: {n_crit}"
        self._status(str_msg, C["green"])
        self.log("SUCCESS", str_msg, "OK")

        # ensure we pop the logs tab first, then analysis pops
        if self._nb.index(self._nb.select()) == 0:
            self._nb.select(1) # shift focus to REPORT

    def show_graphs(self):
        if self.df is None:
            messagebox.showwarning("No Data", "Run analysis first.")
            return
        show_all_plots(self.df, self.severity_scores)

    def generate_report(self):
        if self.df is None: return
        try:
            p = generate_html_report(
                self.df, self.severity_scores, self.bruteforce_df,
                self.night_df, self.compromise_df, self.tamper_result,
                self.attack_chains, self.user_profiles,
                self.insider_threats, self.ai_results, self.file)
            self._status(f"Report saved: {p}", C["green"])
            self.log("REPORT", f"Succeeded compiling HTML forensic summary: {p}", "OK")
            messagebox.showinfo("Done", f"Report saved:\n{p}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_csv(self):
        if self.df is None: return
        try:
            p = generate_csv_report(self.df, self.severity_scores, self.file)
            self._status(f"CSV exported: {p}", C["green"])
            self.log("REPORT", f"Data exported standard flat CSV index: {p}", "OK")
            messagebox.showinfo("Done", f"CSV saved:\n{p}")
        except Exception as e:
            pass

    def open_config(self):
        w = tk.Toplevel(self.root)
        w.title("Settings")
        w.geometry("380x280")
        w.configure(bg=C["bg"])
        w.resizable(False, False)
        tk.Label(w, text="SETTINGS", font=FN_H, bg=C["bg"], fg=C["accent"]).pack(pady=(18, 12))
        tk.Button(w, text="CLOSE", font=FN_BTN, command=w.destroy, bg=C["accent"]).pack(pady=14)

def main():
    root = tk.Tk()
    SentinelGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
