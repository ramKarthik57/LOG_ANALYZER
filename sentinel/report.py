"""
SENTINEL — Forensic Report Generator
======================================
Generates comprehensive HTML forensic reports with embedded
analysis results, severity breakdowns, and MITRE ATT&CK mapping.
Falls back gracefully if optional PDF libraries are unavailable.
"""

import os
from datetime import datetime
import pandas as pd


def _severity_color(level: str) -> str:
    return {
        "CRITICAL": "#ff2d55", "HIGH": "#ff6b35",
        "MEDIUM": "#ffd60a",   "LOW": "#30d158",
    }.get(level, "#64748b")


def _severity_badge(level: str) -> str:
    c = _severity_color(level)
    return (f'<span style="background:{c};color:#0a0e1a;padding:2px 10px;'
            f'border-radius:4px;font-weight:bold;font-size:12px">{level}</span>')


def generate_html_report(
    df: pd.DataFrame,
    severity_scores: dict,
    bruteforce_df: pd.DataFrame,
    night_df: pd.DataFrame,
    compromise_df: pd.DataFrame,
    tamper_result: dict,
    attack_chains: list,
    user_profiles: dict,
    insider_threats: list,
    ai_results: dict,
    log_file: str,
    output_path: str = None,
) -> str:
    """
    Generate a comprehensive HTML forensic report.
    Returns the path to the generated file.
    """
    if output_path is None:
        base = os.path.dirname(log_file) if log_file else "."
        output_path = os.path.join(base, "SENTINEL_Forensic_Report.html")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(df)
    failed = len(df[df.Event == "FAILED_LOGIN"])
    success = len(df[df.Event == "SUCCESSFUL_LOGIN"])

    # Count severity levels
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ip, data in severity_scores.items():
        sev_counts[data["level"]] = sev_counts.get(data["level"], 0) + 1

    # ── Build HTML ──
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SENTINEL Forensic Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Courier New', monospace;
    background: #0a0e1a; color: #e2e8f0;
    padding: 40px; line-height: 1.6;
  }}
  .header {{
    border-bottom: 2px solid #00d4ff;
    padding-bottom: 20px; margin-bottom: 30px;
  }}
  .header h1 {{ color: #00d4ff; font-size: 28px; }}
  .header .sub {{ color: #64748b; font-size: 12px; margin-top: 4px; }}
  .kpi-row {{
    display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap;
  }}
  .kpi {{
    background: #131d35; border: 1px solid #1e2d4d;
    padding: 16px 24px; border-radius: 8px; min-width: 160px;
  }}
  .kpi .label {{ color: #64748b; font-size: 11px; text-transform: uppercase; }}
  .kpi .value {{ color: #00d4ff; font-size: 28px; font-weight: bold; }}
  .kpi.danger .value {{ color: #ef4444; }}
  .kpi.warn .value {{ color: #f59e0b; }}
  .kpi.critical .value {{ color: #ff2d55; }}
  h2 {{
    color: #7c3aed; font-size: 16px; margin: 30px 0 12px;
    border-left: 3px solid #7c3aed; padding-left: 12px;
  }}
  table {{
    width: 100%; border-collapse: collapse; margin: 12px 0 24px;
    font-size: 12px;
  }}
  th {{
    background: #131d35; color: #00d4ff; padding: 10px 12px;
    text-align: left; border-bottom: 1px solid #1e2d4d;
  }}
  td {{
    padding: 8px 12px; border-bottom: 1px solid #0f1629;
  }}
  tr:hover {{ background: #0f1629; }}
  .badge {{
    padding: 2px 10px; border-radius: 4px;
    font-weight: bold; font-size: 11px; color: #0a0e1a;
  }}
  .section {{ background: #0f1629; padding: 20px; border-radius: 8px; margin: 16px 0; }}
  .factor-bar {{
    display: inline-block; height: 8px; border-radius: 4px;
    background: #00d4ff; margin-right: 8px;
  }}
  .footer {{
    margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e2d4d;
    color: #64748b; font-size: 11px; text-align: center;
  }}
  .chain-node {{
    display: inline-block; background: #131d35; border: 1px solid #1e2d4d;
    padding: 8px 14px; border-radius: 6px; margin: 4px;
    font-size: 11px;
  }}
  .chain-arrow {{ color: #00d4ff; margin: 0 4px; font-size: 18px; }}
</style>
</head>
<body>

<div class="header">
  <h1>⬛ SENTINEL — FORENSIC ANALYSIS REPORT</h1>
  <div class="sub">
    Self-Evolving Neural Threat Intelligence Engine for Log-based Forensics<br>
    Generated: {now} &nbsp;|&nbsp; Log File: {os.path.basename(log_file) if log_file else 'N/A'}
  </div>
</div>

<!-- KPI CARDS -->
<div class="kpi-row">
  <div class="kpi"><div class="label">Total Events</div><div class="value">{total}</div></div>
  <div class="kpi danger"><div class="label">Failed Logins</div><div class="value">{failed}</div></div>
  <div class="kpi"><div class="label">Successful</div><div class="value">{success}</div></div>
  <div class="kpi critical"><div class="label">Critical IPs</div><div class="value">{sev_counts["CRITICAL"]}</div></div>
  <div class="kpi warn"><div class="label">High-Risk IPs</div><div class="value">{sev_counts["HIGH"]}</div></div>
  <div class="kpi"><div class="label">Unique IPs</div><div class="value">{df.IP_Address.nunique()}</div></div>
</div>
"""

    # ── THREAT SEVERITY ASSESSMENT ──
    html += '<h2>🎯 THREAT SEVERITY ASSESSMENT</h2>\n<table>\n'
    html += '<tr><th>IP Address</th><th>Score</th><th>Level</th><th>Country</th><th>Top Factor</th></tr>\n'
    sorted_scores = sorted(severity_scores.items(), key=lambda x: x[1]["score"], reverse=True)
    for ip, data in sorted_scores:
        ip_row = df[df.IP_Address == ip]
        country = ip_row.iloc[0].get("Geo_Country", "—") if not ip_row.empty else "—"
        # Find top contributing factor
        factors = data.get("factors", {})
        top_factor = max(factors.items(), key=lambda x: x[1][1])[0] if factors else "—"
        html += (f'<tr><td>{ip}</td><td>{data["score"]}</td>'
                 f'<td>{_severity_badge(data["level"])}</td>'
                 f'<td>{country}</td><td>{top_factor}</td></tr>\n')
    html += '</table>\n'

    # ── BRUTE FORCE ANALYSIS ──
    html += '<h2>🔒 BRUTE FORCE ANALYSIS (Adaptive Threshold)</h2>\n'
    if bruteforce_df is not None and not bruteforce_df.empty:
        bf = bruteforce_df[bruteforce_df.Is_Bruteforce] if "Is_Bruteforce" in bruteforce_df.columns else bruteforce_df
        if not bf.empty:
            html += '<table><tr><th>IP Address</th><th>Failed Attempts</th><th>Threshold</th><th>Confidence</th></tr>\n'
            for _, row in bf.iterrows():
                conf = row.get("Confidence", 0)
                html += (f'<tr><td>{row.IP_Address}</td><td>{row.Failed_Count}</td>'
                         f'<td>{row.get("Threshold", "—")}</td>'
                         f'<td>{conf:.1%}</td></tr>\n')
            html += '</table>\n'
        else:
            html += '<div class="section">✅ No brute force activity detected.</div>\n'
    else:
        html += '<div class="section">✅ No brute force activity detected.</div>\n'

    # ── NIGHT LOGINS ──
    html += '<h2>🌙 SUSPICIOUS NIGHT LOGINS</h2>\n'
    if night_df is not None and not night_df.empty:
        html += '<table><tr><th>Time</th><th>IP Address</th><th>Username</th></tr>\n'
        for _, row in night_df.iterrows():
            html += f'<tr><td>{row.Parsed_Time}</td><td>{row.IP_Address}</td><td>{row.get("Username", "—")}</td></tr>\n'
        html += '</table>\n'
    else:
        html += '<div class="section">✅ No abnormal login times detected.</div>\n'

    # ── COMPROMISE PATTERNS ──
    html += '<h2>⚠️ COMPROMISE PATTERN ANALYSIS</h2>\n'
    if compromise_df is not None and not compromise_df.empty:
        html += '<table><tr><th>IP</th><th>Failed</th><th>Success</th><th>Pattern</th></tr>\n'
        for _, row in compromise_df.iterrows():
            html += (f'<tr><td>{row.IP_Address}</td><td>{row.Failed_Count}</td>'
                     f'<td>{row.Success_Count}</td><td style="color:#ff2d55">{row.Pattern}</td></tr>\n')
        html += '</table>\n'
    else:
        html += '<div class="section">✅ No compromise patterns detected.</div>\n'

    # ── ATTACK CHAINS ──
    html += '<h2>🔗 ATTACK CHAIN RECONSTRUCTION (MITRE ATT&CK Kill Chain)</h2>\n'
    if attack_chains:
        for chain in attack_chains[:5]:
            progress = chain.get("kill_chain_progress", 0)
            phases = chain.get("phases_reached", [])
            html += f'<div class="section">'
            html += f'<strong style="color:#00d4ff">IP: {chain["ip"]}</strong>'
            html += f' &nbsp;|&nbsp; Kill-Chain Progress: <strong style="color:#ff2d55">{progress*100:.0f}%</strong><br>'
            html += f'Phases: {" → ".join(phases)}<br><br>'
            for node in chain.get("nodes", [])[:10]:
                color = "#f59e0b" if node["phase"] == "RECONNAISSANCE" else \
                        "#ff6b35" if node["phase"] == "INITIAL_ACCESS" else \
                        "#ff2d55" if node["phase"] == "PRIVILEGE_ESCALATION" else "#00d4ff"
                html += f'<span class="chain-node" style="border-color:{color}">{node["phase"]}<br>'
                html += f'<span style="color:#64748b;font-size:10px">{node["event"]} @ {node["time"][-8:]}</span></span>'
                html += '<span class="chain-arrow">→</span>'
            html += '</div>\n'
    else:
        html += '<div class="section">No significant attack chains reconstructed.</div>\n'

    # ── LOG TAMPERING DETECTION ──
    html += '<h2>🛡️ LOG INTEGRITY / TAMPERING ANALYSIS</h2>\n'
    if tamper_result and tamper_result.get("tampered"):
        html += f'<div class="section" style="border-left: 3px solid #ff2d55">'
        html += f'<strong style="color:#ff2d55">⚠️ POTENTIAL LOG TAMPERING DETECTED</strong><br>'
        html += f'Baseline Entropy: {tamper_result["baseline_entropy"]}<br>'
        html += f'Suspicious Regions: {len(tamper_result["tamper_regions"])}<br><br>'
        for region in tamper_result["tamper_regions"]:
            html += f'Lines {region[0]}–{region[1]}: entropy={region[2]}, z-score={region[3]}<br>'
        html += '</div>\n'
    else:
        html += '<div class="section">✅ No signs of log tampering detected. Entropy is within normal range.</div>\n'

    # ── INSIDER THREAT DETECTION ──
    html += '<h2>👤 INSIDER THREAT ANALYSIS (HMM Behavioral Profiling)</h2>\n'
    if insider_threats:
        html += '<table><tr><th>Username</th><th>Risk</th><th>State</th><th>Indicators</th></tr>\n'
        for threat in insider_threats:
            html += (f'<tr><td>{threat["username"]}</td>'
                     f'<td>{threat["risk_score"]:.2f}</td>'
                     f'<td style="color:#ff2d55">{threat["current_state"]}</td>'
                     f'<td>{"<br>".join(threat["indicators"])}</td></tr>\n')
        html += '</table>\n'
    else:
        html += '<div class="section">✅ No insider threat indicators detected.</div>\n'

    # ── RISK SCORING EXPLAINABILITY ──
    html += '<h2>📊 RISK SCORE FACTOR BREAKDOWN (Top 5 IPs)</h2>\n'
    for ip, data in sorted_scores[:5]:
        html += f'<div class="section"><strong style="color:#00d4ff">IP: {ip}</strong>'
        html += f' — Score: <strong>{data["score"]}</strong> {_severity_badge(data["level"])}<br><br>'
        factors = data.get("factors", {})
        for name, (raw, weighted, desc) in factors.items():
            bar_width = min(int(weighted * 5), 200)
            html += (f'<div style="margin:3px 0"><span style="color:#64748b;font-size:11px">'
                     f'{name}</span><br>'
                     f'<span class="factor-bar" style="width:{bar_width}px"></span>'
                     f'<span style="font-size:11px"> {weighted:.1f} pts — {desc}</span></div>')
        html += '</div>\n'

    # ── MITRE ATT&CK MAPPING ──
    if "MITRE_Technique" in df.columns:
        html += '<h2>🎯 MITRE ATT&CK TECHNIQUE MAPPING</h2>\n'
        mitre_counts = df.MITRE_Technique.value_counts()
        html += '<table><tr><th>Technique</th><th>Tactic</th><th>Detections</th></tr>\n'
        for tech, count in mitre_counts.items():
            tactic = df[df.MITRE_Technique == tech].MITRE_Tactic.iloc[0]
            html += f'<tr><td>{tech}</td><td>{tactic}</td><td>{count}</td></tr>\n'
        html += '</table>\n'

    # ── FOOTER ──
    html += f"""
<div class="footer">
  SENTINEL v1.0 — Self-Evolving Neural Threat Intelligence Engine<br>
  Forensic Analysis of Unauthorized Access Using Authentication Logs<br>
  Report generated: {now} &nbsp;|&nbsp; Classification: CONFIDENTIAL
</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def generate_csv_report(df: pd.DataFrame, severity_scores: dict,
                        log_file: str, output_path: str = None) -> str:
    """Export enriched DataFrame with scores as CSV."""
    if output_path is None:
        base = os.path.dirname(log_file) if log_file else "."
        output_path = os.path.join(base, "SENTINEL_report.csv")

    export = df.copy()
    # Add severity info
    score_map = {ip: d["score"] for ip, d in severity_scores.items()}
    level_map = {ip: d["level"] for ip, d in severity_scores.items()}
    export["Risk_Score"] = export.IP_Address.map(score_map).fillna(0)
    export["Severity_Level"] = export.IP_Address.map(level_map).fillna("LOW")

    if "Parsed_Time" in export.columns:
        export["Parsed_Time"] = export["Parsed_Time"].astype(str)

    export.to_csv(output_path, index=False)
    return output_path
