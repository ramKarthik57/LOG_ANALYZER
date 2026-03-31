"""
SENTINEL — Forensic Analysis Engine
=====================================
Attack chain DAG reconstruction, entropy-based log tampering detection,
session linking, and insider threat detection.
"""

import numpy as np
import pandas as pd
from collections import defaultdict
import networkx as nx
import random


# ═════════════════════════════════════════════════════════════
# 1. ATTACK CHAIN DAG RECONSTRUCTION
# ═════════════════════════════════════════════════════════════
# MITRE ATT&CK kill-chain phase mapping
PHASE_MAP = {
    "FAILED_LOGIN":      "RECONNAISSANCE",
    "INVALID_USER":      "RECONNAISSANCE",
    "SUCCESSFUL_LOGIN":  "INITIAL_ACCESS",
    "ROOT_ACCESS":       "PRIVILEGE_ESCALATION",
    "SUDO_ATTEMPT":      "PRIVILEGE_ESCALATION",
    "DISCONNECT":        "DEFENSE_EVASION",
    "OTHER":             "EXECUTION",
}

# Causal ordering of kill-chain phases
PHASE_ORDER = {
    "RECONNAISSANCE": 0,
    "INITIAL_ACCESS": 1,
    "EXECUTION": 2,
    "PERSISTENCE": 3,
    "PRIVILEGE_ESCALATION": 4,
    "DEFENSE_EVASION": 5,
    "LATERAL_MOVEMENT": 6,
}

# Valid causal transitions
CAUSAL_RULES = {
    "RECONNAISSANCE":       ["INITIAL_ACCESS"],
    "INITIAL_ACCESS":       ["EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION"],
    "EXECUTION":            ["PERSISTENCE", "PRIVILEGE_ESCALATION"],
    "PERSISTENCE":          ["PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT"],
    "PRIVILEGE_ESCALATION": ["DEFENSE_EVASION", "LATERAL_MOVEMENT"],
    "DEFENSE_EVASION":      ["LATERAL_MOVEMENT"],
}


def build_attack_chain(df: pd.DataFrame, ip: str) -> dict:
    """
    Build a DAG-based attack chain for a specific IP.
    
    Returns:
        {
            "ip": str,
            "nodes": [{"id": int, "phase": str, "event": str, "time": str, "details": str}],
            "edges": [(from_id, to_id)],
            "phases_reached": [str],
            "kill_chain_progress": float  # 0.0 – 1.0
        }
    """
    ip_df = df[df.IP_Address == ip].sort_values("Parsed_Time")
    if ip_df.empty:
        return {"ip": ip, "nodes": [], "edges": [], "phases_reached": [],
                "kill_chain_progress": 0.0}

    nodes = []
    for i, (_, row) in enumerate(ip_df.iterrows()):
        phase = PHASE_MAP.get(row.Event, "EXECUTION")

        # Check for night login → PERSISTENCE
        if row.Event == "SUCCESSFUL_LOGIN" and row.Parsed_Time.hour < 5:
            phase = "PERSISTENCE"

        nodes.append({
            "id": i,
            "phase": phase,
            "event": row.Event,
            "time": str(row.Parsed_Time),
            "details": row.Message[:80],
            "username": row.get("Username", "unknown"),
        })

    # Build edges based on causal rules
    edges = []
    for i, src in enumerate(nodes):
        valid_targets = CAUSAL_RULES.get(src["phase"], [])
        for j, dst in enumerate(nodes):
            if j <= i:
                continue
            if dst["phase"] in valid_targets:
                edges.append((src["id"], dst["id"]))
                break  # first valid next phase only (avoid transitive)

    # Compute kill-chain progress
    phases_reached = list(set(n["phase"] for n in nodes))
    max_phase = max(PHASE_ORDER.get(p, 0) for p in phases_reached) if phases_reached else 0
    progress = max_phase / max(len(PHASE_ORDER) - 1, 1)

    return {
        "ip": ip,
        "nodes": nodes,
        "edges": edges,
        "phases_reached": phases_reached,
        "kill_chain_progress": round(progress, 3),
    }


def build_all_attack_chains(df: pd.DataFrame,
                            severity_map: dict = None) -> list:
    """
    Build attack chains for all HIGH/CRITICAL IPs.
    severity_map: {ip: severity_level_str}
    """
    chains = []
    target_ips = df.IP_Address.unique()

    if severity_map:
        target_ips = [ip for ip in target_ips
                      if severity_map.get(ip, "LOW") in ("HIGH", "CRITICAL")]

    for ip in target_ips:
        chain = build_attack_chain(df, ip)
        if chain["nodes"]:
            chains.append(chain)

    return chains


# ═════════════════════════════════════════════════════════════
# 2. ENTROPY-BASED LOG TAMPERING DETECTION
# ═════════════════════════════════════════════════════════════
def _shannon_entropy(values: np.ndarray, n_bins: int = 20) -> float:
    """Compute Shannon entropy of a value distribution."""
    if len(values) < 2:
        return 0.0
    hist, _ = np.histogram(values, bins=n_bins, density=True)
    hist = hist[hist > 0]  # remove zeros
    hist = hist / hist.sum()  # normalize to probabilities
    return -np.sum(hist * np.log2(hist + 1e-12))


def detect_log_tampering(df: pd.DataFrame,
                         window_size: int = 50,
                         stride: int = 10,
                         z_threshold: float = 2.0) -> dict:
    """
    Detect log tampering using Shannon entropy of inter-event time deltas.
    
    Returns:
        {
            "tampered": bool,
            "tamper_regions": [(start_idx, end_idx, entropy, z_score)],
            "baseline_entropy": float,
            "entropy_series": [(window_center, entropy)],
        }
    """
    if len(df) < window_size * 2:
        return {"tampered": False, "tamper_regions": [],
                "baseline_entropy": 0.0, "entropy_series": []}

    times = df["Parsed_Time"].sort_values()
    deltas = times.diff().dt.total_seconds().dropna().values

    if len(deltas) < window_size:
        return {"tampered": False, "tamper_regions": [],
                "baseline_entropy": 0.0, "entropy_series": []}

    # Compute sliding-window entropy
    entropies = []
    centers = []
    for start in range(0, len(deltas) - window_size, stride):
        window = deltas[start:start + window_size]
        h = _shannon_entropy(window)
        entropies.append(h)
        centers.append(start + window_size // 2)

    entropies = np.array(entropies)
    baseline = np.mean(entropies)
    std = np.std(entropies)

    # Flag regions where entropy deviates significantly
    tamper_regions = []
    for i, (center, h) in enumerate(zip(centers, entropies)):
        if std > 0:
            z = abs(h - baseline) / std
        else:
            z = 0.0
        if z > z_threshold:
            tamper_regions.append((
                max(0, center - window_size // 2),
                min(len(df), center + window_size // 2),
                round(h, 4),
                round(z, 2),
            ))

    return {
        "tampered": len(tamper_regions) > 0,
        "tamper_regions": tamper_regions,
        "baseline_entropy": round(baseline, 4),
        "entropy_series": list(zip(centers, [round(h, 4) for h in entropies])),
    }


# ═════════════════════════════════════════════════════════════
# 3. SESSION LINKER
# ═════════════════════════════════════════════════════════════
def link_sessions(df: pd.DataFrame, timeout_minutes: int = 30) -> pd.DataFrame:
    """
    Link events into logical sessions per IP.
    A new session starts after `timeout_minutes` of inactivity.
    """
    df = df.sort_values("Parsed_Time").copy()
    session_ids = []
    sessions = {}  # ip -> (current_session_id, last_time)
    counter = 0

    for _, row in df.iterrows():
        ip = row.IP_Address
        time = row.Parsed_Time

        if ip in sessions:
            sid, last_time = sessions[ip]
            gap = (time - last_time).total_seconds() / 60
            if gap > timeout_minutes:
                counter += 1
                sid = f"S-{counter:04d}"
            sessions[ip] = (sid, time)
        else:
            counter += 1
            sid = f"S-{counter:04d}"
            sessions[ip] = (sid, time)

        session_ids.append(sid)

    df["Session_ID"] = session_ids
    return df


# ═════════════════════════════════════════════════════════════
# 4. INSIDER THREAT DETECTION
# ═════════════════════════════════════════════════════════════
def detect_insider_threats(df: pd.DataFrame,
                           user_profiles: dict) -> list:
    """
    Detect potential insider threats based on user behavior anomalies.
    
    Indicators:
    - User in COMPROMISED state for prolonged periods
    - Successful logins from unusual IPs
    - Activity during off-hours
    - Privilege escalation attempts
    """
    threats = []

    for user, profile in user_profiles.items():
        risk = profile.get("risk", 0)
        current = profile.get("current_state", "NORMAL")

        user_df = df[df.Username == user]
        if user_df.empty:
            continue

        indicators = []

        # Check behavioral state
        if current == "COMPROMISED":
            indicators.append("HMM state: COMPROMISED")
        elif current == "ELEVATED":
            indicators.append("HMM state: ELEVATED")

        # Night activity
        night = user_df[
            (user_df.Event == "SUCCESSFUL_LOGIN") &
            (user_df.Parsed_Time.dt.hour < 5)
        ]
        if not night.empty:
            indicators.append(f"{len(night)} night logins detected")

        # Multiple IPs
        unique_ips = user_df.IP_Address.nunique()
        if unique_ips > 3:
            indicators.append(f"Accessed from {unique_ips} different IPs")

        # Privilege escalation
        priv = user_df[user_df.Event.isin(["ROOT_ACCESS", "SUDO_ATTEMPT"])]
        if not priv.empty:
            indicators.append(f"{len(priv)} privilege escalation attempts")

        if len(indicators) >= 2 or risk > 0.3:
            threats.append({
                "username": user,
                "risk_score": risk,
                "current_state": current,
                "indicators": indicators,
                "event_count": len(user_df),
            })

    return sorted(threats, key=lambda t: t["risk_score"], reverse=True)


# ═════════════════════════════════════════════════════════════
# 5. GRAPH-BASED LATERAL MOVEMENT DETECTION
# ═════════════════════════════════════════════════════════════
class GraphForensics:
    """
    Analyzes authentication logs as a Graph to detect Lateral Movement.
    Nodes: IPs, Users, Hosts. Edges: successful logins.
    """

    def analyze_lateral_movement(self, df: pd.DataFrame) -> list:
        """Find high-risk edges that indicate host-to-host pivoting."""
        G = nx.Graph()
        success = df[df.Event == "SUCCESSFUL_LOGIN"]
        
        for _, row in success.iterrows():
            u, ip, h = row.Username, row.IP_Address, row.get("Host", "UnkHost")
            G.add_edge(ip, h, user=u)

        pivot_points = []
        try:
            # IPs connected to multiple hosts are potential pivot points
            for node in G.nodes():
                if "." in str(node): # It's an IP
                    neighbors = list(G.neighbors(node))
                    if len(neighbors) > 1:
                        pivot_points.append({
                            "ip": node,
                            "hosts_involved": neighbors,
                            "risk": "HIGH"
                        })
        except Exception: pass
        return pivot_points


# ═════════════════════════════════════════════════════════════
# 6. AGENTIC FORENSIC NARRATOR (Copilot Narrative)
# ═════════════════════════════════════════════════════════════
class ForensicNarrator:
    """
    Generates natural language 'Forensic Narratives' from technical ML outputs.
    Simulates an Agentic AI forensic analyst (Copilot).
    """

    TEMPLATES = [
        "The actor at {ip} initiated a coordinated {technique} campaign.",
        "Detected lateral movement: {ip} breached {hosts} using compromised credentials.",
        "Behavioral sequence for {user} shows a transition from {start_state} to {end_state}.",
        "Risk scores spiked due to {factor} reaching critical thresholds.",
    ]

    def generate_narrative(self, ip_data: dict, chain: dict) -> str:
        """Synthesize a human-readable summary of the attack."""
        ip = ip_data.get("ip", "Unknown")
        level = ip_data.get("level", "LOW")
        score = ip_data.get("score", 0)
        
        phases = chain.get("phases_reached", [])
        top_phase = chain.get("kill_chain_progress", 0) * 100

        summary = f"### [AGENT REPORT] Threat Analysis for {ip}\n\n"
        summary += f"Our neural engine classifies this entity as **{level}** (Confidence: {score}%).\n"
        
        if "PRIVILEGE_ESCALATION" in phases:
            summary += f"- **Critical Alert**: The attacker successfully escalated privileges after initial access.\n"
        elif "INITIAL_ACCESS" in phases:
            summary += f"- **Warning**: Initial access was achieved. Monitoring for lateral movement.\n"
        
        summary += f"- **Kill Chain Progress**: Entity has completed {top_phase:.0f}% of a standard attack cycle.\n"
        
        # Add a "recommendation"
        if score > 40:
             summary += "\n**RECO: [AUTONOMOUS]** Pulsing block to firewall. Isolate affected subnets."
        else:
             summary += "\n**RECO:** Continue passive observation. Flag for manual triage."

        return summary
