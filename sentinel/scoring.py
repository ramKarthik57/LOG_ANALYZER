"""
SENTINEL — Multi-Factor Risk Scoring Engine
=============================================
Replaces the hardcoded linear scoring with a weighted
multi-factor model incorporating AI outputs.
"""

import numpy as np
import pandas as pd
from sentinel.simulator import HONEY_USERS


class RiskScoringEngine:
    """
    Multi-factor risk scoring that fuses rule-based heuristics
    with AI model outputs for per-IP severity assessment.
    
    Score = Σ wᵢ · fᵢ(x)
    
    Classification:
        CRITICAL  if score ≥ 40
        HIGH      if score ≥ 25
        MEDIUM    if score ≥ 12
        LOW       otherwise
    """

    # Default factor weights (can be refined by RL in future)
    WEIGHTS = {
        "failed_log":       1.0,
        "compromise":       1.0,
        "night_fraction":   1.0,
        "anomaly":          1.0,
        "reputation":       1.0,
        "geo_risk":         1.0,
        "spray":            1.0,
        "velocity":         1.0,
    }

    THRESHOLDS = {
        "CRITICAL": 40,
        "HIGH":     25,
        "MEDIUM":   12,
    }

    def score_ip(self, ip: str, df: pd.DataFrame,
                 anomaly_score: float = 0.0,
                 ip_reputation: float = 0.5,
                 geo_risk: float = 0.3) -> dict:
        """
        Compute multi-factor risk score for a single IP.
        
        Returns: {
            score, level, factors: {name: (raw, weighted, description)}
        }
        """
        ip_df = df[df.IP_Address == ip]
        total = len(ip_df)
        if total == 0:
            return {"score": 0, "level": "LOW", "factors": {}}

        failed  = len(ip_df[ip_df.Event == "FAILED_LOGIN"])
        success = len(ip_df[ip_df.Event == "SUCCESSFUL_LOGIN"])
        night   = len(ip_df[
            (ip_df.Event == "SUCCESSFUL_LOGIN") &
            (ip_df.Parsed_Time.dt.hour < 5)
        ])

        # Extract unique users targeted
        unique_users = ip_df.Username.nunique()

        # Compute velocity (events per hour)
        if total > 1:
            time_span = (ip_df.Parsed_Time.max() - ip_df.Parsed_Time.min()).total_seconds()
            velocity = total / max(time_span / 3600, 0.01)
        else:
            velocity = 0

        # ── Deception Check ──
        target_users = set(ip_df.Username.unique())
        if any(u in HONEY_USERS for u in target_users):
            return {
                "score": 100.0,
                "level": "CRITICAL",
                "factors": {
                    "DECEPTION TRIGGER": (100.0, 100.0, "Interacted with Honey-Token (Zero False Positive)")
                }
            }

        # ── Factor Functions ──
        w = self.WEIGHTS

        f1 = np.log2(1 + failed) * 5               # Diminishing returns on failed
        f2 = (10 if failed >= 3 and success > 0 else 0)  # Compromise indicator
        f3 = (night / max(success, 1)) * 8          # Night login fraction
        f4 = anomaly_score * 15                     # ML anomaly score
        f5 = (1 - ip_reputation) * 10               # Bad reputation
        f6 = geo_risk * 5                           # Country risk
        f7 = (unique_users / max(total, 1)) * 20    # User spray ratio
        f8 = min(velocity * 2, 10)                  # Login velocity

        factors = {
            "Failed Logins (log₂)":     (round(f1, 2), round(f1 * w["failed_log"], 2),
                                         f"{failed} failed → log₂({1+failed})×5"),
            "Compromise Pattern":       (round(f2, 2), round(f2 * w["compromise"], 2),
                                         f"{'Yes' if f2 > 0 else 'No'} (fail≥3 + success>0)"),
            "Night Login Fraction":     (round(f3, 2), round(f3 * w["night_fraction"], 2),
                                         f"{night}/{max(success,1)} night/success × 8"),
            "AI Anomaly Score":         (round(f4, 2), round(f4 * w["anomaly"], 2),
                                         f"Isolation Forest: {anomaly_score:.3f} × 15"),
            "IP Reputation Penalty":    (round(f5, 2), round(f5 * w["reputation"], 2),
                                         f"(1 - {ip_reputation:.3f}) × 10"),
            "Geo Risk":                 (round(f6, 2), round(f6 * w["geo_risk"], 2),
                                         f"Country risk: {geo_risk:.2f} × 5"),
            "User Spray":              (round(f7, 2), round(f7 * w["spray"], 2),
                                         f"{unique_users} users / {total} events × 20"),
            "Login Velocity":           (round(f8, 2), round(f8 * w["velocity"], 2),
                                         f"{velocity:.1f} events/hr (capped at 10)"),
        }

        total_score = sum(
            raw * self.WEIGHTS[wk]
            for (raw, _, _), wk in zip(
                factors.values(),
                self.WEIGHTS.keys()
            )
        )
        total_score = round(total_score, 2)

        level = (
            "CRITICAL" if total_score >= self.THRESHOLDS["CRITICAL"] else
            "HIGH"     if total_score >= self.THRESHOLDS["HIGH"]     else
            "MEDIUM"   if total_score >= self.THRESHOLDS["MEDIUM"]   else
            "LOW"
        )

        return {
            "score": total_score,
            "level": level,
            "factors": factors,
        }

    def score_all_ips(self, df: pd.DataFrame,
                      anomaly_df: pd.DataFrame = None) -> dict:
        """
        Score all IPs in the DataFrame.
        anomaly_df: Output from IsolationForestDetector with
                    columns [IP_Address, anomaly_score]
        
        Returns: {ip: {score, level, factors}}
        """
        results = {}
        anomaly_map = {}
        if anomaly_df is not None and not anomaly_df.empty:
            anomaly_map = dict(zip(anomaly_df.IP_Address, anomaly_df.anomaly_score))

        for ip in df.IP_Address.unique():
            ip_row = df[df.IP_Address == ip].iloc[0]
            rep = ip_row.get("IP_Reputation", 0.5)
            geo = ip_row.get("Geo_Risk", 0.3)
            anom = anomaly_map.get(ip, 0.0)

            results[ip] = self.score_ip(ip, df, anom, rep, geo)

        return results


def get_severity_summary(scores: dict) -> dict:
    """Summarize severity distribution from scoring results."""
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ip, data in scores.items():
        lv = data["level"]
        levels[lv] = levels.get(lv, 0) + 1
    return levels
