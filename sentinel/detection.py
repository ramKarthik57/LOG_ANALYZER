"""
SENTINEL — Detection Engine
=============================
Adaptive threshold brute-force detection, night-login analysis,
credential-stuffing detection, and user-spray detection.
"""

import numpy as np
import pandas as pd
from scipy import stats as sp_stats


class AdaptiveDetector:
    """
    Self-calibrating threat detection engine.
    Thresholds learn from baseline log statistics rather than hardcoded values.
    """

    def __init__(self, night_end: int = 5, z_score: float = 2.5):
        self.night_end = night_end
        self.z_score = z_score
        self._baseline_mu = None
        self._baseline_sigma = None

    def _compute_baseline(self, df: pd.DataFrame):
        """Compute baseline failed-login rate per IP."""
        failed = df[df.Event == "FAILED_LOGIN"]
        if failed.empty:
            self._baseline_mu = 3.0
            self._baseline_sigma = 1.5
            return
        per_ip = failed.groupby("IP_Address").size()
        self._baseline_mu = per_ip.mean()
        self._baseline_sigma = max(per_ip.std(), 1.0)

    def get_adaptive_threshold(self, df: pd.DataFrame) -> float:
        """Calculate adaptive brute-force threshold."""
        if self._baseline_mu is None:
            self._compute_baseline(df)
        threshold = self._baseline_mu + self.z_score * self._baseline_sigma
        return max(threshold, 3.0)  # floor at 3

    def detect_bruteforce(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect brute-force attempts using adaptive thresholds.
        Returns DataFrame: IP_Address, Failed_Count, Threshold, Confidence, Is_Bruteforce
        """
        self._compute_baseline(df)
        threshold = self.get_adaptive_threshold(df)

        failed = df[df.Event == "FAILED_LOGIN"]
        per_ip = failed.groupby("IP_Address").size().reset_index(name="Failed_Count")

        per_ip["Threshold"] = round(threshold, 1)
        per_ip["Is_Bruteforce"] = per_ip.Failed_Count >= threshold

        # Confidence: how many standard deviations above mean
        per_ip["Confidence"] = per_ip.Failed_Count.apply(
            lambda x: round(min(
                1.0 - sp_stats.norm.sf(x, self._baseline_mu, self._baseline_sigma),
                0.999
            ), 3) if self._baseline_sigma > 0 else 0.5
        )

        return per_ip

    def detect_night_logins(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect successful logins during suspicious hours."""
        mask = (
            (df.Event == "SUCCESSFUL_LOGIN") &
            (df.Parsed_Time.dt.hour < self.night_end)
        )
        return df[mask].copy()

    def detect_credential_stuffing(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect credential stuffing: many unique usernames tried from single IP.
        Returns IPs with high user/attempt ratios.
        """
        failed = df[df.Event == "FAILED_LOGIN"]
        if failed.empty:
            return pd.DataFrame(columns=["IP_Address", "Unique_Users",
                                          "Total_Attempts", "Spray_Ratio"])

        per_ip = failed.groupby("IP_Address").agg(
            Unique_Users=("Username", "nunique"),
            Total_Attempts=("Username", "count"),
        ).reset_index()

        per_ip["Spray_Ratio"] = (
            per_ip.Unique_Users / per_ip.Total_Attempts
        ).round(3)

        # High spray ratio = credential stuffing (many users, few attempts each)
        per_ip["Is_Stuffing"] = (per_ip.Spray_Ratio > 0.5) & (per_ip.Unique_Users > 2)

        return per_ip

    def detect_compromise_pattern(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect failed-then-succeed pattern: strong indicator of actual compromise.
        """
        results = []
        threshold = self.get_adaptive_threshold(df)

        for ip in df.IP_Address.unique():
            ip_df = df[df.IP_Address == ip].sort_values("Parsed_Time")
            fails = len(ip_df[ip_df.Event == "FAILED_LOGIN"])
            successes = len(ip_df[ip_df.Event == "SUCCESSFUL_LOGIN"])

            if fails >= threshold and successes > 0:
                # Check temporal ordering: fails before success
                first_fail = ip_df[ip_df.Event == "FAILED_LOGIN"].iloc[0].Parsed_Time
                last_success = ip_df[ip_df.Event == "SUCCESSFUL_LOGIN"].iloc[-1].Parsed_Time

                if first_fail < last_success:
                    results.append({
                        "IP_Address": ip,
                        "Failed_Count": fails,
                        "Success_Count": successes,
                        "First_Fail": first_fail,
                        "Last_Success": last_success,
                        "Pattern": "FAILED → SUCCESS (Compromise Likely)"
                    })

        return pd.DataFrame(results)

    def detect_lateral_movement(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect IPs accessing multiple hosts (potential lateral movement)."""
        if "Host" not in df.columns:
            return pd.DataFrame()

        per_ip = df.groupby("IP_Address").agg(
            Hosts_Accessed=("Host", "nunique"),
            Total_Events=("Event", "count"),
        ).reset_index()

        per_ip["Is_Lateral"] = per_ip.Hosts_Accessed > 1
        return per_ip[per_ip.Is_Lateral]
