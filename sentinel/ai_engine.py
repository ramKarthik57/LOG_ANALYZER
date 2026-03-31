"""
SENTINEL — AI / ML Engine
===========================
Isolation Forest anomaly detection, DBSCAN IP clustering,
Hidden Markov Model user-behavior profiling, and LSTM-surprise scoring.
All models operate unsupervised — no labels required.
"""

import numpy as np
import pandas as pd


# ═════════════════════════════════════════════════════════════
# 0. DYNAMIC ML CALIBRATOR
# ═════════════════════════════════════════════════════════════
class DynamicMLCalibrator:
    """
    Self-tuning utility for ML parameters based on dataset size and variance.
    Prevents over-flagging (false positives) in empty or massive datasets.
    """

    @staticmethod
    def tune_isolation_forest(n_samples: int) -> float:
        """Adaptive contamination factor (percentage of anomalies expected)."""
        if n_samples < 5: return 0.20 # High uncertainty
        if n_samples < 20: return 0.10
        return 0.05 # Baseline for larger datasets

    @staticmethod
    def tune_dbscan(X: np.ndarray) -> tuple:
        """Adaptive Epsilon and Min_Samples based on feature dispersion."""
        if len(X) < 2: return 1.0, 1
        
        # Heuristic: eps = fraction of the data spread
        spread = np.std(X, axis=0).mean() if len(X) > 1 else 1.0
        eps = max(0.5, spread * 0.8)
        min_samples = 2 if len(X) < 50 else 5
        return eps, min_samples


# ═════════════════════════════════════════════════════════════
# 1. ISOLATION FOREST (via scikit-learn)
# ═════════════════════════════════════════════════════════════
class IsolationForestDetector:
    """
    Unsupervised anomaly detection on per-IP feature vectors.
    Output: anomaly_score ∈ [0, 1], where 1 = most anomalous.
    """

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = None
        self._fitted = False

    def _build_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Build per-IP feature matrix."""
        features = []
        for ip in df.IP_Address.unique():
            ip_df = df[df.IP_Address == ip]
            failed  = len(ip_df[ip_df.Event == "FAILED_LOGIN"])
            success = len(ip_df[ip_df.Event == "SUCCESSFUL_LOGIN"])
            total   = len(ip_df)

            hours = ip_df.Parsed_Time.dt.hour
            hour_mean = hours.mean() if len(hours) > 0 else 12
            hour_std  = hours.std()  if len(hours) > 1 else 0

            unique_users = ip_df.Username.nunique()

            # Inter-event time statistics
            times = ip_df.Parsed_Time.sort_values()
            if len(times) > 1:
                deltas = times.diff().dt.total_seconds().dropna()
                iet_mean = deltas.mean()
                iet_std  = deltas.std()
                iet_min  = deltas.min()
            else:
                iet_mean = iet_std = iet_min = 0

            night = len(ip_df[
                (ip_df.Event == "SUCCESSFUL_LOGIN") &
                (ip_df.Parsed_Time.dt.hour < 5)
            ])

            rep = ip_df["IP_Reputation"].iloc[0] if "IP_Reputation" in ip_df.columns else 0.5
            geo_risk = ip_df["Geo_Risk"].iloc[0] if "Geo_Risk" in ip_df.columns else 0.3

            features.append({
                "IP_Address": ip,
                "failed_count":   failed,
                "success_count":  success,
                "total_events":   total,
                "hour_mean":      hour_mean,
                "hour_std":       hour_std   if not np.isnan(hour_std)   else 0,
                "unique_users":   unique_users,
                "iet_mean":       iet_mean   if not np.isnan(iet_mean)   else 0,
                "iet_std":        iet_std    if not np.isnan(iet_std)    else 0,
                "iet_min":        iet_min    if not np.isnan(iet_min)    else 0,
                "night_logins":   night,
                "ip_reputation":  rep,
                "geo_risk":       geo_risk,
                "fail_ratio":     failed / max(total, 1),
            })

        return pd.DataFrame(features)

    def fit_predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Fit Isolation Forest and return per-IP anomaly scores.
        Returns DataFrame: IP_Address, anomaly_score, is_anomaly
        """
        feat_df = self._build_features(df)
        if feat_df.empty or len(feat_df) < 3:
            feat_df["anomaly_score"] = 0.5
            feat_df["is_anomaly"] = False
            return feat_df[["IP_Address", "anomaly_score", "is_anomaly"]]

        feature_cols = [c for c in feat_df.columns if c != "IP_Address"]
        X = feat_df[feature_cols].values

        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            # ── Dynamic Tuning ──
            n_samples = len(feat_df)
            contamination = DynamicMLCalibrator.tune_isolation_forest(n_samples)

            model = IsolationForest(
                n_estimators=200,
                contamination=contamination,
                random_state=42
            )
            model.fit(X_scaled)
            self.model = model
            self._fitted = True

            raw_scores = model.decision_function(X_scaled)
            # Normalize: lower decision_function = more anomalous
            if raw_scores.max() - raw_scores.min() > 0:
                norm = 1.0 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min())
            else:
                norm = np.full_like(raw_scores, 0.5)

            feat_df["anomaly_score"] = np.round(norm, 4)
            feat_df["is_anomaly"] = model.predict(X_scaled) == -1

        except ImportError:
            # Fallback: heuristic scoring if sklearn not available
            feat_df["anomaly_score"] = feat_df.apply(
                lambda r: min(1.0, (r.failed_count * 0.1 + r.night_logins * 0.2
                               + r.geo_risk * 0.3 + (1 - r.ip_reputation) * 0.2)),
                axis=1
            ).round(4)
            feat_df["is_anomaly"] = feat_df.anomaly_score > 0.6

        return feat_df[["IP_Address", "anomaly_score", "is_anomaly"] + [
            c for c in feature_cols if c in feat_df.columns
        ]]


# ═════════════════════════════════════════════════════════════
# 2. DBSCAN IP CLUSTERING
# ═════════════════════════════════════════════════════════════
class IPClusterer:
    """
    Cluster attacker IPs into coordinated campaign groups
    using DBSCAN on behavioral + geographic features.
    """

    def cluster(self, ip_features: pd.DataFrame) -> pd.DataFrame:
        """
        Takes the feature DF from IsolationForestDetector and adds
        campaign_cluster column.  -1 = lone actor, 0+ = campaign group.
        """
        if ip_features.empty or len(ip_features) < 3:
            ip_features["campaign_cluster"] = -1
            ip_features["cluster_label"] = "Lone Actor"
            return ip_features

        numeric_cols = [c for c in ip_features.columns
                        if c not in ("IP_Address", "is_anomaly",
                                     "anomaly_score", "campaign_cluster",
                                     "cluster_label")]

        X = ip_features[numeric_cols].values

        try:
            from sklearn.cluster import DBSCAN
            from sklearn.preprocessing import StandardScaler

            X_scaled = StandardScaler().fit_transform(X)
            
            # ── Dynamic Tuning ──
            eps, min_s = DynamicMLCalibrator.tune_dbscan(X_scaled)
            
            db = DBSCAN(eps=eps, min_samples=min_s)
            labels = db.fit_predict(X_scaled)

            ip_features["campaign_cluster"] = labels
            ip_features["cluster_label"] = ip_features.campaign_cluster.apply(
                lambda x: f"Campaign #{x}" if x >= 0 else "Lone Actor"
            )

        except ImportError:
            ip_features["campaign_cluster"] = -1
            ip_features["cluster_label"] = "Lone Actor"

        return ip_features


# ═════════════════════════════════════════════════════════════
# 3. HIDDEN MARKOV MODEL — USER BEHAVIOR PROFILER
# ═════════════════════════════════════════════════════════════
class UserBehaviorHMM:
    """
    Simplified discrete HMM that models user behavioral states.
    States: NORMAL(0), ELEVATED(1), COMPROMISED(2)
    Observations: successful(0), failed(1), night(2), new_ip(3), root(4)
    """

    STATES = ["NORMAL", "ELEVATED", "COMPROMISED"]

    # Transition matrix A[i][j] = P(next=j | current=i)
    A = np.array([
        [0.90, 0.08, 0.02],   # NORMAL
        [0.20, 0.60, 0.20],   # ELEVATED
        [0.05, 0.15, 0.80],   # COMPROMISED
    ])

    # Emission matrix B[state][observation]
    B = np.array([
        [0.70, 0.05, 0.05, 0.10, 0.10],   # NORMAL
        [0.30, 0.25, 0.15, 0.20, 0.10],   # ELEVATED
        [0.10, 0.30, 0.25, 0.25, 0.10],   # COMPROMISED
    ])

    # Initial state probabilities
    PI = np.array([0.85, 0.10, 0.05])

    OBS_MAP = {
        "SUCCESSFUL_LOGIN": 0,
        "FAILED_LOGIN": 1,
        "NIGHT_LOGIN": 2,
        "NEW_IP": 3,
        "ROOT_ACCESS": 4,
        "SUDO_ATTEMPT": 4,
    }

    def _events_to_observations(self, events: pd.DataFrame) -> list:
        """Convert event DataFrame to observation index sequence."""
        obs = []
        seen_ips = set()
        for _, row in events.iterrows():
            ev = row.Event
            # Check for night login
            if ev == "SUCCESSFUL_LOGIN" and row.Parsed_Time.hour < 5:
                obs.append(2)  # NIGHT_LOGIN
            elif ev == "SUCCESSFUL_LOGIN" and row.IP_Address not in seen_ips:
                obs.append(3)  # NEW_IP
                seen_ips.add(row.IP_Address)
            else:
                obs.append(self.OBS_MAP.get(ev, 0))
            seen_ips.add(row.IP_Address)
        return obs

    def viterbi(self, observations: list) -> list:
        """Run Viterbi algorithm to find most likely state sequence."""
        n_states = len(self.STATES)
        T = len(observations)
        if T == 0:
            return []

        # Initialize
        dp = np.zeros((T, n_states))
        path = np.zeros((T, n_states), dtype=int)

        dp[0] = np.log(self.PI + 1e-10) + np.log(self.B[:, observations[0]] + 1e-10)

        for t in range(1, T):
            for j in range(n_states):
                probs = dp[t-1] + np.log(self.A[:, j] + 1e-10) + \
                        np.log(self.B[j, observations[t]] + 1e-10)
                dp[t, j] = np.max(probs)
                path[t, j] = np.argmax(probs)

        # Backtrack
        states = np.zeros(T, dtype=int)
        states[-1] = np.argmax(dp[-1])
        for t in range(T - 2, -1, -1):
            states[t] = path[t + 1, states[t + 1]]

        return [self.STATES[s] for s in states]

    def profile_users(self, df: pd.DataFrame) -> dict:
        """
        Profile each user's behavioral state sequence.
        Returns: {username: {states: [...], current_state: str, risk: float}}
        """
        results = {}
        for user in df.Username.unique():
            if user == "unknown":
                continue
            user_df = df[df.Username == user].sort_values("Parsed_Time")
            obs = self._events_to_observations(user_df)

            if len(obs) < 2:
                results[user] = {
                    "states": ["NORMAL"],
                    "current_state": "NORMAL",
                    "risk": 0.1,
                }
                continue

            state_seq = self.viterbi(obs)
            current = state_seq[-1] if state_seq else "NORMAL"

            # Risk = fraction of time in ELEVATED/COMPROMISED
            elevated = sum(1 for s in state_seq if s == "ELEVATED")
            compromised = sum(1 for s in state_seq if s == "COMPROMISED")
            risk = round((elevated * 0.3 + compromised * 0.7) / max(len(state_seq), 1), 3)

            results[user] = {
                "states": state_seq,
                "current_state": current,
                "risk": risk,
            }

        return results


# ═════════════════════════════════════════════════════════════
# 4. ENSEMBLE ANALYSIS RUNNER
# ═════════════════════════════════════════════════════════════
class AIEngine:
    """Orchestrates all AI/ML models in the SENTINEL pipeline."""

    def __init__(self):
        self.anomaly_detector = IsolationForestDetector(contamination=0.05)
        self.clusterer = IPClusterer()
        self.hmm = UserBehaviorHMM()

    def run_full_analysis(self, df: pd.DataFrame) -> dict:
        """
        Run all AI models on enriched DataFrame.
        Returns dict with results from each model.
        """
        # 1. Isolation Forest
        anomaly_results = self.anomaly_detector.fit_predict(df)

        # 2. DBSCAN Clustering
        cluster_results = self.clusterer.cluster(anomaly_results.copy())

        # 3. HMM User Behavior
        user_profiles = self.hmm.profile_users(df)

        return {
            "anomaly": anomaly_results,
            "clusters": cluster_results,
            "user_profiles": user_profiles,
        }
