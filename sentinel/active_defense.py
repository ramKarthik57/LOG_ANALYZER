"""
SENTINEL — Active Defense & SOAR Engine
========================================
Automated IP blocking, account suspension, and honey-token triggering.
This module translates ML-detected risks into operational security actions.
"""

import logging
import time

# Configure logging for SOAR actions
logging.basicConfig(level=logging.INFO, format='[SOAR] %(asctime)s - %(levelname)s - %(message)s')

class SOAREngine:
    """
    Security Orchestration, Automation, and Response (SOAR) Engine.
    Orchestrates automated responses based on IP risk scores.
    """

    def __init__(self, block_threshold: float = 40.0):
        self.block_threshold = block_threshold
        self.blocked_ips = set()
        self.suspended_users = set()
        self.history = []

    def execute_responses(self, scored_ips: dict):
        """Analyze scored IPs and trigger autonomous defenses."""
        for ip, data in scored_ips.items():
            score = data.get("score", 0)
            level = data.get("level", "LOW")

            if score >= self.block_threshold:
                self._action_block_ip(ip, score)
                
                # Check for specific users involved (e.g., successful compromise)
                factors = data.get("factors", {})
                if "Compromise Pattern" in factors and factors["Compromise Pattern"][0] > 0:
                     # Simulate finding the user tied to this IP from events
                     # This is a simplified logic for the SOAR POC
                     self._action_suspend_user("compromised_user", ip)

    def _action_block_ip(self, ip: str, score: float):
        """Simulate a firewall rule update (WAF/IPS)."""
        if ip not in self.blocked_ips:
            logging.warning(f"CRITICAL RISK (Score {score}): Pulsing block signal to Edge WAF for {ip}")
            self.blocked_ips.add(ip)
            self.history.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "IP_BLOCK",
                "target": "WAF / Cloudflare",
                "status": "SUCCESS"
            })

    def _action_suspend_user(self, username: str, ip: str):
        """Simulate an account lockout in Active Directory / LDAP."""
        if username not in self.suspended_users:
            logging.critical(f"ACCOUNT SUSPENDED: Locking {username} due to high-risk activity from {ip}")
            self.suspended_users.add(username)
            self.history.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "user": username,
                "action": "ACCOUNT_LOCKOUT",
                "target": "Active Directory",
                "status": "ENFORCED"
            })

    def get_soar_logs(self):
        """Return history of automated actions for UI display."""
        return self.history
