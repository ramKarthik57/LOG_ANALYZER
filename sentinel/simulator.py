"""
SENTINEL — Attack Simulation Engine
=====================================
Generates synthetic auth.log entries with configurable attack patterns
for testing and demonstrating detection capabilities.
"""

import random
import os
from datetime import datetime, timedelta


# ── Realistic syslog names / IPs ─────────────────────────────
_USERNAMES = [
    "root", "admin", "user", "test", "deploy", "ubuntu",
    "jenkins", "postgres", "mysql", "www-data", "ftpuser",
    "oracle", "nagios", "backup", "git",
]

_ATTACKER_IPS = [
    "185.220.101.34", "45.33.32.156", "103.91.64.22",
    "91.240.118.172", "186.233.186.4", "112.85.42.87",
    "193.35.18.33", "62.210.105.116", "218.92.0.190",
    "141.98.10.37",
]

_INTERNAL_IPS = [
    "10.0.0.5", "10.0.0.12", "192.168.1.101",
    "192.168.1.55", "10.0.1.200",
]

_HOSTS = ["server01", "web-prod", "db-primary", "auth-gateway"]
_PROCESSES = ["sshd", "sshd", "sshd", "login", "sudo"]

# ── Deception Technology (Honey-tokens) ──────────────────────
HONEY_USERS = ["admin_backup", "db_service_acct", "svc_forensics"]


def _syslog_timestamp(dt: datetime) -> str:
    """Format datetime as syslog timestamp (e.g. 'Jan  5 03:22:14')."""
    return dt.strftime("%b %d %H:%M:%S").replace("  ", " ")


def _gen_failed(dt: datetime, ip: str, user: str, host: str) -> str:
    pid = random.randint(1000, 65000)
    return (f"{_syslog_timestamp(dt)} {host} sshd[{pid}]: "
            f"Failed password for {user} from {ip} port "
            f"{random.randint(30000, 65000)} ssh2")


def _gen_success(dt: datetime, ip: str, user: str, host: str) -> str:
    pid = random.randint(1000, 65000)
    return (f"{_syslog_timestamp(dt)} {host} sshd[{pid}]: "
            f"Accepted password for {user} from {ip} port "
            f"{random.randint(30000, 65000)} ssh2")


def _gen_invalid_user(dt: datetime, ip: str, user: str, host: str) -> str:
    pid = random.randint(1000, 65000)
    return (f"{_syslog_timestamp(dt)} {host} sshd[{pid}]: "
            f"Invalid user {user} from {ip} port "
            f"{random.randint(30000, 65000)}")


def _gen_disconnect(dt: datetime, ip: str, host: str) -> str:
    pid = random.randint(1000, 65000)
    return (f"{_syslog_timestamp(dt)} {host} sshd[{pid}]: "
            f"Disconnected from {ip} port {random.randint(30000, 65000)}")


def _gen_sudo(dt: datetime, user: str, host: str) -> str:
    return (f"{_syslog_timestamp(dt)} {host} sudo: "
            f"{user} : TTY=pts/0 ; PWD=/home/{user} ; "
            f"USER=root ; COMMAND=/bin/bash")


def _gen_session_open(dt: datetime, user: str, host: str) -> str:
    pid = random.randint(1000, 65000)
    return (f"{_syslog_timestamp(dt)} {host} sshd[{pid}]: "
            f"pam_unix(sshd:session): session opened for user {user}")


# ═════════════════════════════════════════════════════════════
# ATTACK PATTERN GENERATORS
# ═════════════════════════════════════════════════════════════

def generate_normal_traffic(start: datetime, duration_hours: int = 24,
                            events_per_hour: int = 5) -> list:
    """Generate realistic normal authentication traffic."""
    lines = []
    current = start

    for _ in range(duration_hours):
        n_events = random.randint(max(1, events_per_hour - 2),
                                  events_per_hour + 3)
        for _ in range(n_events):
            dt = current + timedelta(seconds=random.randint(0, 3599))
            ip = random.choice(_INTERNAL_IPS)
            user = random.choice(["admin", "deploy", "ubuntu", "user"])
            host = random.choice(_HOSTS)

            r = random.random()
            if r < 0.85:
                lines.append(_gen_success(dt, ip, user, host))
            elif r < 0.95:
                lines.append(_gen_failed(dt, ip, user, host))
            else:
                lines.append(_gen_session_open(dt, user, host))

        current += timedelta(hours=1)

    return lines


def generate_bruteforce_attack(start: datetime, attacker_ip: str = None,
                               attempts: int = 50,
                               duration_minutes: int = 10,
                               success_at_end: bool = True) -> list:
    """Generate a brute-force attack: many failed then optional success."""
    lines = []
    ip = attacker_ip or random.choice(_ATTACKER_IPS)
    host = random.choice(_HOSTS)
    target_user = random.choice(["root", "admin", "ubuntu"])

    interval = (duration_minutes * 60) / max(attempts, 1)

    for i in range(attempts):
        dt = start + timedelta(seconds=i * interval + random.uniform(-2, 2))
        user = random.choice(_USERNAMES) if random.random() < 0.3 else target_user
        lines.append(_gen_failed(dt, ip, user, host))

    if success_at_end:
        dt = start + timedelta(minutes=duration_minutes + 1)
        lines.append(_gen_success(dt, ip, target_user, host))
        dt2 = dt + timedelta(seconds=30)
        lines.append(_gen_sudo(dt2, target_user, host))

    return lines


def generate_credential_stuffing(start: datetime,
                                 n_ips: int = 8,
                                 attempts_per_ip: int = 5) -> list:
    """Generate distributed credential stuffing: many IPs, few attempts each."""
    lines = []
    host = random.choice(_HOSTS)
    target_users = random.sample(_USERNAMES, min(5, len(_USERNAMES)))

    for i in range(n_ips):
        ip = f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        for j in range(attempts_per_ip):
            dt = start + timedelta(seconds=i * 60 + j * 10 + random.randint(-3, 3))
            user = random.choice(target_users)
            lines.append(_gen_failed(dt, ip, user, host))

    return lines


def generate_night_intrusion(start_hour: int = 2,
                             base_date: datetime = None) -> list:
    """Generate a suspicious night-time login pattern."""
    lines = []
    if base_date is None:
        base_date = datetime(2024, 6, 15)

    dt = base_date.replace(hour=start_hour, minute=random.randint(0, 30))
    ip = random.choice(_ATTACKER_IPS)
    host = random.choice(_HOSTS)
    user = "admin"

    lines.append(_gen_success(dt, ip, user, host))
    dt2 = dt + timedelta(minutes=5)
    lines.append(_gen_sudo(dt2, user, host))
    dt3 = dt + timedelta(minutes=20)
    lines.append(_gen_disconnect(dt3, ip, host))

    return lines


def generate_lateral_movement(start: datetime,
                              initial_ip: str = None) -> list:
    """Generate lateral movement: access multiple hosts after initial breach."""
    lines = []
    ip = initial_ip or random.choice(_ATTACKER_IPS)
    user = "admin"

    for i, host in enumerate(_HOSTS):
        dt = start + timedelta(minutes=i * 15)
        lines.append(_gen_success(dt, ip, user, host))
        dt2 = dt + timedelta(minutes=2)
        lines.append(_gen_sudo(dt2, user, host))

    return lines


# ═════════════════════════════════════════════════════════════
# FULL SIMULATION
# ═════════════════════════════════════════════════════════════

def generate_full_simulation(output_path: str = None,
                             year: str = "2024") -> str:
    """
    Generate a complete simulated auth.log file with mixed
    normal traffic and various attack patterns.
    Returns path to the generated file.
    """
    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), "..",
                                   "simulated_auth.log")
    output_path = os.path.abspath(output_path)

    base = datetime(int(year), 6, 15, 0, 0, 0)
    all_lines = []

    # 1. Normal traffic (48 hours)
    all_lines.extend(generate_normal_traffic(base, duration_hours=48,
                                             events_per_hour=8))

    # 2. Brute force attack #1 (day 1, 14:00)
    all_lines.extend(generate_bruteforce_attack(
        base + timedelta(hours=14), attempts=40, success_at_end=True))

    # 3. Brute force attack #2 (day 1, 22:00)
    all_lines.extend(generate_bruteforce_attack(
        base + timedelta(hours=22),
        attacker_ip="91.240.118.172", attempts=25, success_at_end=False))

    # 4. Credential stuffing (day 2, 06:00)
    all_lines.extend(generate_credential_stuffing(
        base + timedelta(hours=30), n_ips=6, attempts_per_ip=4))

    # 5. Night intrusion (day 2, 02:30)
    all_lines.extend(generate_night_intrusion(
        start_hour=2, base_date=base + timedelta(days=1)))

    # 6. Lateral movement (day 2, 10:00)
    all_lines.extend(generate_lateral_movement(
        base + timedelta(hours=34), initial_ip="185.220.101.34"))

    # 7. Deception: Honey-token attempts
    for _ in range(3):
        ip = f"11.22.{random.randint(1,254)}.{random.randint(1,254)}"
        user = random.choice(HONEY_USERS)
        dt = base + timedelta(hours=random.randint(0, 48))
        all_lines.append(_gen_failed(dt, ip, user, random.choice(_HOSTS)))

    # Sort by timestamp order (approximate — from position in line)
    all_lines.sort()

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(all_lines) + "\n")

    return output_path
