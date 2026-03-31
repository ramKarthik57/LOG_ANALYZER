"""
SENTINEL — Multi-Format Authentication Log Parser
==================================================
Parses auth.log, syslog, wtmp-style, and journald-style logs into
a unified event schema for downstream AI/forensic analysis.
"""

import re
import pandas as pd
from datetime import datetime


# ── Regex patterns for multiple log formats ──────────────────
PATTERNS = {
    "auth_log": re.compile(
        r'([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+?)[\[:\s](.*)'),
    "syslog": re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s(\S+)\s(\S+?)[\[:\s](.*)'),
    "journald": re.compile(
        r'([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+)\[(\d+)\]:\s(.*)'),
}

# ── Event classification rules ───────────────────────────────
EVENT_RULES = [
    (re.compile(r'Failed password',    re.I), "FAILED_LOGIN"),
    (re.compile(r'authentication failure', re.I), "FAILED_LOGIN"),
    (re.compile(r'Accepted password',  re.I), "SUCCESSFUL_LOGIN"),
    (re.compile(r'Accepted publickey', re.I), "SUCCESSFUL_LOGIN"),
    (re.compile(r'session opened.*root', re.I), "ROOT_ACCESS"),
    (re.compile(r'sudo:',             re.I), "SUDO_ATTEMPT"),
    (re.compile(r'Invalid user',      re.I), "INVALID_USER"),
    (re.compile(r'Connection closed',  re.I), "DISCONNECT"),
    (re.compile(r'Disconnected from',  re.I), "DISCONNECT"),
]

IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
USER_RE = re.compile(r'(?:for|user)\s+(\S+?)(?:\s|$)', re.I)


def _classify_event(message: str) -> str:
    """Classify a log message into a structured event type."""
    for pattern, event_type in EVENT_RULES:
        if pattern.search(message):
            return event_type
    return "OTHER"


def _extract_ip(message: str) -> str:
    """Extract IPv4 address from message, fallback to 'Internal'."""
    match = IP_RE.search(message)
    return match.group(0) if match else "Internal"


def _extract_user(message: str) -> str:
    """Extract target username from message."""
    match = USER_RE.search(message)
    return match.group(1) if match else "unknown"


def _detect_format(lines: list) -> str:
    """Auto-detect log format from first 20 lines."""
    sample = lines[:20]
    scores = {fmt: 0 for fmt in PATTERNS}
    for line in sample:
        for fmt, pat in PATTERNS.items():
            if pat.search(line):
                scores[fmt] += 1
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "auth_log"


def parse_log_file(filepath: str, year: str = "2024") -> pd.DataFrame:
    """
    Parse a log file into a unified event DataFrame.
    
    Returns DataFrame with columns:
        Timestamp, Parsed_Time, Event, IP_Address, Username,
        Process, Host, Message, Raw_Line
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    fmt = _detect_format(lines)
    pattern = PATTERNS[fmt]
    rows = []

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        m = pattern.search(line)
        if not m:
            continue

        groups = m.groups()
        timestamp_str = groups[0]
        host = groups[1]
        process = groups[2]
        message = groups[-1]

        # Parse timestamp
        try:
            if fmt == "syslog":
                parsed_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                parsed_time = datetime.strptime(
                    f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S"
                )
        except ValueError:
            continue

        event_type = _classify_event(message)
        ip = _extract_ip(message)
        user = _extract_user(message)

        rows.append({
            "Line_Number": line_num,
            "Timestamp": timestamp_str,
            "Parsed_Time": parsed_time,
            "Event": event_type,
            "IP_Address": ip,
            "Username": user,
            "Process": process,
            "Host": host,
            "Message": message,
            "Raw_Line": line,
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("Parsed_Time").reset_index(drop=True)
    return df
