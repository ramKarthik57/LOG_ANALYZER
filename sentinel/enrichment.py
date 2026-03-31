"""
SENTINEL — Enrichment Layer
============================
Offline-first enrichment: GeoIP (simulated MaxMind), MITRE ATT&CK mapping,
IP reputation scoring, and ASN resolution.  Uses local lookup tables so the
demo works without any API keys.
"""

import hashlib
import pandas as pd

# ─────────────────────────────────────────────────────────────
# SIMULATED GeoIP DATABASE  (deterministic from IP hash)
# In production, replace with MaxMind GeoLite2 reader.
# ─────────────────────────────────────────────────────────────
_GEO_LOCATIONS = [
    ("United States", "New York",      40.71,  -74.01),
    ("Russia",        "Moscow",        55.75,   37.62),
    ("China",         "Beijing",       39.90,  116.40),
    ("Germany",       "Berlin",        52.52,   13.40),
    ("Brazil",        "São Paulo",    -23.55,  -46.63),
    ("India",         "Mumbai",        19.08,   72.88),
    ("Nigeria",       "Lagos",          6.52,    3.38),
    ("Iran",          "Tehran",        35.69,   51.39),
    ("North Korea",   "Pyongyang",     39.02,  125.75),
    ("Ukraine",       "Kyiv",          50.45,   30.52),
    ("Japan",         "Tokyo",         35.68,  139.69),
    ("South Korea",   "Seoul",         37.57,  126.98),
    ("United Kingdom","London",        51.51,   -0.13),
    ("France",        "Paris",         48.86,    2.35),
    ("Netherlands",   "Amsterdam",     52.37,    4.90),
]

# Country-level cyber threat risk index (0=safe, 1=highest risk)
_COUNTRY_RISK = {
    "Russia": 0.90, "China": 0.85, "North Korea": 0.95, "Iran": 0.88,
    "Nigeria": 0.70, "Brazil": 0.50, "Ukraine": 0.65, "India": 0.35,
    "United States": 0.25, "Germany": 0.15, "Japan": 0.10,
    "United Kingdom": 0.12, "France": 0.14, "Netherlands": 0.20,
    "South Korea": 0.15,
}


def _ip_hash_index(ip: str) -> int:
    """Deterministic hash of IP to index into geo table."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    return h % len(_GEO_LOCATIONS)


def resolve_geoip(ip: str) -> dict:
    """Resolve IP to geo-location (simulated). Returns dict with geo fields."""
    if ip == "Internal" or ip.startswith("127.") or ip.startswith("10."):
        return {
            "geo_country": "Local",  "geo_city": "Internal",
            "geo_lat": 0.0, "geo_lon": 0.0
        }
    idx = _ip_hash_index(ip)
    country, city, lat, lon = _GEO_LOCATIONS[idx]
    return {
        "geo_country": country, "geo_city": city,
        "geo_lat": lat, "geo_lon": lon
    }


def get_country_risk(country: str) -> float:
    """Get cyber threat risk index for a country. 0.0–1.0."""
    return _COUNTRY_RISK.get(country, 0.30)


# ─────────────────────────────────────────────────────────────
# IP REPUTATION  (deterministic from IP hash)
# In production, query AbuseIPDB / OTX AlienVault.
# ─────────────────────────────────────────────────────────────
def compute_ip_reputation(ip: str, failed_count: int = 0,
                          geo_country: str = "") -> float:
    """
    Compute reputation score for an IP.  0.0 = malicious, 1.0 = clean.
    Factors: base hash, failed attempt penalty, country risk.
    """
    if ip == "Internal":
        return 0.95

    h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    base = (h % 100) / 100.0  # 0.0 – 1.0 random baseline

    # Penalize high failure counts
    fail_penalty = min(failed_count * 0.05, 0.4)

    # Country risk factor
    country_risk = get_country_risk(geo_country)
    country_penalty = country_risk * 0.3

    reputation = max(0.0, min(1.0, base - fail_penalty - country_penalty))
    return round(reputation, 3)


# ─────────────────────────────────────────────────────────────
# ASN / WHOIS  (simulated)
# ─────────────────────────────────────────────────────────────
_ASN_TABLE = [
    "AS15169 — Google LLC",
    "AS13335 — Cloudflare Inc",
    "AS16509 — Amazon.com Inc",
    "AS8075  — Microsoft Corp",
    "AS4134  — ChinaNet",
    "AS12389 — Rostelecom",
    "AS9009  — M247 Ltd (VPN)",
    "AS14061 — DigitalOcean LLC",
    "AS20473 — Vultr Holdings",
    "AS36352 — ColoCrossing (bulletproof)",
]


def resolve_asn(ip: str) -> str:
    """Resolve IP to ASN (simulated). Returns ASN string."""
    if ip == "Internal":
        return "AS0 — Internal"
    idx = int(hashlib.sha1(ip.encode()).hexdigest(), 16) % len(_ASN_TABLE)
    return _ASN_TABLE[idx]


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────────────────────
MITRE_MAP = {
    "FAILED_LOGIN": {
        "technique": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts to gain access via systematic password guessing.",
    },
    "SUCCESSFUL_LOGIN": {
        "technique": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversary uses valid credentials to gain access.",
    },
    "ROOT_ACCESS": {
        "technique": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversary escalates privileges to root/admin.",
    },
    "SUDO_ATTEMPT": {
        "technique": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversary uses sudo to execute with elevated privileges.",
    },
    "INVALID_USER": {
        "technique": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversary attempts login with non-existent usernames.",
    },
    "DISCONNECT": {
        "technique": "T1070",
        "technique_name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Session disconnection may indicate cleanup activity.",
    },
    "OTHER": {
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "General system activity.",
    },
}


def map_mitre(event_type: str) -> dict:
    """Map event type to MITRE ATT&CK technique + tactic."""
    return MITRE_MAP.get(event_type, MITRE_MAP["OTHER"])


# ─────────────────────────────────────────────────────────────
# FULL ENRICHMENT PIPELINE
# ─────────────────────────────────────────────────────────────
def enrich_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich a parsed events DataFrame with GeoIP, reputation,
    ASN, and MITRE ATT&CK mappings.
    """
    geo_data = []
    reputations = []
    asns = []
    mitre_techniques = []
    mitre_tactics = []
    geo_risks = []

    # Pre-compute per-IP failure counts for reputation
    fail_counts = df[df.Event == "FAILED_LOGIN"].groupby("IP_Address").size().to_dict()

    for _, row in df.iterrows():
        ip = row["IP_Address"]

        # GeoIP
        geo = resolve_geoip(ip)
        geo_data.append(geo)

        # Reputation
        fc = fail_counts.get(ip, 0)
        rep = compute_ip_reputation(ip, fc, geo["geo_country"])
        reputations.append(rep)

        # ASN
        asns.append(resolve_asn(ip))

        # MITRE
        mitre = map_mitre(row["Event"])
        mitre_techniques.append(f"{mitre['technique']} — {mitre['technique_name']}")
        mitre_tactics.append(mitre["tactic"])

        # Geo risk
        geo_risks.append(get_country_risk(geo["geo_country"]))

    df["Geo_Country"] = [g["geo_country"] for g in geo_data]
    df["Geo_City"]    = [g["geo_city"]    for g in geo_data]
    df["Geo_Lat"]     = [g["geo_lat"]     for g in geo_data]
    df["Geo_Lon"]     = [g["geo_lon"]     for g in geo_data]
    df["IP_Reputation"] = reputations
    df["ASN"]         = asns
    df["MITRE_Technique"] = mitre_techniques
    df["MITRE_Tactic"]    = mitre_tactics
    df["Geo_Risk"]    = geo_risks

    return df
