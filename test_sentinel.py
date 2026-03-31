"""SENTINEL — End-to-End Pipeline Test"""
from sentinel.simulator import generate_full_simulation
from sentinel.parser import parse_log_file
from sentinel.enrichment import enrich_dataframe
from sentinel.detection import AdaptiveDetector
from sentinel.ai_engine import AIEngine
from sentinel.forensics import (build_all_attack_chains, detect_log_tampering,
                                 link_sessions, detect_insider_threats)
from sentinel.scoring import RiskScoringEngine
from sentinel.report import generate_html_report, generate_csv_report

print("=== SENTINEL END-TO-END PIPELINE TEST ===")

# Phase 1: Simulate
path = generate_full_simulation()
print(f"[1/7] Simulated log: {path}")

# Phase 2: Parse
df = parse_log_file(path)
ev_counts = df.Event.value_counts().to_dict()
print(f"[2/7] Parsed: {len(df)} events")
for ev, cnt in ev_counts.items():
    print(f"       {ev}: {cnt}")

# Phase 3: Enrich
df = enrich_dataframe(df)
print(f"[3/7] Enriched: {len(df.columns)} columns")
print(f"       Countries: {df.Geo_Country.unique().tolist()}")

# Phase 4: Detect
det = AdaptiveDetector()
bf = det.detect_bruteforce(df)
night = det.detect_night_logins(df)
comp = det.detect_compromise_pattern(df)
stuff = det.detect_credential_stuffing(df)
n_bf = len(bf[bf.Is_Bruteforce]) if "Is_Bruteforce" in bf.columns else 0
n_stuff = len(stuff[stuff.Is_Stuffing]) if "Is_Stuffing" in stuff.columns else 0
print(f"[4/7] Detection: bruteforce={n_bf}, night={len(night)}, compromise={len(comp)}, stuffing={n_stuff}")
print(f"       Adaptive threshold: {det.get_adaptive_threshold(df):.1f}")

# Phase 5: AI Engine
ai = AIEngine()
results = ai.run_full_analysis(df)
anom = results["anomaly"]
clusters = results["clusters"]
profiles = results["user_profiles"]
n_anom = len(anom[anom.is_anomaly]) if "is_anomaly" in anom.columns else 0
camp_ids = clusters.campaign_cluster[clusters.campaign_cluster >= 0] if "campaign_cluster" in clusters.columns else []
n_camps = len(set(camp_ids))
print(f"[5/7] AI Engine: anomalies={n_anom}, campaigns={n_camps}, profiled_users={len(profiles)}")
for user, p in list(profiles.items())[:3]:
    print(f"       User '{user}': state={p['current_state']}, risk={p['risk']:.3f}")

# Phase 6: Scoring
scorer = RiskScoringEngine()
scores = scorer.score_all_ips(df, anom)
levels = {}
for ip, d in scores.items():
    levels[d["level"]] = levels.get(d["level"], 0) + 1
print(f"[6/7] Risk Scoring: {levels}")
top_ip, top_data = sorted(scores.items(), key=lambda x: x[1]["score"], reverse=True)[0]
print(f"       Top threat: {top_ip} -> score={top_data['score']}, level={top_data['level']}")

# Phase 7: Forensics
sev_map = {ip: d["level"] for ip, d in scores.items()}
chains = build_all_attack_chains(df, sev_map)
tamper = detect_log_tampering(df)
df = link_sessions(df)
insiders = detect_insider_threats(df, profiles)
print(f"[7/7] Forensics: attack_chains={len(chains)}, tampered={tamper['tampered']}, insider_threats={len(insiders)}")
for ch in chains[:2]:
    print(f"       Chain IP={ch['ip']}: {' -> '.join(ch['phases_reached'])} ({ch['kill_chain_progress']*100:.0f}%)")

# Reports
html = generate_html_report(df, scores, bf, night, comp, tamper, chains, profiles, insiders, results, path)
csv_path = generate_csv_report(df, scores, path)

print("")
print("=" * 50)
print("ALL 7 PHASES PASSED SUCCESSFULLY")
print(f"HTML Report: {html}")
print(f"CSV Report:  {csv_path}")
print(f"Total Events: {len(df)}")
print(f"Unique IPs:   {df.IP_Address.nunique()}")
print(f"Sessions:     {df.Session_ID.nunique()}")
print("=" * 50)
