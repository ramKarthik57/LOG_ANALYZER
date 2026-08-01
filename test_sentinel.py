"""
SENTINEL — End-to-End Pipeline Unit Tests
"""
import pytest
import os
import pandas as pd
from sentinel.simulator import generate_full_simulation
from sentinel.parser import parse_log_file
from sentinel.enrichment import enrich_dataframe
from sentinel.detection import AdaptiveDetector
from sentinel.ai_engine import AIEngine
from sentinel.forensics import (build_all_attack_chains, detect_log_tampering,
                                 link_sessions, detect_insider_threats)
from sentinel.scoring import RiskScoringEngine
from sentinel.report import generate_html_report, generate_csv_report


@pytest.fixture(scope="module")
def pipeline_data():
    """Fixture to run the simulation, parsing, and enrichment steps once for tests."""
    # Phase 1: Simulate
    path = generate_full_simulation()
    assert os.path.exists(path), f"Simulated log file {path} was not created."
    
    # Phase 2: Parse
    df = parse_log_file(path)
    assert isinstance(df, pd.DataFrame)
    assert not df.empty, "Parsed DataFrame is empty."
    
    # Phase 3: Enrich
    df_enriched = enrich_dataframe(df)
    assert "Geo_Country" in df_enriched.columns, "Enrichment failed to add Geo_Country."
    
    return {
        "df": df_enriched,
        "path": path
    }


def test_detection(pipeline_data):
    """Test Phase 4: Threat Detection"""
    df = pipeline_data["df"]
    det = AdaptiveDetector()
    
    bf = det.detect_bruteforce(df)
    night = det.detect_night_logins(df)
    comp = det.detect_compromise_pattern(df)
    stuff = det.detect_credential_stuffing(df)
    
    assert bf is not None
    assert night is not None
    assert comp is not None
    assert stuff is not None
    assert det.get_adaptive_threshold(df) >= 0


def test_ai_engine(pipeline_data):
    """Test Phase 5: AI Engine analysis, clustering, and profiling"""
    df = pipeline_data["df"]
    ai = AIEngine()
    results = ai.run_full_analysis(df)
    
    assert "anomaly" in results
    assert "clusters" in results
    assert "user_profiles" in results
    
    anom = results["anomaly"]
    assert isinstance(anom, pd.DataFrame)
    assert "is_anomaly" in anom.columns


def test_scoring_and_forensics(pipeline_data):
    """Test Phase 6 & 7: Risk Scoring and Forensics analysis"""
    df = pipeline_data["df"]
    ai = AIEngine()
    results = ai.run_full_analysis(df)
    anom = results["anomaly"]
    profiles = results["user_profiles"]
    
    # Scoring
    scorer = RiskScoringEngine()
    scores = scorer.score_all_ips(df, anom)
    assert isinstance(scores, dict)
    
    # Forensics
    sev_map = {ip: d["level"] for ip, d in scores.items()}
    chains = build_all_attack_chains(df, sev_map)
    tamper = detect_log_tampering(df)
    df_linked = link_sessions(df)
    insiders = detect_insider_threats(df_linked, profiles)
    
    assert isinstance(chains, list)
    assert "tampered" in tamper
    assert "Session_ID" in df_linked.columns
    assert isinstance(insiders, list)


def test_report_generation(pipeline_data, tmp_path):
    """Test Phase 8: HTML and CSV Report Generation"""
    df = pipeline_data["df"]
    path = pipeline_data["path"]
    
    # Detect & Analysis mock results for report
    det = AdaptiveDetector()
    bf = det.detect_bruteforce(df)
    night = det.detect_night_logins(df)
    comp = det.detect_compromise_pattern(df)
    
    ai = AIEngine()
    results = ai.run_full_analysis(df)
    anom = results["anomaly"]
    profiles = results["user_profiles"]
    
    scorer = RiskScoringEngine()
    scores = scorer.score_all_ips(df, anom)
    
    sev_map = {ip: d["level"] for ip, d in scores.items()}
    chains = build_all_attack_chains(df, sev_map)
    tamper = detect_log_tampering(df)
    
    df_linked = link_sessions(df)
    insiders = detect_insider_threats(df_linked, profiles)
    
    # Use temporary directory for reports in tests to avoid cluttering workspace
    temp_html_report = os.path.join(tmp_path, "test_report.html")
    temp_csv_report = os.path.join(tmp_path, "test_report.csv")
    
    html = generate_html_report(df_linked, scores, bf, night, comp, tamper, chains, profiles, insiders, results, path)
    csv_path = generate_csv_report(df_linked, scores, path)
    
    assert os.path.exists(html)
    assert os.path.exists(csv_path)
    
    # Clean up generated files if they are in the root directory
    if os.path.exists(html) and os.path.dirname(html) == os.getcwd():
        try:
            os.remove(html)
        except Exception:
            pass
    if os.path.exists(csv_path) and os.path.dirname(csv_path) == os.getcwd():
        try:
            os.remove(csv_path)
        except Exception:
            pass
