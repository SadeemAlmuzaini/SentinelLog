"""
pytest-style tests for the analysis engine. Run with: pytest (from project root,
after `pip install -r requirements.txt`).
"""
import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND)

from analysis import parse_and_validate_csv, compute_statistics, CSVParseError  # noqa: E402
from detection_engine import run_detections, compute_risk_score, _threat_level  # noqa: E402
from report_generator import generate_report  # noqa: E402
from pdf_export import build_pdf  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def _csv_rows(rows):
    """Build an in-memory CSV string (header + data rows) for tests that
    construct synthetic scenarios inline rather than from a fixture file."""
    header = ("Timestamp,Source_IP,Destination_IP,Source_Port,Destination_Port,"
              "Protocol,Action,Country,Bytes\n")
    return header + "\n".join(rows) + "\n"


def test_valid_dataset_parses():
    v = parse_and_validate_csv(_read("valid.csv"))
    assert v["valid_rows"] == 20
    assert v["rejected_rows"] == 0


def test_only_allowed():
    v = parse_and_validate_csv(_read("only_allowed.csv"))
    stats = compute_statistics(v["rows"])
    assert stats["blocked_connections"] == 0
    assert stats["allowed_connections"] == v["valid_rows"]


def test_only_blocked():
    v = parse_and_validate_csv(_read("only_blocked.csv"))
    stats = compute_statistics(v["rows"])
    assert stats["allowed_connections"] == 0
    assert stats["blocked_connections"] == v["valid_rows"]


def test_mixed_actions_and_protocols():
    v = parse_and_validate_csv(_read("mixed.csv"))
    stats = compute_statistics(v["rows"])
    assert stats["allowed_connections"] + stats["blocked_connections"] <= stats["total_records"]
    assert stats["protocols"] >= 1


def test_empty_csv_raises():
    try:
        parse_and_validate_csv(_read("empty.csv"))
        assert False, "expected CSVParseError"
    except CSVParseError:
        pass


def test_header_only_raises():
    try:
        parse_and_validate_csv(_read("header_only.csv"))
        assert False, "expected CSVParseError"
    except CSVParseError:
        pass


def test_missing_required_columns_raises():
    try:
        parse_and_validate_csv(_read("missing_columns.csv"))
        assert False, "expected CSVParseError"
    except CSVParseError as exc:
        assert "Missing required column" in str(exc)


def test_malformed_rows_are_rejected_not_crash():
    v = parse_and_validate_csv(_read("malformed.csv"))
    assert v["rejected_rows"] >= 1
    assert v["valid_rows"] == 2


def test_invalid_ports_and_bytes_handled():
    v = parse_and_validate_csv(_read("invalid_ports_bytes.csv"))
    assert v["rejected_rows"] == 2
    assert v["valid_rows"] == 3
    assert len(v["warnings"]) >= 1


def test_bad_timestamps_do_not_crash():
    v = parse_and_validate_csv(_read("bad_timestamps.csv"))
    stats = compute_statistics(v["rows"])
    assert v["valid_rows"] == 3
    assert stats["has_timestamps"] is True


def test_port_scan_detected():
    v = parse_and_validate_csv(_read("port_scan.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    rules = [f["rule"] for f in findings]
    assert "Potential Port Scan" in rules
    scan = next(f for f in findings if f["rule"] == "Potential Port Scan")
    assert scan["affected"] == "198.51.100.5"
    assert scan["mitre"]["technique_id"] == "T1595.001"


def test_single_record_does_not_crash():
    v = parse_and_validate_csv(_read("single_record.csv"))
    stats = compute_statistics(v["rows"])
    risk = compute_risk_score(stats, [], stats["total_records"])
    assert v["valid_rows"] == 1
    assert 0 <= risk["score"] <= 100


def test_clean_dataset_has_no_findings():
    v = parse_and_validate_csv(_read("clean.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    assert findings == []


def test_risk_score_bounds_and_no_div_by_zero():
    empty_stats = {
        "total_records": 0, "blocked_connections": 0,
        "top_destination_ports": {}, "protocol_distribution": {},
    }
    risk = compute_risk_score(empty_stats, [], 0)
    assert risk["score"] == 0
    assert risk["threat_level"] == "LOW"


def test_risk_score_deterministic():
    v = parse_and_validate_csv(_read("valid.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    r1 = compute_risk_score(stats, findings, stats["total_records"])
    r2 = compute_risk_score(stats, findings, stats["total_records"])
    assert r1 == r2
    assert 0 <= r1["score"] <= 100


def test_high_volume_source_detected():
    """Synthetic fixture: one source responsible for 10/30 (33%) of records."""
    v = parse_and_validate_csv(_read("high_volume_source.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    hv = [f for f in findings if f["rule"] == "High-Volume Source"]
    assert len(hv) == 1
    assert hv[0]["affected"] == "10.0.0.100"
    assert hv[0]["record_count"] == 10
    assert hv[0]["mitre"] is None  # too generic alone to map to a technique


def test_rapid_connection_burst_detected():
    """Synthetic fixture: 20 connections from one source within ~20 seconds."""
    v = parse_and_validate_csv(_read("rapid_burst.csv"))
    stats = compute_statistics(v["rows"])
    assert stats["has_timestamps"] is True
    findings = run_detections(stats, stats["total_records"])
    burst = [f for f in findings if f["rule"] == "Rapid Connection Burst"]
    assert len(burst) == 1
    assert burst[0]["affected"] == "10.0.0.50"
    assert burst[0]["record_count"] == 20
    assert burst[0]["mitre"] is None  # ambiguous alone (scan vs flood vs retry storm)


def test_admin_port_allowed_traffic_is_high_severity_with_mitre():
    """Synthetic fixture: RDP traffic with both ALLOW and BLOCK hits.
    The allowed subset is real exposure, so this should be HIGH severity
    and carry the T1133 External Remote Services mapping."""
    v = parse_and_validate_csv(_read("admin_port_mixed.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    f = next(x for x in findings if x["rule"] == "Exposure of Sensitive Administrative Ports")
    assert f["severity"] == "HIGH"
    assert f["mitre"] is not None
    assert f["mitre"]["technique_id"] == "T1133"
    assert f["mitre"]["reference_url"] == "https://attack.mitre.org/techniques/T1133/"
    assert "allowed" in f["evidence"]


def test_admin_port_blocked_only_is_low_severity_no_mitre():
    """Synthetic fixture: RDP traffic that was entirely BLOCKed. No real
    exposure was confirmed, so severity should be LOW and no MITRE technique
    should be claimed."""
    v = parse_and_validate_csv(_read("admin_port_blocked_only.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    f = next(x for x in findings if x["rule"] == "Exposure of Sensitive Administrative Ports")
    assert f["severity"] == "LOW"
    assert f["mitre"] is None


def test_repeated_block_on_auth_port_maps_to_brute_force():
    """Synthetic fixture: repeated BLOCKed connections concentrated on SSH
    (an authentication-relevant port) should map to T1110 Brute Force."""
    v = parse_and_validate_csv(_read("repeated_block_auth_port.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    f = next(x for x in findings if x["rule"] == "Repeated Blocked Connections")
    assert f["mitre"] is not None
    assert f["mitre"]["technique_id"] == "T1110"
    assert f["mitre"]["reference_url"] == "https://attack.mitre.org/techniques/T1110/"


def test_repeated_block_on_nonauth_port_has_no_mitre_mapping():
    """Synthetic fixture: repeated BLOCKed connections to a non-authentication
    port (8080) should NOT be labeled Brute Force — there is no evidence an
    authentication attempt was targeted."""
    v = parse_and_validate_csv(_read("repeated_block_nonauth_port.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    f = next(x for x in findings if x["rule"] == "Repeated Blocked Connections")
    assert f["mitre"] is None


def test_elevated_icmp_mitre_mapping_and_tactic():
    """ICMP-heavy dataset should map to T1595.001 under the Reconnaissance
    tactic (not T1018/Discovery, which is the wrong tactic for externally
    observed ICMP sweeps)."""
    v = parse_and_validate_csv(_read("valid.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    icmp_findings = [f for f in findings if f["rule"] == "Elevated ICMP Volume"]
    if icmp_findings:
        m = icmp_findings[0]["mitre"]
        assert m["technique_id"] == "T1595.001"
        assert m["tactic"] == "Reconnaissance"
        assert m["reference_url"] == "https://attack.mitre.org/techniques/T1595/001/"


def test_high_risk_port_detection_is_not_limited_to_top_10_ports():
    """Regression test for a real bug: high-risk-port detection and the risk
    score used to read only stats['top_destination_ports'] (capped at the 10
    most-frequent ports), so a high-risk port that wasn't among the top 10
    by raw frequency was invisible to both. Build a dataset with 11 distinct
    low-frequency ports plus one ALLOWed hit on port 3389 (RDP) so that RDP
    is guaranteed to rank below the top-10 cutoff, and confirm it is still
    detected via the full (uncapped) per-port aggregate."""
    lines = ["Timestamp,Source_IP,Destination_IP,Source_Port,Destination_Port,Protocol,Action,Country,Bytes"]
    # 11 distinct ordinary ports, 2 hits each (22 rows) -> all outrank a
    # single RDP hit by raw frequency, pushing RDP out of any top-10 cut.
    ordinary_ports = [8000 + i for i in range(11)]
    for p in ordinary_ports:
        for _ in range(2):
            lines.append(f"2026-10-24 09:00:00,10.0.0.5,192.168.9.9,40000,{p},TCP,ALLOW,US,500")
    # single ALLOWed hit on the high-risk RDP port
    lines.append("2026-10-24 09:05:00,10.0.0.6,192.168.9.10,40001,3389,TCP,ALLOW,US,500")
    csv_text = "\n".join(lines) + "\n"

    v = parse_and_validate_csv(csv_text)
    stats = compute_statistics(v["rows"])
    # Sanity: confirm RDP really did fall outside the top-10 "chart" field,
    # i.e. this test actually exercises the bug it is meant to catch.
    assert 3389 not in stats["top_destination_ports"]
    assert 3389 in stats["destination_port_counts"]

    findings = run_detections(stats, stats["total_records"])
    f = next((x for x in findings if x["rule"] == "Exposure of Sensitive Administrative Ports"), None)
    assert f is not None, "high-risk port outside the top-10 chart ports was not detected"

    risk = compute_risk_score(stats, findings, stats["total_records"])
    assert risk["components"]["high_risk_port_ratio"] > 0, \
        "risk score's high-risk-port component did not see the port outside the top-10 cut"


def test_risk_score_scan_findings_weight_dedupes_by_entity():
    """Regression test: a single source triggering multiple HIGH findings
    at once (port scan + high-volume) should not multiply the risk score's
    scan_findings_weight component beyond counting that one entity once."""
    lines = ["Timestamp,Source_IP,Destination_IP,Source_Port,Destination_Port,Protocol,Action,Country,Bytes"]
    # One source hitting 35 distinct ports (HIGH port-scan) across a small
    # dataset so it also clears the 20%% high-volume-source threshold.
    for i in range(35):
        lines.append(f"2026-10-24 09:00:{i%60:02d},10.0.0.77,192.168.3.3,40000,{3000+i},TCP,ALLOW,US,500")
    # padding rows from other sources so total_records stays small but >=20
    for i in range(5):
        lines.append(f"2026-10-24 09:01:00,10.1.1.{i},192.168.3.4,41000,443,TCP,ALLOW,DE,400")
    csv_text = "\n".join(lines) + "\n"

    v = parse_and_validate_csv(csv_text)
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    rules = {f["rule"] for f in findings}
    assert "Potential Port Scan" in rules
    assert "High-Volume Source" in rules
    high_or_crit_affected = {f["affected"] for f in findings if f["severity"] in ("HIGH", "CRITICAL")}
    # Both HIGH findings here point at the same source IP.
    assert high_or_crit_affected == {"10.0.0.77"}

    risk = compute_risk_score(stats, findings, stats["total_records"])
    # scan_findings_weight = min(1, unique_entities / 3) = min(1, 1/3) = 1/3,
    # not 2/3 (which raw finding count would have produced).
    assert abs(risk["components"]["scan_findings_weight"] - round(1 / 3, 4)) < 1e-4


def test_findings_carry_confidence_and_next_steps():
    v = parse_and_validate_csv(_read("port_scan.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    assert len(findings) > 0
    for f in findings:
        assert f.get("confidence") in ("LOW", "MEDIUM", "HIGH")
        assert isinstance(f.get("next_steps"), str) and f["next_steps"]


def test_real_sample_matches_known_values():
    """Cross-check against independently known totals for the project's
    real sample_firewall_logs.csv (500 rows, 309 allowed / 191 blocked,
    7 countries, 3 protocols, 37,877,294 total bytes)."""
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "sample_firewall_logs.csv",
    )
    with open(sample_path, encoding="utf-8") as f:
        text = f.read()
    v = parse_and_validate_csv(text)
    stats = compute_statistics(v["rows"])
    assert stats["total_records"] == 500
    assert stats["allowed_connections"] == 309
    assert stats["blocked_connections"] == 191
    assert stats["countries"] == 7
    assert stats["protocols"] == 3
    assert stats["total_traffic_bytes"] == 37877294



# --- Validation & false-positive-testing phase: input security regressions ---
# These cover the Section 5 requirement that uploaded data is treated as
# untrusted and cannot inject HTML/script into findings or reports, plus the
# PDF-export stability and CSV-export formula-injection issues discovered
# while validating that requirement against this project's existing code.

def test_injection_payloads_are_html_escaped_in_markdown_report():
    """A CSV with HTML/script-like Country values and a malformed Source_IP
    (invalid format, kept as raw text with a warning rather than hard-failed)
    must never appear as raw, executable HTML in the generated markdown
    report, because the frontend renders that report via
    marked.parse() + innerHTML with no further sanitization."""
    v = parse_and_validate_csv(_read("validation_phase/injection_payloads.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    risk = compute_risk_score(stats, findings, stats["total_records"])
    report = generate_report(stats, risk, findings, v)

    raw_payloads = [
        "<img src=x onerror=alert(1)>",
        "<script>alert(2)</script>",
    ]
    for payload in raw_payloads:
        assert payload not in report, f"unescaped payload leaked into report: {payload!r}"
    # The content must still be present, just neutralized as literal text.
    assert "&lt;img src=x onerror=alert(1)&gt;" in report
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in report


def test_injection_payloads_do_not_crash_pdf_export():
    """The same adversarial dataset must not crash PDF generation. Before the
    fix, reportlab's Paragraph (which parses a small HTML-like markup
    dialect) raised a ValueError on unescaped '<'/'>' content sourced from
    the CSV, breaking the PDF download for any analysis containing it."""
    v = parse_and_validate_csv(_read("validation_phase/injection_payloads.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    risk = compute_risk_score(stats, findings, stats["total_records"])
    report = generate_report(stats, risk, findings, v)

    pdf_bytes = build_pdf(stats, risk, findings, report, "injection_payloads.csv")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes[:4] == b"%PDF"


def test_findings_csv_export_neutralizes_formula_injection():
    """A finding's "affected"/"description"/"recommended_action" text can
    embed a raw, malformed Source_IP/Destination_IP string. If that string
    starts with '=', '+', '-', or '@', writing it verbatim into the exported
    findings.csv risks spreadsheet formula injection when the file is later
    opened in Excel/LibreOffice/Google Sheets. app._csv_safe must prefix such
    values with a leading apostrophe so they are always treated as literal
    text, while leaving ordinary values untouched."""
    from app import _csv_safe

    dangerous = ["=1+1", "+1+1", "-1+1", "@SUM(1+1)", "=cmd|' /C calc'!A1"]
    for value in dangerous:
        safe = _csv_safe(value)
        assert safe.startswith("'"), f"formula-triggering value not neutralized: {value!r} -> {safe!r}"
        assert safe == "'" + value

    ordinary = ["10.0.0.1", "Source 10.0.0.1 was blocked 20 times.", ""]
    for value in ordinary:
        assert _csv_safe(value) == value


def test_benign_report_content_is_unaffected_by_escaping():
    """Escaping must be invisible for ordinary, non-malicious data: normal
    country names and IPs contain no HTML-special characters, so the
    generated report should read exactly as before."""
    v = parse_and_validate_csv(_read("clean.csv"))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    risk = compute_risk_score(stats, findings, stats["total_records"])
    report = generate_report(stats, risk, findings, v)
    assert "&amp;" not in report
    assert "&lt;" not in report
    assert "&gt;" not in report


def test_large_input_within_local_limits_completes_successfully():
    """A several-thousand-row CSV (well within the 15 MB upload limit) must
    parse, analyze, and score without error or excessive slowdown."""
    import time

    header = ("Timestamp,Source_IP,Destination_IP,Source_Port,Destination_Port,"
              "Protocol,Action,Country,Bytes\n")
    lines = [header]
    for i in range(5000):
        src_ip = f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}"
        action = "BLOCK" if i % 3 == 0 else "ALLOW"
        proto = "ICMP" if i % 11 == 0 else "TCP"
        lines.append(
            f"2026-10-24 09:{i % 60:02d}:{i % 60:02d},{src_ip},198.51.100.{i % 256},"
            f"{40000 + (i % 1000)},{443 if i % 2 else 22},{proto},{action},US,{500 + i}\n"
        )
    csv_text = "".join(lines)

    start = time.time()
    v = parse_and_validate_csv(csv_text)
    assert v["valid_rows"] == 5000
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    risk = compute_risk_score(stats, findings, stats["total_records"])
    elapsed = time.time() - start

    assert 0 <= risk["score"] <= 100
    assert elapsed < 30, f"5,000-row analysis took {elapsed:.1f}s, unexpectedly slow"



# --- Final hardening phase: risk-score formula fix (CRITICAL reachability) ---
# The validation phase documented that CRITICAL (80-100) was structurally
# unreachable because block_rate and high_risk_port_ratio both divided by
# total_records, so a dataset could not have "most traffic blocked" and
# "most traffic allowed to a sensitive port" at once. The fix changes
# high_risk_port_ratio's denominator to allowed_connections (see the module
# docstring "Revision note" in detection_engine.py). These tests prove the
# fix without asserting on exact score values beyond what's needed, so they
# stay robust to minor, behavior-preserving tuning later.

def test_threat_level_boundaries_exact():
    """Direct, dataset-independent check of the documented thresholds at
    their exact edges: 0-29 LOW, 30-54 MEDIUM, 55-79 HIGH, 80-100 CRITICAL."""
    assert _threat_level(0) == "LOW"
    assert _threat_level(29) == "LOW"
    assert _threat_level(30) == "MEDIUM"
    assert _threat_level(54) == "MEDIUM"
    assert _threat_level(55) == "HIGH"
    assert _threat_level(79) == "HIGH"
    assert _threat_level(80) == "CRITICAL"
    assert _threat_level(100) == "CRITICAL"


def test_high_risk_port_ratio_denominator_is_allowed_not_total():
    """Regression test for the specific structural fix: a dataset with a lot
    of BLOCKED, non-high-risk-port traffic (which would dilute a
    total_records-based ratio) but where 100% of the small ALLOWED subset
    goes to a high-risk port must score high_risk_port_ratio == 1.0, not a
    small fraction. This is the behavior the old formula could not produce
    simultaneously with a high block_rate."""
    rows = []
    for i in range(80):
        rows.append(f"2026-10-24 09:{i%60:02d}:00,203.0.113.{i%20+1},198.51.100.9,"
                    f"{40000+i},9999,TCP,BLOCK,RU,100")
    for i in range(5):
        rows.append(f"2026-10-24 10:{i:02d}:00,172.16.0.{i+1},10.0.0.5,"
                    f"{50000+i},3389,TCP,ALLOW,DE,200")
    v = parse_and_validate_csv(_csv_rows(rows))
    stats = compute_statistics(v["rows"])
    findings = run_detections(stats, stats["total_records"])
    risk = compute_risk_score(stats, findings, stats["total_records"])
    assert risk["components"]["block_rate"] > 0.9
    assert risk["components"]["high_risk_port_ratio"] == 1.0


def test_all_four_threat_levels_reachable_by_constructed_datasets():
    """Proves LOW, MEDIUM, HIGH, and CRITICAL are all reachable under
    plausible, explicitly constructed synthetic conditions -- not just
    theoretically possible by the formula's arithmetic. Each dataset
    represents a qualitatively different traffic shape, not an arbitrary
    search for a specific score."""
    def run(rows):
        v = parse_and_validate_csv(_csv_rows(rows))
        stats = compute_statistics(v["rows"])
        findings = run_detections(stats, stats["total_records"])
        return compute_risk_score(stats, findings, stats["total_records"])

    # LOW: ordinary allowed traffic, nothing suspicious.
    low_rows = [f"2026-10-24 09:{i%60:02d}:00,172.16.0.{(i%40)+1},198.51.100.{(i%40)+1},"
                f"{30000+i},443,TCP,ALLOW,DE,500" for i in range(100)]
    low = run(low_rows)
    assert low["threat_level"] == "LOW"

    # MEDIUM: moderate blocking plus some admin-port exposure, no scan corroboration.
    medium_rows = (
        [f"2026-10-24 09:{i%60:02d}:00,198.51.100.{i+1},10.0.0.9,{40000+i},22,TCP,BLOCK,RU,100"
         for i in range(40)]
        + [f"2026-10-24 09:{i%60:02d}:00,172.16.0.{i+1},198.51.100.{i+1},{30000+i},443,TCP,ALLOW,DE,500"
           for i in range(30)]
        + [f"2026-10-24 09:{i%60:02d}:00,10.0.1.{i+1},10.0.0.5,{50000+i},3389,TCP,ALLOW,US,200"
           for i in range(10)]
    )
    medium = run(medium_rows)
    assert medium["threat_level"] == "MEDIUM"

    # HIGH: heavier blocking plus a real port scan plus modest admin exposure.
    high_rows = []
    for src_idx in range(3):
        src_ip = f"203.0.113.{src_idx+1}"
        high_rows += [f"2026-10-24 09:30:00,{src_ip},198.51.100.10,{p},{p},TCP,BLOCK,RU,100"
                      for p in range(16000, 16020)]
    high_rows += [f"2026-10-24 09:{i%60:02d}:00,203.0.113.9,198.51.100.9,{40000+i},7,ICMP,BLOCK,RU,100"
                  for i in range(80)]
    high_rows += [f"2026-10-24 10:{i%60:02d}:00,172.16.0.{i+1},10.0.0.5,{50000+i},3389,TCP,ALLOW,DE,200"
                  for i in range(15)]
    high_rows += [f"2026-10-24 11:{i%60:02d}:00,172.16.1.{i+1},198.51.100.20,{60000+i},443,TCP,ALLOW,DE,500"
                  for i in range(15)]
    high = run(high_rows)
    assert high["threat_level"] == "HIGH"

    # CRITICAL: multi-vector -- heavy blocked ICMP flood/scan from several
    # sources (drives block_rate + icmp_ratio + scan_findings_weight up) AND
    # a small but fully-exposed allowed subset hitting an admin port (drives
    # high_risk_port_ratio to 1.0, independently of the blocked volume).
    crit_rows = []
    for src_idx in range(5):
        src_ip = f"203.0.113.{src_idx+1}"
        crit_rows += [f"2026-10-24 09:{i%60:02d}:00,{src_ip},198.51.100.9,{40000+i},7,ICMP,BLOCK,RU,100"
                      for i in range(60)]
        crit_rows += [f"2026-10-24 09:30:00,{src_ip},198.51.100.10,{p},{p},TCP,BLOCK,RU,100"
                      for p in range(16000, 16020)]
    crit_rows += [f"2026-10-24 10:{i%60:02d}:00,198.51.100.{20+i},10.0.0.5,{50000+i},3389,TCP,ALLOW,DE,200"
                  for i in range(20)]
    critical = run(crit_rows)
    assert critical["threat_level"] == "CRITICAL"
    assert critical["score"] >= 80


def test_benign_and_merely_noisy_traffic_never_reaches_high_or_critical():
    """Ordinary high-volume allowed traffic (CDN-like) and heavy but fully
    ALLOWED ICMP monitoring must never cross into HIGH/CRITICAL just from
    volume or protocol mix alone -- the fix must not make noisy-but-benign
    traffic score higher than before."""
    def run(rows):
        v = parse_and_validate_csv(_csv_rows(rows))
        stats = compute_statistics(v["rows"])
        findings = run_detections(stats, stats["total_records"])
        return compute_risk_score(stats, findings, stats["total_records"])

    cdn_rows = [f"2026-10-24 09:{i%60:02d}:00,172.16.0.{(i%40)+1},198.51.100.{(i%40)+1},"
                f"{30000+i},443,TCP,ALLOW,DE,500" for i in range(200)]
    cdn = run(cdn_rows)
    assert cdn["threat_level"] in ("LOW", "MEDIUM")

    icmp_rows = [f"2026-10-24 09:{i%60:02d}:00,10.0.0.9,198.51.100.{(i%50)+1},"
                 f"{40000+i},7,ICMP,ALLOW,DE,500" for i in range(150)]
    icmp = run(icmp_rows)
    assert icmp["threat_level"] in ("LOW", "MEDIUM")

    small_admin_rows = (
        [f"2026-10-24 09:{i:02d}:00,10.0.5.{i+1},10.0.0.5,{50000+i},22,TCP,ALLOW,US,200"
         for i in range(4)]
        + [f"2026-10-24 09:{i%60:02d}:00,172.16.0.{(i%40)+1},198.51.100.{(i%40)+1},"
           f"{30000+i},443,TCP,ALLOW,DE,500" for i in range(100)]
    )
    small_admin = run(small_admin_rows)
    assert small_admin["threat_level"] == "LOW"
