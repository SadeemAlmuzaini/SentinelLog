"""
CyberSight AI - detection_engine.py
Modular, rule-based suspicious-activity detector plus a transparent,
documented risk-scoring function.

Every finding is a heuristic, not proof of compromise. Each one carries its
own evidence and a stated false-positive caveat so an analyst can judge it.
Each finding also carries a "confidence" field, separate from "severity":
  - severity   = how impactful this WOULD BE if the interpretation is correct
  - confidence = how certain the interpretation itself is, given only a
                 firewall connection log (no auth logs, no endpoint
                 telemetry, no packet payloads)

===============================================================================
RISK SCORE FORMULA (documented, deterministic, 0-100, never divides by zero)
===============================================================================
score = round(min(100,
            block_rate            * 40   +   # share of connections blocked
            high_risk_port_ratio  * 30   +   # share of ALLOWED traffic that hits sensitive ports
            icmp_ratio            * 15   +   # share of ICMP traffic
            scan_findings_weight  * 15        # breadth of distinct entities behind HIGH/CRITICAL findings
        ))

- block_rate           = blocked_connections / total_records                      (0..1)
- high_risk_port_ratio = ALLOWED connections to HIGH_RISK_PORTS / allowed_connections (0..1)
                         (uses the FULL per-port action breakdown, not just the
                         top-10 "chart" ports, and counts only the ALLOWED
                         subset, because an allowed connection to a sensitive
                         port is the actual exposure; a blocked one was denied.
                         The denominator is ALLOWED connections, not total
                         records: this measures "of the traffic that actually
                         got through, how much of it exposes a sensitive
                         service", which is the quantity that matters for
                         exposure. Revision note: an earlier version divided
                         by total_records instead, which made this component
                         structurally compete with block_rate for the same
                         denominator -- a dataset could not simultaneously
                         have a high block_rate (most traffic blocked) and a
                         high high_risk_port_ratio (most traffic allowed to a
                         sensitive port), since "most" of the same total
                         cannot describe two different action outcomes at
                         once. That made the documented CRITICAL band
                         (80-100) effectively unreachable (verified ceiling
                         ~70/100 under the old denominator, see
                         VALIDATION_REPORT.md / HARDENING_REPORT.md). Dividing
                         by allowed_connections instead fixes this because it
                         measures a fact about the allowed subset specifically,
                         independent of how much unrelated traffic was
                         blocked, which is both the more defensible metric and
                         the one that permits a severe, multi-signal dataset
                         (heavy blocking/scanning *and* meaningful allowed
                         exposure) to score as CRITICAL. If there are no
                         allowed connections at all, the ratio is defined as 0
                         (no allowed traffic means no allowed-port exposure to
                         measure) rather than raising a division error.
- icmp_ratio            = ICMP records / total_records                          (0..1)
- scan_findings_weight  = min(1, distinct "affected" entities behind HIGH or
                          CRITICAL findings / 3)                                (0..1)
                         (counts unique affected entities, not raw finding
                         count, so one noisy source that trips several rules
                         at once is not weighted multiple times over -- this
                         is what keeps the findings-breadth term from
                         double-counting a single underlying incident.)

All four components are normalized ratios, so each term is individually
bounded to its weight and the sum is clamped to [0, 100]. The four
components are intentionally kept on independent evidential axes (denial
volume, allowed-traffic exposure, protocol mix, and corroborating-findings
breadth) so that a dataset genuinely exhibiting several of them at once can
reach a high combined score without any one component being inflated. With
total_records == 0 the score is 0 (LOW) by definition rather than raising a
division error.

Per-finding severity (in each finding's own "severity"/"confidence" fields)
is intentionally a SEPARATE concept from this aggregate score: a finding's
severity says how serious THAT finding would be if its interpretation holds;
the risk score summarizes the WHOLE dataset across all four signals above.
A dataset can contain a single CRITICAL-severity finding yet still produce a
LOW or MEDIUM aggregate score if nothing else in the traffic corroborates it
(e.g. one isolated, already-blocked attempt) -- that is by design, not a bug:
the aggregate score reflects the overall shape of the traffic, not a
restatement of the worst individual finding.

THREAT_LEVEL thresholds (unchanged; verified reachable under the corrected
formula by tests in tests/test_analysis.py):
  0-29   LOW
  30-54  MEDIUM
  55-79  HIGH
  80-100 CRITICAL

===============================================================================
KNOWN LIMITATIONS (dataset-level, apply to every rule below)
===============================================================================
- This is a connection-log analyzer only. It has no authentication logs,
  no endpoint/process telemetry, and no packet payload visibility. It can
  observe that traffic was attempted/allowed/blocked between two
  addresses/ports; it cannot confirm that any attempt succeeded, that
  credentials were used, or that a host was compromised.
- MITRE ATT&CK associations are behavioral pattern matches against the
  technique's documented indicators, not confirmed technique usage. Where
  the available fields cannot reasonably support a specific technique,
  the finding is left unmapped (mitre=None) rather than guessed.
===============================================================================
"""

# Ports commonly targeted for unauthorized remote administration / data
# exfiltration. Presence of ALLOWED traffic here is treated as genuine
# perimeter exposure; presence of BLOCKED-only traffic is treated as
# attempted-but-denied interest, which is lower urgency.
HIGH_RISK_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle-DB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 6379: "Redis",
}

# Subset of HIGH_RISK_PORTS where the service's primary function is an
# interactive or credentialed login (so repeated BLOCKed attempts there are
# a defensible, if still hedged, brute-force/probing indicator). Ports left
# out (SMB/NetBIOS/MS-RPC/SMTP/FTP-DATA) are excluded because a blocked
# connection to them does not, on its own, indicate a login attempt.
AUTH_PORTS = {21, 22, 23, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379}

# Official MITRE ATT&CK reference links, verified against attack.mitre.org.
MITRE_REFERENCES = {
    "T1595.001": "https://attack.mitre.org/techniques/T1595/001/",
    "T1110": "https://attack.mitre.org/techniques/T1110/",
    "T1133": "https://attack.mitre.org/techniques/T1133/",
}

# --- Configurable detection thresholds ---------------------------------
PORT_SCAN_THRESHOLD = 15
REPEATED_BLOCK_THRESHOLD = 10
HOT_DESTINATION_THRESHOLD = 20
HIGH_VOLUME_SOURCE_RATIO = 0.20       # a single source responsible for >=20% of all records
HIGH_VOLUME_MIN_RECORDS = 20          # don't fire on tiny datasets where 20% is 1-2 rows
BURST_WINDOW_SECONDS = 60
BURST_EVENT_THRESHOLD = 15            # >=15 connections from one source within any 60s window
ICMP_RATIO_THRESHOLD = 0.25
HIGH_RISK_ALLOWED_HIGH_SEVERITY_RATIO = 0.05


def _severity_rank(sev):
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(sev, 0)


def _mitre(tactic, technique_id, technique_name, rationale):
    return {
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "rationale": rationale,
        "reference_url": MITRE_REFERENCES.get(technique_id),
    }


def _max_events_in_window(sorted_timestamps, window_seconds):
    """Sliding-window max count of events within `window_seconds` of each
    other. `sorted_timestamps` must already be sorted ascending. Returns
    (max_count, window_start, window_end) for the densest window found."""
    if not sorted_timestamps:
        return 0, None, None
    left = 0
    best = 1
    best_start = sorted_timestamps[0]
    best_end = sorted_timestamps[0]
    for right in range(len(sorted_timestamps)):
        while (sorted_timestamps[right] - sorted_timestamps[left]).total_seconds() > window_seconds:
            left += 1
        count = right - left + 1
        if count > best:
            best = count
            best_start = sorted_timestamps[left]
            best_end = sorted_timestamps[right]
    return best, best_start, best_end


def run_detections(stats, total_records):
    findings = []
    fid = 1

    def add(rule, severity, confidence, description, evidence, affected, record_count,
             rationale, recommended_action, next_steps, limitations, mitre=None):
        nonlocal fid
        findings.append({
            "id": f"F{fid:03d}",
            "rule": rule,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "evidence": evidence,
            "affected": affected,
            "record_count": record_count,
            "rationale": rationale,
            "recommended_action": recommended_action,
            "next_steps": next_steps,
            "limitations": limitations,
            "mitre": mitre,
        })
        fid += 1

    if total_records == 0:
        return findings

    # --- Rule 1: Potential Port Scan ------------------------------------
    for source_ip, ports in stats.get("source_to_ports", {}).items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            add(
                rule="Potential Port Scan",
                severity="HIGH" if len(ports) >= PORT_SCAN_THRESHOLD * 2 else "MEDIUM",
                confidence="MEDIUM",
                description=f"Source {source_ip} contacted {len(ports)} distinct destination ports.",
                evidence=f"Distinct destination ports observed: {sorted(ports)[:20]}"
                          + (" ..." if len(ports) > 20 else ""),
                affected=source_ip,
                record_count=len(ports),
                rationale="A single source touching many distinct ports in a short "
                          "dataset window is a classic (though not conclusive) "
                          "signature of service/port enumeration.",
                recommended_action="Review firewall logs for this source IP; "
                                    "consider temporary rate-limiting or blocking "
                                    "if not a known internal scanner.",
                next_steps="Check whether this source IP is a known internal "
                           "vulnerability scanner or monitoring tool before escalating.",
                limitations="Could also be a legitimate vulnerability scanner, "
                            "monitoring tool, or load balancer health-checker.",
                mitre=_mitre(
                    "Reconnaissance", "T1595.001", "Active Scanning: Scanning IP Blocks",
                    "Port enumeration against a range of destination ports is "
                    "consistent with active network scanning.",
                ),
            )

    # --- Rule 2: Repeated Blocked Connections ---------------------------
    for source_ip, count in stats.get("blocked_source_ip_counts", {}).items():
        if count >= REPEATED_BLOCK_THRESHOLD:
            blocked_ports = set(stats.get("blocked_source_to_ports", {}).get(source_ip, []))
            auth_ports_hit = sorted(blocked_ports & AUTH_PORTS)

            if auth_ports_hit:
                mitre = _mitre(
                    "Credential Access", "T1110", "Brute Force",
                    "Repeated, repeatedly-blocked connection attempts from one "
                    "source concentrated on authentication-relevant service "
                    f"port(s) {auth_ports_hit} are a common brute-force/"
                    "probing indicator, though this dataset alone cannot "
                    "confirm an authentication attempt actually occurred "
                    "or that credentials were used.",
                )
                description = (f"Source {source_ip} was blocked {count} times, "
                                f"including against authentication-relevant port(s) {auth_ports_hit}.")
                confidence = "MEDIUM"
            else:
                mitre = None
                description = f"Source {source_ip} was blocked {count} times."
                confidence = "LOW"

            add(
                rule="Repeated Blocked Connections",
                severity="MEDIUM" if count < REPEATED_BLOCK_THRESHOLD * 2 else "HIGH",
                confidence=confidence,
                description=description,
                evidence=f"{count} BLOCK-action records from {source_ip}"
                          + (f"; blocked destination ports include {auth_ports_hit}" if auth_ports_hit else "") + ".",
                affected=source_ip,
                record_count=count,
                rationale="A high volume of denied attempts from one source can "
                          "indicate persistent unauthorized access attempts or "
                          "automated brute-force/scanning activity."
                          + ("" if auth_ports_hit else " No authentication-service "
                             "port was among the blocked destinations here, so a "
                             "brute-force interpretation specifically is not "
                             "supported by this evidence alone."),
                recommended_action="Investigate the source; consider adding an "
                                    "explicit deny rule and alerting if the pattern continues.",
                next_steps="Correlate with authentication logs (if available) to "
                           "check whether any attempt from this source reached "
                           "a login prompt.",
                limitations="A misconfigured legitimate client retrying a failed "
                            "connection can also produce this pattern. Firewall-level "
                            "BLOCK does not by itself prove an authentication "
                            "attempt occurred.",
                mitre=mitre,
            )

    # --- Rule 3: Exposure of Sensitive Administrative Ports -------------
    port_action = stats.get("destination_port_action_counts", {})
    high_risk_rows = []
    total_allowed_high_risk = 0
    total_blocked_high_risk = 0
    for port, name in HIGH_RISK_PORTS.items():
        counts = port_action.get(port, {})
        allowed = counts.get("ALLOW", 0)
        blocked = counts.get("BLOCK", 0)
        if allowed or blocked:
            high_risk_rows.append((port, name, allowed, blocked))
            total_allowed_high_risk += allowed
            total_blocked_high_risk += blocked

    if high_risk_rows:
        port_list = ", ".join(
            f"{p} ({n}): {a} allowed / {b} blocked" for p, n, a, b in high_risk_rows
        )
        total_high_risk = total_allowed_high_risk + total_blocked_high_risk

        if total_allowed_high_risk > 0:
            allowed_ratio = total_allowed_high_risk / total_records
            severity = "HIGH" if allowed_ratio > HIGH_RISK_ALLOWED_HIGH_SEVERITY_RATIO else "MEDIUM"
            confidence = "MEDIUM"
            description = ("Traffic observed was ALLOWED to commonly exploited "
                           "administrative or database ports, indicating these "
                           "services are reachable.")
            rationale = ("Ports such as SMB (445), RDP (3389) and SSH (22) are "
                        "frequent targets for ransomware propagation, credential "
                        "stuffing, and unauthorized remote administration. "
                        "Because at least one connection to a sensitive port was "
                        "ALLOWED (not just attempted), this indicates the service "
                        "is actually reachable, not merely that it was probed.")
        else:
            severity = "LOW"
            confidence = "LOW"
            description = ("Traffic toward commonly exploited administrative or "
                           "database ports was observed, but every such "
                           "connection was BLOCKED.")
            rationale = ("All observed attempts to sensitive ports were denied "
                        "by the firewall, so this reflects attacker/scanner "
                        "interest rather than confirmed exposure.")

        add(
            rule="Exposure of Sensitive Administrative Ports",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=port_list,
            affected="multiple sources" if len(high_risk_rows) > 1 else HIGH_RISK_PORTS[high_risk_rows[0][0]],
            record_count=total_high_risk,
            rationale=rationale,
            recommended_action="Confirm whether these services are intentionally "
                                "internet-facing. If not required externally, "
                                "restrict access to VPN-only with MFA.",
            next_steps="For each ALLOWED port above, verify in the firewall "
                       "rule base whether that exposure is intentional and "
                       "whether MFA/VPN is enforced in front of it.",
            limitations="The presence of traffic to a port does not confirm the "
                        "service version, that it is vulnerable, or that any "
                        "connection attempt succeeded at the application layer.",
            mitre=_mitre(
                "Initial Access, Persistence", "T1133", "External Remote Services",
                "Reachable administrative/remote-access ports at the network "
                "perimeter are the condition this technique describes: "
                "adversaries leveraging externally-facing remote services to "
                "gain initial access to, or persist within, a network.",
            ) if total_allowed_high_risk > 0 else None,
        )

    # --- Rule 4: Elevated ICMP Volume ------------------------------------
    icmp_count = stats.get("protocol_distribution", {}).get("ICMP", 0)
    icmp_ratio = icmp_count / total_records if total_records else 0
    if icmp_ratio > ICMP_RATIO_THRESHOLD:
        add(
            rule="Elevated ICMP Volume",
            severity="MEDIUM",
            confidence="LOW",
            description=f"ICMP traffic accounts for {icmp_ratio*100:.1f}% of records "
                        f"({icmp_count} of {total_records}).",
            evidence=f"ICMP record count: {icmp_count} / {total_records} total.",
            affected="network-wide",
            record_count=icmp_count,
            rationale="A disproportionately high share of ICMP traffic relative to "
                      "TCP/UDP can indicate host-discovery (ping sweep) activity "
                      "ahead of a more targeted attack.",
            recommended_action="Rate-limit or filter unsolicited inbound ICMP at "
                                "the perimeter if this volume is unexpected.",
            next_steps="Sample a few ICMP source/destination pairs to check "
                       "whether they match known monitoring infrastructure "
                       "(e.g. uptime checks) before treating this as hostile.",
            limitations="ICMP is also used for legitimate diagnostics "
                        "(e.g. path MTU discovery, monitoring); this alone is "
                        "not evidence of malicious intent.",
            mitre=_mitre(
                "Reconnaissance", "T1595.001", "Active Scanning: Scanning IP Blocks",
                "The official technique description explicitly lists \"simple "
                "pings (ICMP requests and responses)\" as a form of IP block "
                "scanning used to gather targeting information before an attack.",
            ),
        )

    # --- Rule 5: Concentrated Traffic to Single Destination --------------
    for dest_ip, count in stats.get("dest_hit_counts", {}).items():
        if count >= HOT_DESTINATION_THRESHOLD:
            add(
                rule="Concentrated Traffic to Single Destination",
                severity="MEDIUM",
                confidence="LOW",
                description=f"Destination {dest_ip} received {count} connections, "
                            f"an unusually large share of total traffic.",
                evidence=f"{count} records targeting {dest_ip} "
                          f"({count/total_records*100:.1f}% of all records).",
                affected=dest_ip,
                record_count=count,
                rationale="A single destination absorbing a large share of all "
                          "connections can indicate either a popular legitimate "
                          "service or the focus of a targeted attack.",
                recommended_action="Confirm this destination's expected traffic "
                                    "profile; investigate if it is unexpected.",
                next_steps="Check whether this destination is a known gateway, "
                           "load balancer, or heavily-used internal service.",
                limitations="High-traffic legitimate services (e.g. a gateway or "
                            "load balancer) will also trigger this rule.",
                mitre=None,
            )

    # --- Rule 6: High-Volume Source ---------------------------------------
    if total_records >= HIGH_VOLUME_MIN_RECORDS:
        for source_ip, count in stats.get("top_source_ips", {}).items():
            share = count / total_records
            if share >= HIGH_VOLUME_SOURCE_RATIO:
                add(
                    rule="High-Volume Source",
                    severity="MEDIUM",
                    confidence="LOW",
                    description=f"Source {source_ip} accounts for {count} of "
                                f"{total_records} records ({share*100:.1f}% of all traffic).",
                    evidence=f"{count} records from {source_ip} "
                              f"({share*100:.1f}% of dataset).",
                    affected=source_ip,
                    record_count=count,
                    rationale="A single source responsible for a large share of "
                              "all observed traffic warrants a look, whether "
                              "that turns out to be a gateway/NAT device, a "
                              "busy legitimate client, or automated activity.",
                    recommended_action="Confirm whether this source is an "
                                        "expected high-traffic device (gateway, "
                                        "proxy, NAT) or investigate if unexpected.",
                    next_steps="Cross-check this IP against your asset inventory "
                               "or known-infrastructure list.",
                    limitations="Internal gateways, proxies, and NAT devices "
                                "routinely account for a large share of traffic "
                                "and are not inherently suspicious.",
                    mitre=None,
                )

    # --- Rule 7: Rapid Connection Burst (time-window) ---------------------
    if stats.get("has_timestamps"):
        for source_ip, ts_list in stats.get("source_ip_timestamps", {}).items():
            if len(ts_list) < BURST_EVENT_THRESHOLD:
                continue  # can't possibly reach the threshold in any window
            max_count, win_start, win_end = _max_events_in_window(ts_list, BURST_WINDOW_SECONDS)
            if max_count >= BURST_EVENT_THRESHOLD:
                add(
                    rule="Rapid Connection Burst",
                    severity="MEDIUM",
                    confidence="LOW",
                    description=f"Source {source_ip} made {max_count} connections "
                                f"within a {BURST_WINDOW_SECONDS}-second window.",
                    evidence=f"{max_count} records between "
                              f"{win_start.isoformat() if win_start else '?'} and "
                              f"{win_end.isoformat() if win_end else '?'}.",
                    affected=source_ip,
                    record_count=max_count,
                    rationale="A dense burst of connections from one source in a "
                              "short time window is consistent with scripted or "
                              "automated activity (scanning, flooding, or a retry "
                              "storm), as opposed to typical human-paced traffic.",
                    recommended_action="Review this source's traffic around the "
                                        "flagged time window for scan/flood "
                                        "indicators; consider rate-limiting.",
                    next_steps="Check whether source timestamps in this dataset "
                               "carry second-level precision; minute-only "
                               "timestamps make burst timing approximate.",
                    limitations="Could also be a legitimate retry storm, a batch "
                                "job, or a monitoring probe. Timestamp precision "
                                "in the source log directly affects how reliable "
                                "this window measurement is.",
                    mitre=None,
                )

    # --- Rule 8: Unrecognized Action Values -------------------------------
    if stats.get("unrecognized_action_count", 0) > 0:
        add(
            rule="Unrecognized Action Values",
            severity="LOW",
            confidence="HIGH",
            description=f"{stats['unrecognized_action_count']} record(s) had an "
                        f"Action value that is not ALLOW/BLOCK/DENY/DROP/etc.",
            evidence="See validation warnings for the raw values encountered.",
            affected="data quality",
            record_count=stats["unrecognized_action_count"],
            rationale="These records were kept in overall counts but excluded "
                      "from the allowed/blocked totals to avoid misclassifying them.",
            recommended_action="Check the source log format; extend the "
                                "recognized Action vocabulary if this is a "
                                "legitimate value from your firewall vendor.",
            next_steps="Inspect the raw Action values reported in validation "
                       "warnings and confirm they are a known vendor-specific term.",
            limitations="Not a security finding — a data-quality note.",
            mitre=None,
        )

    findings.sort(key=lambda f: -_severity_rank(f["severity"]))
    return findings


def _threat_level(score):
    """Map a 0-100 risk score to its threat-level label. Extracted as a
    standalone function (rather than inline in compute_risk_score) so the
    documented thresholds can be unit-tested directly at their exact
    boundary values (29/30, 54/55, 79/80) without having to engineer a
    synthetic dataset that happens to produce that precise score. Pure
    integer comparison, no side effects, deterministic.
    """
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def compute_risk_score(stats, findings, total_records):
    if total_records == 0:
        return {
            "score": 0,
            "threat_level": "LOW",
            "components": {
                "block_rate": 0, "high_risk_port_ratio": 0,
                "icmp_ratio": 0, "scan_findings_weight": 0,
            },
            "explanation": "No valid records were available to assess.",
        }

    block_rate = stats.get("blocked_connections", 0) / total_records

    port_action = stats.get("destination_port_action_counts", {})
    allowed_high_risk_hits = sum(
        counts.get("ALLOW", 0)
        for port, counts in port_action.items()
        if port in HIGH_RISK_PORTS
    )
    allowed_connections = stats.get("allowed_connections", 0)
    # Denominator is ALLOWED connections, not total_records: this measures
    # exposure within the traffic that actually got through, independent of
    # how much unrelated traffic was blocked. See the module docstring above
    # ("Revision note") for why this specific change makes CRITICAL reachable
    # without arbitrarily inflating ordinary/benign traffic.
    high_risk_port_ratio = (
        min(1.0, allowed_high_risk_hits / allowed_connections)
        if allowed_connections > 0 else 0.0
    )

    icmp_count = stats.get("protocol_distribution", {}).get("ICMP", 0)
    icmp_ratio = icmp_count / total_records

    high_or_critical_entities = {
        f["affected"] for f in findings if f["severity"] in ("HIGH", "CRITICAL")
    }
    scan_findings_weight = min(1.0, len(high_or_critical_entities) / 3)

    raw = (
        block_rate * 40 +
        high_risk_port_ratio * 30 +
        icmp_ratio * 15 +
        scan_findings_weight * 15
    )
    score = int(round(min(100, max(0, raw))))
    level = _threat_level(score)

    explanation = (
        f"Block rate contributed {block_rate*40:.1f} pts "
        f"({stats.get('blocked_connections', 0)}/{total_records} blocked); "
        f"high-risk port exposure contributed {high_risk_port_ratio*30:.1f} pts "
        f"({allowed_high_risk_hits}/{allowed_connections} ALLOWED connections went to sensitive ports); "
        f"ICMP volume contributed {icmp_ratio*15:.1f} pts "
        f"({icmp_count}/{total_records} ICMP records); "
        f"detection findings contributed {scan_findings_weight*15:.1f} pts "
        f"({len(high_or_critical_entities)} distinct entity/entities behind "
        f"HIGH/CRITICAL finding(s))."
    )

    return {
        "score": score,
        "threat_level": level,
        "components": {
            "block_rate": round(block_rate, 4),
            "high_risk_port_ratio": round(high_risk_port_ratio, 4),
            "icmp_ratio": round(icmp_ratio, 4),
            "scan_findings_weight": round(scan_findings_weight, 4),
        },
        "explanation": explanation,
    }
