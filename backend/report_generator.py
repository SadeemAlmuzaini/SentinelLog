"""
SentinelLog - report_generator.py
Template-based security report. No external AI call is made here — this is
explicitly a local, deterministic report built from the computed statistics,
risk score, and detection findings. If Gemini integration is later enabled
(see app.py), that code path is responsible for its own disclosure; this
function must never claim AI involvement that didn't happen.
"""

from datetime import datetime, timezone
import html


def _fmt_mb(num_bytes):
    return f"{num_bytes / 1024 / 1024:.2f} MB"


def _esc(value):
    """HTML-escape untrusted, CSV-derived text (country names, IPs that failed
    format validation, finding text built from those values, raw CSV header
    names) before it is embedded in the markdown report. The report is later
    rendered client-side via marked.parse() + innerHTML with no further
    sanitization, so this is the point that must neutralize HTML/script
    content from untrusted uploaded data. Escaped entities still render as
    plain, correct text; they are not re-interpreted as markup.
    """
    return html.escape(str(value), quote=True)


def generate_report(stats, risk, findings, validation):
    total = stats["total_records"]
    blocked = stats["blocked_connections"]
    allowed = stats["allowed_connections"]
    block_pct = (blocked / total * 100) if total else 0

    top_countries = sorted(stats["country_distribution"].items(), key=lambda kv: -kv[1])[:5]
    top_countries_str = ", ".join(f"{_esc(c)} ({n})" for c, n in top_countries) or "n/a"

    high_crit = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
    other = [f for f in findings if f["severity"] not in ("HIGH", "CRITICAL")]

    lines = []
    lines.append("# SENTINELLOG — FIREWALL SECURITY REPORT")
    lines.append("")
    lines.append(f"*Generated locally, template-based (no external AI call). "
                 f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 1. Executive Summary")
    lines.append("")
    lines.append(
        f"This report covers **{total} valid records** "
        f"({validation['rejected_rows']} row(s) rejected during validation) "
        f"representing **{allowed} allowed** and **{blocked} blocked** connections "
        f"(**{block_pct:.1f}%** block rate), totaling "
        f"**{_fmt_mb(stats['total_traffic_bytes'])}** of traffic across "
        f"**{stats['countries']} countries** and **{stats['protocols']} protocols**."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 2. Risk Score and Threat Level")
    lines.append("")
    lines.append(f"**Risk Score: {risk['score']} / 100 — {risk['threat_level']}**")
    lines.append("")
    lines.append(risk["explanation"])
    lines.append("")
    lines.append(
        "*This is a heuristic assessment of the supplied logs only. It is not "
        "a certified security rating and does not prove an environment is or "
        "isn't compromised.*"
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 3. Dataset Overview")
    lines.append("")
    lines.append(f"- Unique source IPs: **{stats['unique_source_ips']}**")
    lines.append(f"- Unique destination IPs: **{stats['unique_destination_ips']}**")
    lines.append(f"- Unique destination ports: **{stats['unique_destination_ports']}**")
    lines.append(f"- Average bytes/record: **{stats['average_bytes_per_record']:.0f}**")
    if stats["has_timestamps"]:
        lines.append(f"- Time range: **{stats['min_timestamp']} → {stats['max_timestamp']}**")
    else:
        lines.append("- Time range: *no valid timestamps in this dataset*")
    lines.append(f"- Top countries: {top_countries_str}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 4. Suspicious Activity Findings")
    lines.append("")
    if not findings:
        lines.append("No findings were triggered by the configured detection rules "
                     "on this dataset.")
    else:
        for f in high_crit + other:
            lines.append(f"**[{f['severity']}] {_esc(f['rule'])}** ({f['id']}) "
                         f"— interpretive confidence: {f.get('confidence', 'n/a')}")
            lines.append(f"- Description: {_esc(f['description'])}")
            lines.append(f"- Evidence: {_esc(f['evidence'])}")
            lines.append(f"- Affected: {_esc(f['affected'])} ({f['record_count']} record(s))")
            lines.append(f"- Why this matters: {_esc(f['rationale'])}")
            if f.get("mitre"):
                m = f["mitre"]
                ref = f" Reference: {m['reference_url']}" if m.get("reference_url") else ""
                lines.append(
                    f"- Possible MITRE ATT&CK association: {m['tactic']} — "
                    f"{m['technique_id']} ({m['technique_name']}). {m['rationale']} "
                    f"*(behavioral association, not confirmed adversary activity)*{ref}"
                )
            lines.append(f"- Recommended action: {_esc(f['recommended_action'])}")
            if f.get("next_steps"):
                lines.append(f"- Suggested next step to verify: {_esc(f['next_steps'])}")
            lines.append(f"- Limitations: {_esc(f['limitations'])}")
            lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 5. Defensive Recommendations")
    lines.append("")
    if high_crit:
        lines.append("Based on the HIGH/CRITICAL findings above:")
        for f in high_crit:
            lines.append(f"- {_esc(f['recommended_action'])}")
    else:
        lines.append("No HIGH/CRITICAL findings were triggered. General hygiene "
                     "recommendations:")
        lines.append("- Periodically review blocked-connection trends for drift.")
        lines.append("- Keep firewall rules and exposed services under regular review.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 6. Data Quality & Limitations")
    lines.append("")
    lines.append(f"- Rows accepted: **{validation['valid_rows']}** / "
                 f"{validation['total_rows']} ({validation['rejected_rows']} rejected)")
    if validation["unmapped_columns"]:
        lines.append(f"- Unrecognized columns ignored: "
                     f"{', '.join(_esc(c) for c in validation['unmapped_columns'])}")
    if stats["unrecognized_action_count"]:
        lines.append(f"- {stats['unrecognized_action_count']} record(s) had an "
                     f"unrecognized Action value and were excluded from allowed/blocked counts.")
    lines.append(
        "- This analysis is heuristic and based solely on the uploaded CSV. "
        "It cannot confirm whether any attempt succeeded, and does not "
        "constitute a penetration test or certified audit."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 7. Overall Assessment")
    lines.append("")
    lines.append(f"**POSTURE: {risk['threat_level']} RISK (score {risk['score']}/100)**")
    lines.append("")
    lines.append(
        "Review the findings and recommendations above. This report reflects "
        "only the current analysis run; re-upload and re-analyze after making "
        "changes to confirm improvement."
    )

    return "\n".join(lines)
