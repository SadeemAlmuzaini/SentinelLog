"""
SentinelLog - pdf_export.py
Builds a PDF report from the CURRENT analysis result (never a stale fixed
file) using reportlab, which is a pure-Python dependency (no system
libraries required on Windows).
"""

import io
import re
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors as rl_colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def _markdown_to_plain(md_text):
    text = re.sub(r"^#+\s*", "", md_text, flags=re.MULTILINE)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"^-+\s*$", "", text, flags=re.MULTILINE)
    return text


def _esc(value):
    """XML-escape untrusted, CSV-derived text (uploaded filename, finding
    evidence strings that embed raw Source_IP/Destination_IP text) before
    it is embedded in a reportlab Paragraph. Paragraph parses a small
    HTML-like markup dialect, so unescaped '<', '>', '&' from untrusted
    input can either break the PDF build (a crafted CSV value that looks
    like an unsupported/invalid tag raises a parser ValueError) or be
    misinterpreted as markup. Escaping neutralizes both risks.
    """
    return _xml_escape(str(value))


def build_pdf(stats, risk, findings, report_text, source_filename):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CSTitle", parent=styles["Title"], fontSize=18,
                                  textColor=rl_colors.HexColor("#1E3A8A"))
    h2 = ParagraphStyle("CSH2", parent=styles["Heading2"], fontSize=13,
                        textColor=rl_colors.HexColor("#1E3A8A"), spaceBefore=10)
    body = ParagraphStyle("CSBody", parent=styles["BodyText"], fontSize=10, leading=14)

    elements = [
        Paragraph("SentinelLog &mdash; Firewall Security Report", title_style),
        Spacer(1, 4 * mm),
        Paragraph(f"Source file: {_esc(source_filename) if source_filename else 'uploaded CSV'}", body),
        Spacer(1, 6 * mm),
        Paragraph("Summary Metrics", h2),
    ]

    summary_rows = [
        ["Risk Score", f"{risk['score']} / 100"],
        ["Threat Level", risk["threat_level"]],
        ["Total Records", str(stats["total_records"])],
        ["Allowed / Blocked", f"{stats['allowed_connections']} / {stats['blocked_connections']}"],
        ["Countries", str(stats["countries"])],
        ["Protocols", str(stats["protocols"])],
        ["Total Traffic", f"{stats['total_traffic_bytes'] / 1024 / 1024:.2f} MB"],
    ]
    table = Table(summary_rows, colWidths=[55 * mm, 100 * mm])
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), rl_colors.HexColor("#1E3A8A")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, rl_colors.HexColor("#CBD5E1")),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 6 * mm))

    elements.append(Paragraph("Findings", h2))
    if not findings:
        elements.append(Paragraph("No findings were triggered by the configured "
                                   "detection rules on this dataset.", body))
    for f in findings:
        conf = f.get("confidence", "n/a")
        elements.append(Paragraph(
            f"<b>[{f['severity']}] {f['rule']}</b> ({f['id']}) &mdash; confidence: {conf}", body))
        elements.append(Paragraph(f"Evidence: {_esc(f['evidence'])}", body))
        if f.get("mitre"):
            m = f["mitre"]
            elements.append(Paragraph(
                f"MITRE ATT&amp;CK: {m['tactic']} &mdash; {m['technique_id']} "
                f"({m['technique_name']})", body))
        elements.append(Paragraph(f"Recommended action: {f['recommended_action']}", body))
        elements.append(Spacer(1, 2 * mm))

    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph("Full Report", h2))
    plain = _markdown_to_plain(report_text)
    for para in plain.split("\n\n"):
        clean = para.strip().replace("\n", " ")
        if clean:
            elements.append(Paragraph(clean, body))
            elements.append(Spacer(1, 2 * mm))

    doc.build(elements)
    buf.seek(0)
    return buf.read()
