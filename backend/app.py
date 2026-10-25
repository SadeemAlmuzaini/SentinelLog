"""
SentinelLog - app.py
Flask backend. Binds to 127.0.0.1 only. Processes uploads in memory
(no permanent storage of uploaded CSVs). Serves the frontend as static files.

Run:  python app.py        (see ../README.md / ../run.bat)
"""

import os
import sys
import json
import logging
import secrets
from datetime import datetime, timezone

from flask import Flask, request, jsonify, send_from_directory, Response, session

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analysis import parse_and_validate_csv, compute_statistics, CSVParseError
from detection_engine import run_detections, compute_risk_score
from report_generator import generate_report
from pdf_export import build_pdf


def _csv_safe(value):
    """Neutralize CSV/spreadsheet formula injection. Finding fields such as
    "affected" and "description" can embed raw, untrusted CSV field values
    (e.g. a Source_IP that failed IP-format validation but was still kept
    as free text). If such a value starts with =, +, -, @, or a tab/CR,
    Excel/LibreOffice/Google Sheets may interpret the cell as a formula
    when the exported CSV is opened. Prefixing with a single quote forces
    the cell to be treated as literal text in every major spreadsheet app,
    while leaving ordinary values (the vast majority) completely unchanged.
    """
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

MAX_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("sentinellog")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
# Signs the session cookie that keeps each visitor's analysis result
# separate from every other visitor's on a shared/public deployment (see
# _RESULTS_BY_SESSION below). If SECRET_KEY is not set, a random key is
# generated once at process startup -- sessions simply reset on restart,
# which fits this app's existing "processed in memory only" design. Set a
# fixed SECRET_KEY in production so a redeploy/restart does not silently
# invalidate everyone's current session.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Per-browser-session result store. Earlier builds used a single shared
# module-level dict (_LAST_RESULT) for the most recent analysis; that is
# safe for one local user but means, on a public multi-user deployment,
# every visitor would see the LAST ANALYSIS RUN BY ANYONE ELSE -- a real
# data-exposure bug once this app is reachable over the network rather than
# only from 127.0.0.1. _RESULTS_BY_SESSION keys each result by a random,
# session-cookie-held id instead, so results are isolated per visitor.
# Still fully in-memory (nothing is written to disk), and still bounded --
# _MAX_SESSIONS caps memory growth from anonymous public traffic by evicting
# the oldest-inserted entry once the cap is exceeded.
_RESULTS_BY_SESSION = {}
_MAX_SESSIONS = 500


def _session_id():
    sid = session.get("sid")
    if not sid:
        sid = secrets.token_hex(16)
        session["sid"] = sid
    return sid


def _store_result(sid, result, filename):
    _RESULTS_BY_SESSION[sid] = {"data": result, "filename": filename}
    if len(_RESULTS_BY_SESSION) > _MAX_SESSIONS:
        oldest = next(iter(_RESULTS_BY_SESSION))
        if oldest != sid:
            _RESULTS_BY_SESSION.pop(oldest, None)


def _get_result():
    sid = session.get("sid")
    if not sid:
        return None
    return _RESULTS_BY_SESSION.get(sid)


def _safe_filename(name):
    name = os.path.basename(name or "upload.csv")
    name = name.replace("\x00", "")
    return name[:200] or "upload.csv"


def _build_result(file_text, filename):
    validation = parse_and_validate_csv(file_text)
    stats = compute_statistics(validation["rows"])
    findings = run_detections(stats, stats["total_records"])
    risk = compute_risk_score(stats, findings, stats["total_records"])
    report_text = generate_report(stats, risk, findings, validation)

    result = {
        "source_filename": filename,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation": {
            "total_rows": validation["total_rows"],
            "valid_rows": validation["valid_rows"],
            "rejected_rows": validation["rejected_rows"],
            "rejected_reasons": validation["rejected_reasons"],
            "warnings": validation["warnings"],
            "unmapped_columns": validation["unmapped_columns"],
        },
        "stats": stats,
        "risk": risk,
        "findings": findings,
        "report": report_text,
    }
    return result


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    safe_root = os.path.abspath(FRONTEND_DIR)
    target = os.path.abspath(os.path.join(FRONTEND_DIR, filename))
    if not target.startswith(safe_root):
        return jsonify({"error": "Not found"}), 404
    if not os.path.isfile(target):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file part named 'file' in the request."}), 400

    upload = request.files["file"]
    if upload.filename == "":
        return jsonify({"error": "No file selected."}), 400

    filename = _safe_filename(upload.filename)
    if not filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are accepted."}), 400

    try:
        raw = upload.read()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
    except Exception:
        # The real exception (and traceback) is logged server-side only;
        # the client gets a generic, non-leaky message. Avoids exposing
        # internal details (file paths, library internals) in the response.
        log.exception("Failed to read upload")
        return jsonify({"error": "Could not read the uploaded file."}), 400

    try:
        result = _build_result(text, filename)
    except CSVParseError as exc:
        return jsonify({"error": str(exc)}), 422
    except Exception:
        log.exception("Analysis failed")
        return jsonify({"error": "Internal error while analyzing the file."}), 500

    sid = _session_id()
    _store_result(sid, result, filename)
    log.info(
        "Analyzed %s: %s valid / %s total rows, risk=%s (%s)",
        filename, result["validation"]["valid_rows"],
        result["validation"]["total_rows"],
        result["risk"]["score"], result["risk"]["threat_level"],
    )
    return jsonify(result)


@app.route("/api/export/json")
def export_json():
    entry = _get_result()
    if not entry or not entry["data"]:
        return jsonify({"error": "No analysis has been run yet."}), 404
    try:
        payload = json.dumps(entry["data"], indent=2, default=str)
    except Exception:
        log.exception("JSON export failed")
        return jsonify({"error": "Internal error while building the JSON export."}), 500
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinellog_analysis.json"},
    )


@app.route("/api/export/pdf")
def export_pdf():
    entry = _get_result()
    if not entry or not entry["data"]:
        return jsonify({"error": "No analysis has been run yet."}), 404
    data = entry["data"]
    try:
        pdf_bytes = build_pdf(
            data["stats"], data["risk"], data["findings"],
            data["report"], entry["filename"],
        )
    except Exception:
        # Defense-in-depth / consistency with api_analyze's error handling:
        # the known XSS/crash-causing inputs are already fixed and covered
        # by regression tests (see HARDENING_REPORT.md), but any other
        # unanticipated failure here should still return a clean JSON error
        # rather than Flask's default error page, and must never leak
        # internal details to the client.
        log.exception("PDF export failed")
        return jsonify({"error": "Internal error while building the PDF export."}), 500
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=SentinelLog_Report.pdf"},
    )


@app.route("/api/export/findings.csv")
def export_findings_csv():
    import csv
    import io as _io

    entry = _get_result()
    if not entry or not entry["data"]:
        return jsonify({"error": "No analysis has been run yet."}), 404
    findings = entry["data"]["findings"]
    try:
        buf = _io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "rule", "severity", "confidence", "affected", "record_count",
                         "description", "recommended_action",
                         "mitre_technique_id", "mitre_technique_name"])
        for f in findings:
            m = f.get("mitre") or {}
            writer.writerow([f["id"], f["rule"], f["severity"], f.get("confidence", ""),
                             _csv_safe(f["affected"]), f["record_count"], _csv_safe(f["description"]),
                             _csv_safe(f["recommended_action"]), m.get("technique_id", ""),
                             m.get("technique_name", "")])
    except Exception:
        log.exception("findings.csv export failed")
        return jsonify({"error": "Internal error while building the CSV export."}), 500
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinellog_findings.csv"},
    )


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "gemini_configured": bool(os.environ.get("GEMINI_API_KEY"))})


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB upload limit."}), 413


@app.errorhandler(404)
def not_found(_e):
    # Applies to any unmatched route (the static_files catch-all already
    # returns its own JSON 404 for known-missing frontend files; this is
    # the fallback for anything else, e.g. an unknown /api/... path).
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(_e):
    # Final safety net: any exception not already caught by a route's own
    # try/except (see api_analyze, export_json, export_pdf,
    # export_findings_csv) lands here instead of Flask's default HTML error
    # page. The real exception and traceback are in the server log only;
    # the client never sees internal details (file paths, library
    # internals, stack traces).
    log.exception("Unhandled exception")
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    log.info("SentinelLog backend starting on http://127.0.0.1:%s", port)
    app.run(host="127.0.0.1", port=port, debug=False)
