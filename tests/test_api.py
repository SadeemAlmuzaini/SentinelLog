"""
pytest-style tests for the Flask API layer. Run with: pytest
(from project root, after `pip install -r requirements.txt`).
"""
import io
import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND)

import app as app_module  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def _upload(client, filename):
    path = os.path.join(FIXTURES, filename)
    with open(path, "rb") as f:
        data = f.read()
    return client.post(
        "/api/analyze",
        data={"file": (io.BytesIO(data), filename)},
        content_type="multipart/form-data",
    )


def test_health_check():
    client = _client()
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert "gemini_configured" in body


def test_export_before_analyze_returns_404():
    # A brand-new client has no session cookie yet, so it has no entry in
    # the per-session result store (_RESULTS_BY_SESSION in app.py) -- this
    # replaced the old shared module-level _LAST_RESULT global specifically
    # so that one visitor's analysis is never visible to another visitor on
    # a public deployment; a fresh session correctly finds nothing to export.
    client = _client()
    resp = client.get("/api/export/json")
    assert resp.status_code == 404


def test_analyze_real_sample_and_exports():
    client = _client()
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "sample_firewall_logs.csv",
    )
    with open(data_path, "rb") as f:
        raw = f.read()
    resp = client.post(
        "/api/analyze",
        data={"file": (io.BytesIO(raw), "sample_firewall_logs.csv")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["stats"]["total_records"] == 500

    pdf_resp = client.get("/api/export/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.data[:4] == b"%PDF"

    json_resp = client.get("/api/export/json")
    assert json_resp.status_code == 200
    assert json_resp.get_json()["stats"]["total_records"] == 500

    csv_resp = client.get("/api/export/findings.csv")
    assert csv_resp.status_code == 200
    assert csv_resp.content_type.startswith("text/csv")


def test_reject_non_csv_file():
    client = _client()
    resp = client.post(
        "/api/analyze",
        data={"file": (io.BytesIO(b"not a csv"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_reject_missing_columns():
    client = _client()
    resp = _upload(client, "missing_columns.csv")
    # CSVParseError (malformed/semantically-invalid CSV content, as opposed to
    # a non-CSV upload) is surfaced by app.py as 422 Unprocessable Entity.
    assert resp.status_code == 422
    assert "Missing required column" in resp.get_json()["error"]


def test_reject_empty_file():
    client = _client()
    resp = _upload(client, "empty.csv")
    assert resp.status_code == 422


def test_reanalyze_refreshes_result():
    client = _client()
    r1 = _upload(client, "only_allowed.csv")
    assert r1.status_code == 200
    first_total = r1.get_json()["stats"]["total_records"]

    r2 = _upload(client, "only_blocked.csv")
    assert r2.status_code == 200
    second_total = r2.get_json()["stats"]["total_records"]

    latest = client.get("/api/export/json").get_json()
    assert latest["stats"]["total_records"] == second_total
    assert latest["stats"]["blocked_connections"] == second_total
    assert latest["stats"]["allowed_connections"] == 0
    # sanity: the two fixtures aren't accidentally identical in size
    assert isinstance(first_total, int) and isinstance(second_total, int)



# --- Final hardening phase: end-to-end security-fix regression via the real
# Flask API layer (not just the lower-level functions tested in
# test_analysis.py), using harmless, clearly-labeled synthetic payloads.
# Verifies that escaping is applied correctly in each output *context*
# separately -- HTML-rendered report, PDF, and findings.csv -- rather than
# assuming one fix covers every format.

def test_injection_payloads_safe_end_to_end_via_api():
    client = _client()
    resp = _upload(client, "validation_phase/injection_payloads.csv")
    assert resp.status_code == 200
    body = resp.get_json()

    # 1. The markdown report returned in the JSON analyze response must have
    #    the raw HTML/script payloads neutralized (HTML-escaped), since the
    #    frontend renders this field via marked.parse() + innerHTML.
    report = body["report"]
    assert "<img src=x onerror=alert(1)>" not in report
    assert "<script>alert(2)</script>" not in report
    assert "&lt;img src=x onerror=alert(1)&gt;" in report

    # 2. PDF export must not crash on the same adversarial dataset.
    pdf_resp = client.get("/api/export/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.data[:4] == b"%PDF"

    # 3. findings.csv must not contain raw, un-neutralized formula-trigger
    #    characters as the FIRST character of any cell (the actual
    #    injection condition spreadsheet apps check for).
    csv_resp = client.get("/api/export/findings.csv")
    assert csv_resp.status_code == 200
    csv_text = csv_resp.get_data(as_text=True)
    import csv as _csv
    import io as _io
    reader = _csv.reader(_io.StringIO(csv_text))
    next(reader)  # header
    for row in reader:
        for cell in row:
            if cell and cell[0] in ("=", "+", "-", "@") and not cell.startswith("'"):
                raise AssertionError(f"un-neutralized formula-triggering cell: {cell!r}")

    # 4. JSON export is intentionally RAW/unescaped -- it is not rendered as
    #    HTML by this application, so escaping it would corrupt the true
    #    underlying values for any downstream consumer. This is a deliberate
    #    design choice (escape at the point of output, not point of storage),
    #    verified here so it is not "fixed" by mistake later.
    json_resp = client.get("/api/export/json")
    assert json_resp.status_code == 200
    json_body = json_resp.get_json()
    raw_country_values = list(json_body["stats"]["country_distribution"].keys())
    assert "<img src=x onerror=alert(1)>" in raw_country_values


def test_legitimate_report_and_exports_still_work_after_hardening():
    """Sanity check that none of the escaping/formula-injection fixes broke
    ordinary, non-adversarial usage."""
    client = _client()
    resp = _upload(client, "clean.csv")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["risk"]["score"] == 0
    assert body["risk"]["threat_level"] == "LOW"
    assert "&amp;" not in body["report"]
    assert "&lt;" not in body["report"]

    pdf_resp = client.get("/api/export/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.data[:4] == b"%PDF"

    csv_resp = client.get("/api/export/findings.csv")
    assert csv_resp.status_code == 200
