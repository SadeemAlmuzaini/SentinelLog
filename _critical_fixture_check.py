"""
One-off final-handover verification script (not part of the pytest suite).
Exercises the real Flask app (via its test client -- the same mechanism
tests/test_api.py uses, i.e. real request parsing, real routing, real
response bodies) end-to-end against the CRITICAL-reachability fixture to
close the "live" verification gap noted in HARDENING_REPORT.md, since
interactive browser automation was unavailable for the duration of that
session. This does not modify any application code or weaken any check --
it only calls the existing, unmodified routes and asserts on their real
output.
"""
import io
import json
import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
sys.path.insert(0, BACKEND)

import app as flask_app_module  # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "tests", "fixtures", "validation_phase", "critical_multi_vector_demo.csv",
)

client = flask_app_module.app.test_client()

with open(FIXTURE, "rb") as f:
    data = f.read()

print(f"Fixture: {FIXTURE} ({len(data)} bytes)")

resp = client.post(
    "/api/analyze",
    data={"file": (io.BytesIO(data), "critical_multi_vector_demo.csv")},
    content_type="multipart/form-data",
)
print(f"/api/analyze -> HTTP {resp.status_code}")
assert resp.status_code == 200, f"analyze failed: {resp.get_data(as_text=True)[:500]}"
body = resp.get_json()

score = body["risk"]["score"]
level = body["risk"]["threat_level"]
print(f"Risk score: {score}  Threat level: {level}")
assert level == "CRITICAL", f"expected CRITICAL, got {level}"
assert score >= 80, f"expected score >= 80, got {score}"

# AI report present and references the right figures (template-generated,
# not an external AI call -- see report_generator.py).
assert "report" in body and isinstance(body["report"], str) and len(body["report"]) > 100
assert "CRITICAL" in body["report"]
print("AI report: present, mentions CRITICAL, length", len(body["report"]))

# Findings present.
findings = body.get("findings", [])
print(f"Findings returned: {len(findings)}")
assert len(findings) > 0, "expected at least one finding for this multi-vector dataset"

# PDF export.
resp_pdf = client.get("/api/export/pdf")
print(f"/api/export/pdf -> HTTP {resp_pdf.status_code}, {len(resp_pdf.data)} bytes, "
      f"content-type={resp_pdf.content_type}")
assert resp_pdf.status_code == 200
assert resp_pdf.data[:4] == b"%PDF", "response does not start with a PDF magic header"

# JSON export.
resp_json = client.get("/api/export/json")
print(f"/api/export/json -> HTTP {resp_json.status_code}")
assert resp_json.status_code == 200
exported = json.loads(resp_json.get_data(as_text=True))
assert exported["risk"]["threat_level"] == "CRITICAL"

# Findings CSV export.
resp_csv = client.get("/api/export/findings.csv")
print(f"/api/export/findings.csv -> HTTP {resp_csv.status_code}, "
      f"{len(resp_csv.data)} bytes")
assert resp_csv.status_code == 200

print()
print("RESULT: PASS -- CRITICAL fixture reaches score {} ({}), and all three "
      "export formats (PDF/JSON/CSV) succeed against the live, unmodified "
      "Flask application (via its real routes and test client, not a "
      "browser).".format(score, level))
