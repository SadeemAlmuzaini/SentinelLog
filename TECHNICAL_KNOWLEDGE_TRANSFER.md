# CyberSight AI — Complete Technical Audit and Knowledge Transfer

**Audit date:** 2026-10-24
**Folder inspected:** `CyberSight AI - Final Project` (sibling of the original `CyberSightAI-Frontend` folder; this audit did **not** read from `CyberSightAI-Frontend` or any `_backup_*` folder)
**Method:** Direct, read-only inspection of every source file listed below. No file was modified, created, deleted, renamed, or moved. No package was installed, no script was run, no server was started or stopped. Where a claim could not be verified from the code or from existing historical documents, this document says so explicitly rather than guessing.

---

## Part 1 — Project Overview

### What CyberSight AI does
CyberSight AI is a self-contained local web application that takes a firewall connection log (a CSV file) and produces, in a browser dashboard:
- A 0–100 **risk score** and a LOW/MEDIUM/HIGH/CRITICAL **threat level**.
- Traffic breakdown statistics (allowed vs. blocked, countries, protocols, ports, total bytes).
- A set of rule-based **suspicious-activity findings**, each with evidence, an affected entity, a recommended action, and (where applicable) a MITRE ATT&CK mapping.
- A **template-generated** (not AI-generated) written security report.
- Export of the result as PDF, JSON, and a findings CSV.

### Problem it solves / intended users
It is a teaching/portfolio project demonstrating firewall-log triage: turning a raw CSV of allow/block firewall events into a prioritized, explainable security summary a junior analyst or student could present. It is explicitly **not** a production SIEM, not a certified security tool, and (per its own report text) "does not constitute a penetration test or certified audit."

### Purpose, scope, and main features (as implemented today)
- Single-file CSV upload (drag-and-drop or file picker), `.csv` only, 15 MB cap.
- Server-side parsing, validation, and statistics computation.
- Eight rule-based detections (port scan, repeated blocks, sensitive-port exposure, elevated ICMP, concentrated destination traffic, high-volume source, rapid connection burst, unrecognized action values).
- A documented, deterministic 4-component risk-score formula (no machine learning, no external AI call).
- Five Chart.js visualizations, a findings list, and a markdown-rendered report in the browser.
- PDF / JSON / CSV export of the current in-memory result.
- All processing is in-memory per request; nothing is written to disk by the app itself, and no uploaded data is persisted between requests.

### Actual technologies and libraries used (verified from code — see Part 3 for full detail)
- **Backend:** Python 3 (tested against CPython 3.14 in this session), Flask, ReportLab, pytest. **No Pandas, no NumPy** — `analysis.py` uses only the Python standard library (`csv`, `io`, `collections.Counter`/`defaultdict`).
- **Frontend:** plain HTML5, CSS3 (no framework), vanilla JavaScript (no framework), Chart.js 4.4.1 and marked.js 15.0.12 (both loaded from CDN), Font Awesome 6.5.1 icons (CDN).
- **No Gemini, no LangGraph, no Google Colab, no Google Sheets, and no external AI API of any kind are used at runtime.** See Part 3 for the exact evidence.

### Complete architecture of the current implementation

```
                        ┌─────────────────────────────┐
                        │         Browser (UI)         │
                        │  frontend/index.html          │
                        │  frontend/style.css           │
                        │  frontend/script.js           │
                        │  (Chart.js, marked.js — CDN)  │
                        └───────────────┬───────────────┘
                                        │ fetch() — multipart/form-data
                                        │ POST /api/analyze
                                        ▼
                        ┌─────────────────────────────┐
                        │   Flask app (backend/app.py)  │
                        │   - routes / HTTP layer        │
                        │   - holds _LAST_RESULT in RAM  │
                        └───────────────┬───────────────┘
                                        │ calls, in order:
                ┌───────────────────────┼───────────────────────────┐
                ▼                       ▼                           ▼
   backend/validators.py   backend/analysis.py        backend/detection_engine.py
   (schema + row checks)   (parse → stats)             (findings + risk score)
                                        │                           │
                                        └─────────────┬─────────────┘
                                                      ▼
                                   backend/report_generator.py
                                   (markdown report, HTML-escaped)
                                                      │
                               ┌──────────────────────┼───────────────────────┐
                               ▼                      ▼                       ▼
                      JSON response to UI   backend/pdf_export.py    /api/export/findings.csv
                      (/api/analyze, and                              (built from _LAST_RESULT
                      /api/export/json)     (/api/export/pdf)          in app.py directly)
```

### End-to-end workflow (CSV upload → dashboard/findings/report/exports)

1. User opens `http://127.0.0.1:5000/` → Flask's `index()` route (`backend/app.py`) serves `frontend/index.html`.
2. User selects/drops a `.csv` file. `frontend/script.js`'s `fileInput` `change` listener stores the `File` object (`selectedCSVFile`) and shows its name/size — **no upload happens yet**.
3. User clicks **Analyze Logs**. `script.js` builds a `FormData` with the file under key `"file"` and does `fetch("/api/analyze", {method:"POST", body: formData})`.
4. `backend/app.py`'s `api_analyze()` route: validates a file is present and named `.csv`, reads the raw bytes, decodes as UTF-8 (falling back to Latin-1), then calls `_build_result(text, filename)`.
5. `_build_result()` calls, in order:
   a. `validators.resolve_schema()` + `validators.validate_row()` (via `analysis.parse_and_validate_csv()`) — maps column aliases, rejects rows that fail hard checks, keeps a list of clean rows plus rejection/warning reasons.
   b. `analysis.compute_statistics(rows)` — builds the full statistics object (counts, distributions, top-N lists, and several **uncapped** aggregates reserved for detection logic).
   c. `detection_engine.run_detections(stats, total_records)` — runs the 8 detection rules, returns a sorted list of findings.
   d. `detection_engine.compute_risk_score(stats, findings, total_records)` — computes the 0–100 score and threat level from 4 weighted components.
   e. `report_generator.generate_report(stats, risk, findings, validation)` — builds the markdown report text, HTML-escaping any CSV-derived text.
6. `app.py` stores the whole result dict in the module-level `_LAST_RESULT` (in-memory only, overwritten by the next analysis) and returns it as JSON.
7. `script.js`'s `renderAll(body)` runs: `updateDashboard()` fills the 8 stat cards, five `createXChart()` functions (re)build the Chart.js charts, `renderFindings()` builds the finding cards (escaping every field with `escapeHtml()`), and `aiReport.innerHTML = marked.parse(result.report)` renders the markdown report client-side.
8. Clicking **Download PDF / Export JSON / Export Findings CSV** opens `/api/export/pdf`, `/api/export/json`, or `/api/export/findings.csv` in a new tab. Each route reads from `_LAST_RESULT` (404 if nothing has been analyzed yet in this server process) and streams back the corresponding file with a `Content-Disposition: attachment` header.

---

## Part 2 — Complete File and Folder Inventory

Inspected with the project's own `venv/` excluded (environment material, not source). All paths are relative to `CyberSight AI - Final Project/`.

| Path | Purpose | Contains | Used by app? | Depended on by | Essential to run? | Category |
|---|---|---|---|---|---|---|
| `backend/app.py` | Flask application entry point, HTTP routing, in-memory result cache | Routes `/`, static file serving, `/api/analyze`, `/api/export/{json,pdf,findings.csv}`, `/api/health`, error handlers | Yes | `run.bat`, all backend modules it imports | Yes | Source code |
| `backend/validators.py` | CSV schema resolution + per-row validation | `REQUIRED_COLUMNS`, `COLUMN_ALIASES`, `resolve_schema()`, `validate_row()` | Yes (imported by `analysis.py`) | `analysis.py` | Yes | Source code |
| `backend/analysis.py` | CSV parsing orchestration + statistics engine | `parse_and_validate_csv()`, `compute_statistics()`, `CSVParseError` | Yes (imported by `app.py`) | `app.py`, `tests/test_analysis.py` | Yes | Source code |
| `backend/detection_engine.py` | Rule-based findings + risk-score calculation | 8 detection rules, `run_detections()`, `compute_risk_score()`, `_threat_level()`, MITRE reference table | Yes (imported by `app.py`) | `app.py`, `tests/test_analysis.py` | Yes | Source code |
| `backend/report_generator.py` | Builds the markdown security report | `generate_report()`, HTML-escaping helper `_esc()` | Yes (imported by `app.py`) | `app.py` | Yes | Source code |
| `backend/pdf_export.py` | Builds the PDF export from the current result | `build_pdf()` using ReportLab `SimpleDocTemplate` | Yes (imported by `app.py`, only when `/api/export/pdf` is called) | `app.py` | Yes (for PDF export only) | Source code |
| `backend/__pycache__/` | Python bytecode cache | Compiled `.pyc` files | N/A — auto-generated, not source | — | No | Environment/cache material |
| `frontend/index.html` | Page structure/markup | Nav, upload card, dashboard cards, chart canvases, findings container, report container, script/style tags | Yes (served by `app.py`'s `index()`) | `style.css`, `script.js`, CDN libs | Yes | Source code |
| `frontend/style.css` | Visual design system (dark SOC dashboard theme) | CSS custom properties, layout, component styling, 3 responsive breakpoints | Yes | `index.html` | Yes (for intended appearance) | Source code |
| `frontend/script.js` | Client-side logic | File selection, `/api/analyze` call, chart creation (5 charts), findings rendering, export buttons | Yes | `index.html` | Yes | Source code |
| `tests/test_analysis.py` | Unit tests for the analysis/detection/risk-score logic (no Flask) | 35 `test_*` functions | Not used at runtime | pytest, imports `backend/*` directly | No (test-only) | Test code |
| `tests/test_api.py` | Integration tests through the real Flask API layer | 9 `test_*` functions, uses `app.test_client()` | Not used at runtime | pytest, `backend/app.py` | No (test-only) | Test code |
| `tests/fixtures/*.csv` (18 files) | Hand-crafted CSVs for unit tests (empty, malformed, boundary cases, etc.) | Small synthetic logs | Not used at runtime | `tests/test_analysis.py`, `tests/test_api.py` | No (test-only) | Test data |
| `tests/fixtures/validation_phase/*.csv` (12 files) | Security/false-positive/boundary validation fixtures (injection payloads, exact threshold boundaries, legitimate-but-noisy traffic) | Synthetic logs targeting specific edge cases | Not used at runtime | `tests/test_analysis.py`, `tests/test_api.py`, `_critical_fixture_check.py` | No (test-only) | Test data |
| `tests/__pycache__/` | pytest bytecode cache | Compiled test `.pyc` files | N/A | — | No | Environment/cache material |
| `data/sample_firewall_logs.csv` | Ready-to-use demo log (500 rows) | Realistic sample firewall log matching the app's schema | Not read automatically by the app; a user manually uploads it through the UI | Referenced by `README.md`, `tests/test_api.py` (`test_analyze_real_sample_and_exports`), `test_analysis.py` (`test_real_sample_matches_known_values`) | No (convenience only) | Test/demo data |
| `reference/CyberSight_AI_Project_Handover.docx` | **Historical** — the original pre-engagement handover document describing the Colab/Gemini/LangGraph architecture that preceded the current Flask implementation | Original architecture, file structure, JSON schema, chart plan, a specific bug report, and working-preference notes | No — not read by the running application | — | No | Documentation (historical only) |
| `reference/CyberSight_AI_Report.pdf` | **Historical** — a sample PDF report from the earlier (Gemini-based) prototype, kept for comparison | An earlier-format PDF report over the same 500-row sample | No | — | No | Documentation (historical only) |
| `reference/analysis_result.json` | **Historical** — the static JSON result file the original Colab-based workflow produced | Old flat schema: `risk_score`, `threat_level`, `action_distribution`, `langgraph_statistics`/`langgraph_risk`/`langgraph_recommendations`, `ai_report` | No — the current app computes its own result in-memory per request; it does not read this file | — | No | Documentation (historical only) |
| `requirements.txt` | Pinned Python dependencies | `Flask>=3.0`, `reportlab>=4.0`, `pytest>=8.0` | Yes — installed by `run.bat`/manually | `run.bat` | Yes | Configuration |
| `run.bat` | One-click Windows launcher | Creates/activates `venv`, installs `requirements.txt`, runs `python backend\app.py` | Yes (operator-run, not imported by app code) | — | Yes (for the documented launch path) | Configuration/script |
| `.env.example` | Template for optional environment variables | `GEMINI_API_KEY=` (documented as optional/future, unused today — see Part 3), `PORT=5000` | Only `PORT` is actually read (`os.environ.get("PORT", 5000)` in `app.py`); `GEMINI_API_KEY` is only read by the `/api/health` check, nowhere else | — | No (defaults work without it) | Configuration |
| `.gitignore` | Git ignore rules | Excludes `__pycache__/`, `venv/`, `.env`, logs, `.pytest_cache/`, and `_backup_*/` | N/A | — | No | Configuration |
| `README.md` | Operator-facing run/setup instructions for this folder | How to run, test, and the architecture notes | No (documentation, not imported) | — | No (documentation) | Documentation |
| `FINAL_HANDOVER_REPORT.md` | Record of this folder's prior independent verification session (dependency install, test run, live browser verification, and the later process-lock/rebuild safety checks) | Verification results, file inclusion/exclusion list, launch instructions, known-remaining-items | No | — | No | Documentation |
| `_critical_fixture_check.py` | Standalone one-off verification script (not part of pytest) | Runs the CRITICAL fixture through the real Flask test client and prints the result | Not used by the running app; a manual verification aid | — | No | Documentation/verification tooling |
| `venv/` | Python virtual environment for this folder | Python interpreter copy + installed packages (Flask, reportlab, pytest and their dependencies) | Yes, to run the app | `run.bat` activates it | Yes (or an equivalent environment) | Environment material (excluded from this audit's content inspection per instruction; listed for completeness) |

**Note:** `TECHNICAL_KNOWLEDGE_TRANSFER.md` (this document) did not exist in the folder prior to this audit (verified before writing) and is being added as a new file, per the instructions, without overwriting anything.

---

## Part 3 — Technologies Actually Used

| Technology | What it is | Why this project needs it | Files that use it | What it does here | Required at |
|---|---|---|---|---|---|
| **Python 3** | General-purpose language | Runs the entire backend | All `backend/*.py`, `tests/*.py`, `_critical_fixture_check.py` | Everything server-side | Runtime, dev, test |
| **Flask** | Micro web framework | Serves the frontend and the JSON API | `backend/app.py` | Routing, request/response handling, static file serving, error handlers | Runtime |
| **ReportLab** | Pure-Python PDF generation library | Produces the downloadable PDF report without needing system-level PDF libraries | `backend/pdf_export.py` | Builds a `SimpleDocTemplate` with a summary table, findings, and the full report text | Runtime (only when `/api/export/pdf` is called) |
| **pytest** | Testing framework | Runs the 44-test automated suite | `tests/test_analysis.py`, `tests/test_api.py` | Test discovery, fixtures, assertions | Dev/test only |
| **HTML5** | Markup | Page structure | `frontend/index.html` | Defines the dashboard, upload UI, chart canvases | Runtime (client) |
| **CSS3** | Styling | Visual design | `frontend/style.css` | Dark theme, layout, responsive breakpoints at 980px/640px/420px | Runtime (client) |
| **JavaScript (vanilla, ES2017+)** | Client scripting | Drives all client-side interactivity | `frontend/script.js` | Upload handling, API calls, DOM updates, chart creation, escaping | Runtime (client) |
| **Chart.js 4.4.1** | Charting library (CDN: `cdnjs.cloudflare.com`) | Renders the 5 analytics charts | `frontend/index.html` (script tag), `frontend/script.js` | Bar, doughnut, and line charts | Runtime (client) |
| **marked.js 15.0.12** | Markdown-to-HTML renderer (CDN: `cdn.jsdelivr.net`) | Converts the server's markdown report text into HTML for display | `frontend/index.html` (script tag), `frontend/script.js` (`marked.parse(result.report)`) | Client-side markdown rendering | Runtime (client) |
| **Font Awesome 6.5.1** | Icon font (CDN: `cdnjs.cloudflare.com`) | UI icons throughout the dashboard | `frontend/index.html` | Icons only, no logic | Runtime (client) |

**Explicitly verified NOT present at runtime (per the task's specific question):**
- **Pandas / NumPy:** Not imported anywhere in `backend/`. `analysis.py`'s own docstring and code show it is built on the Python standard library (`csv`, `io`, `collections`) instead. The *original* (historical) architecture in `reference/CyberSight_AI_Project_Handover.docx` did use Pandas/NumPy in a Google Colab notebook — that code is not part of this folder.
- **Gemini:** Searched all source files (`grep -ril "gemini"` across `backend/`, `frontend/`, `requirements.txt`, `run.bat`, `README.md`). Only two mentions exist, and neither calls Gemini:
  - `backend/app.py`'s `/api/health` route: `"gemini_configured": bool(os.environ.get("GEMINI_API_KEY"))` — this only reports whether an environment variable happens to be set; it never sends a request to any Gemini/Google API.
  - `backend/report_generator.py`'s module docstring: *"No external AI call is made here... If Gemini integration is later enabled (see app.py), that code path is responsible for its own disclosure; this function must never claim AI involvement that didn't happen."* — this is explicit documentation that Gemini integration is **not implemented**, only reserved as a possible future addition.
  - `.env.example` documents `GEMINI_API_KEY=` as "Optional: enables a future/optional AI-enhanced report pass... Leave empty or unset to keep the app fully offline." This confirms it as an unimplemented placeholder, not a working feature.
  - No `google-generativeai`, `google.genai`, or any Gemini/Google AI package appears in `requirements.txt` or anywhere in the installed `venv` package list observed during this session's earlier environment rebuild.
- **LangGraph:** No occurrence anywhere in `backend/`, `frontend/`, `requirements.txt`, or `run.bat`. It appears only in the historical `reference/CyberSight_AI_Project_Handover.docx`, describing the earlier Colab-based design (`"langgraph_statistics"`, `"langgraph_risk"`, `"langgraph_recommendations"` keys in the old `analysis_result.json` schema). It is not part of the current implementation.
- **Google Colab:** Referenced only in the historical handover document as the *original* development environment; the current Flask app runs as a normal local Python process, not inside a notebook.
- **Google Sheets:** No occurrence found anywhere in the codebase or the historical document. Not used, planned, or referenced.
- **Any other external AI API** (OpenAI, Anthropic, etc.): No occurrence anywhere in the inspected files.

**Conclusion for Part 3:** the application's "AI Report" is, per its own UI label and its own generator code, a **template-generated, deterministic report** — not the output of any AI model, local or remote.

---

## Part 4 — Backend Walkthrough (Execution Order)

### 4.1 Flask application initialization (`backend/app.py`)
```python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
...
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES   # 15 MB
_LAST_RESULT = {"data": None, "filename": None}
```
- `static_folder=None` disables Flask's default static handling; static files are instead served manually via the `static_files()` catch-all route below, which path-restricts requests to inside `FRONTEND_DIR` (`if not target.startswith(safe_root): return 404`) — this prevents path traversal.
- `BASE_DIR`/`PROJECT_ROOT`/`FRONTEND_DIR` are derived purely from the file's own location on disk, so the app has no hardcoded dependency on any specific folder path or name (verified by inspection — no absolute paths or references to `CyberSightAI-Frontend` appear anywhere in `backend/`).
- `_LAST_RESULT` is a plain in-process dict holding the most recent analysis. It is **not** a database, not a file, and not per-session — it is shared by the whole Flask process, and is **overwritten** by every new `/api/analyze` call (verified by `tests/test_api.py::test_reanalyze_refreshes_result`).

### 4.2 API endpoints and HTTP methods
| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Serves `frontend/index.html` |
| `/<path:filename>` | GET | Serves other frontend static files (`style.css`, `script.js`), path-restricted to `FRONTEND_DIR` |
| `/api/analyze` | POST | Accepts a CSV upload, runs the full pipeline, returns JSON, updates `_LAST_RESULT` |
| `/api/export/json` | GET | Returns `_LAST_RESULT` as a downloadable `.json` file (404 if nothing analyzed yet) |
| `/api/export/pdf` | GET | Builds and returns a PDF from `_LAST_RESULT` (404 if nothing analyzed yet) |
| `/api/export/findings.csv` | GET | Returns the findings as a downloadable CSV (404 if nothing analyzed yet) |
| `/api/health` | GET | Returns `{"status": "ok", "gemini_configured": <bool>}` |

### 4.3 CSV upload and validation
`api_analyze()` (app.py) → checks `"file" in request.files`, non-empty filename, `.csv` extension → reads raw bytes, decodes as `utf-8-sig` (to transparently strip a BOM if present) with a `latin-1` fallback on decode failure → calls `_build_result()`.

`analysis.parse_and_validate_csv(file_text)`:
```python
if file_text is None or not file_text.strip():
    raise CSVParseError("The file is empty.")
reader = csv.DictReader(io.StringIO(file_text))
if reader.fieldnames is None:
    raise CSVParseError("Could not read a header row from this file.")
mapping, missing, unmapped = resolve_schema(reader.fieldnames)
if missing:
    raise CSVParseError("Missing required column(s): " + ...)
```
Then every row is passed to `validators.validate_row()`. A row is **hard-rejected** (excluded from the dataset, counted in `rejected_rows`, reason recorded) only if `Action` is unparseable/missing or `Destination_Port` is invalid/missing. Other issues (bad `Timestamp`, invalid IP format, invalid `Source_Port`, negative/invalid `Bytes`) are recorded as a **warning** but the row is still kept with the offending field set to `None`/default, so one malformed field doesn't discard an otherwise-usable row. `MAX_ROWS = 200_000` caps processing; rows beyond that are rejected with a specific reason rather than the server hanging or erroring.

### 4.4 Data cleaning and analysis (`analysis.compute_statistics`)
Iterates the clean rows once, building:
- Simple counters: allowed/blocked/unrecognized-action counts, unique source/destination IP counts, country/protocol/port counts, total bytes, average bytes/record.
- Distributions: `country_distribution`, `protocol_distribution`, `protocol_bytes`.
- **Capped "top-10" lists** for chart/UI display (`top_destination_ports`, `top_source_ips`, `top_destination_ips`, `top_blocked_source_ips`).
- **Uncapped aggregates reserved specifically for detection logic**, called out in the function's own docstring: `destination_port_counts`, `destination_port_action_counts`, `source_to_ports`, `dest_hit_counts`, `blocked_source_ip_counts`, `blocked_source_to_ports`, `source_ip_timestamps`. The docstring explicitly warns that detection code must use these, not the capped top-10 fields, "a high-risk port that isn't in the top 10 by volume would otherwise be invisible to detection."
- `hourly_traffic_bytes`: an array of 6 buckets (4-hour windows) built from each row's parsed timestamp hour, used by the "Traffic Over Time" chart.
- `source_ip_timestamps` is capped at `MAX_TIMESTAMPS_PER_SOURCE = 2000` per source IP — a documented memory bound that "does not lose any detection signal in practice for this project's scope," since a source already past 2000 events is high-volume regardless.

### 4.5 Risk-score calculation — exact formula and thresholds
From `detection_engine.py`'s own documented formula:
```
score = round(min(100,
            block_rate            * 40 +
            high_risk_port_ratio  * 30 +
            icmp_ratio            * 15 +
            scan_findings_weight  * 15
        ))
```
- `block_rate` = blocked_connections / total_records
- `high_risk_port_ratio` = (ALLOWED connections hitting a `HIGH_RISK_PORTS` port) / allowed_connections (0 if there are no allowed connections at all — avoids divide-by-zero, and is a deliberate, documented fix over an earlier version that divided by `total_records`, which made the CRITICAL band effectively unreachable — see the long "Revision note" inside the module docstring, and the regression test `test_high_risk_port_ratio_denominator_is_allowed_not_total` in `tests/test_analysis.py`)
- `icmp_ratio` = ICMP records / total_records
- `scan_findings_weight` = min(1, distinct "affected" entities behind HIGH/CRITICAL findings / 3) — counts unique affected entities, not raw finding count, so one noisy source tripping several rules isn't weighted multiple times

Threshold mapping (`_threat_level()`, verified exactly in `tests/test_analysis.py::test_threat_level_boundaries_exact`):
```
0-29   LOW
30-54  MEDIUM
55-79  HIGH
80-100 CRITICAL
```
With `total_records == 0`, the score is defined as `0` (LOW) rather than raising a division error.

### 4.6 Suspicious-activity detection rules (`detection_engine.run_detections`)
All 8 rules, each producing zero or more findings with `severity`, `confidence`, `description`, `evidence`, `affected`, `record_count`, `rationale`, `recommended_action`, `next_steps`, `limitations`, and an optional `mitre` object:

1. **Potential Port Scan** — a source IP touching ≥15 distinct destination ports (`PORT_SCAN_THRESHOLD`); severity escalates to HIGH at ≥30. MITRE: Reconnaissance, T1595.001.
2. **Repeated Blocked Connections** — a source IP blocked ≥10 times (`REPEATED_BLOCK_THRESHOLD`); if any of the blocked ports are in `AUTH_PORTS` (login-oriented services: FTP, SSH, Telnet, MSSQL, Oracle, MySQL, RDP, PostgreSQL, VNC, Redis), it's mapped to MITRE T1110 (Brute Force) at MEDIUM confidence; otherwise no MITRE mapping and LOW confidence.
3. **Exposure of Sensitive Administrative Ports** — any traffic to a `HIGH_RISK_PORTS` port (FTP, SSH, Telnet, SMTP, MS-RPC, NetBIOS, SMB, MSSQL, Oracle, MySQL, RDP, PostgreSQL, VNC, Redis). If any of it was **ALLOWED**, severity is HIGH (if allowed-ratio > 5% of all records) or MEDIUM, with MITRE T1133 (External Remote Services); if only **BLOCKED**, severity is LOW with no MITRE mapping (denied interest, not confirmed exposure).
4. **Elevated ICMP Volume** — ICMP > 25% of total records (`ICMP_RATIO_THRESHOLD`). MITRE: Reconnaissance, T1595.001 (the rationale quotes the official technique description mentioning ICMP ping sweeps).
5. **Concentrated Traffic to Single Destination** — one destination IP receiving ≥20 connections (`HOT_DESTINATION_THRESHOLD`). No MITRE mapping.
6. **High-Volume Source** — only evaluated when `total_records >= 20`; a source IP responsible for ≥20% of all records. No MITRE mapping.
7. **Rapid Connection Burst** — only when the dataset has valid timestamps; a sliding-window check (`_max_events_in_window`, a two-pointer/left-right window algorithm) for ≥15 events from one source within any 60-second window. No MITRE mapping.
8. **Unrecognized Action Values** — a data-quality note (not a security finding) when rows had an `Action` value outside the recognized ALLOW/BLOCK vocabulary.

Findings are then sorted descending by severity (`findings.sort(key=lambda f: -_severity_rank(f["severity"]))`).

### 4.7 Severity, confidence, and MITRE mappings — and their limitations
The module docstring is explicit about the distinction: **severity** = how impactful the finding would be if the interpretation holds; **confidence** = how certain the interpretation itself is, "given only a firewall connection log (no auth logs, no endpoint telemetry, no packet payloads)." MITRE associations are described as "behavioral pattern matches against the technique's documented indicators, not confirmed technique usage," and are explicitly left unmapped (`mitre=None`) where the evidence doesn't reasonably support a specific technique (Rules 5, 6, 7, and Rule 2 when no auth port was hit).

### 4.8 Report generation (`report_generator.generate_report`)
Builds a markdown string in a fixed section order: Executive Summary → Risk Score and Threat Level → Dataset Overview → Suspicious Activity Findings (HIGH/CRITICAL first) → Defensive Recommendations → Data Quality & Limitations → Overall Assessment. Every piece of text that originates from the uploaded CSV (country names, finding evidence/descriptions that embed raw field values, unmapped column names) is passed through `_esc()`, which is `html.escape(str(value), quote=True)` — documented explicitly as the point that must neutralize HTML/script content before the frontend renders this text via `marked.parse()` + `innerHTML`.

### 4.9 PDF, JSON, and findings CSV exports
- **PDF** (`pdf_export.build_pdf`): ReportLab `SimpleDocTemplate` with a title, a summary metrics table, a findings section (escaped via `_xml_escape`), and the full report text (stripped of markdown syntax by a small regex-based `_markdown_to_plain()` and split into paragraphs). Built fresh from the current `_LAST_RESULT` every time — "never a stale fixed file," per its own docstring.
- **JSON** (`/api/export/json` in `app.py`): `json.dumps(_LAST_RESULT["data"], indent=2, default=str)` — this is the **raw, unescaped** result (see security note in Part 8 — this is intentional).
- **Findings CSV** (`/api/export/findings.csv` in `app.py`): built with Python's `csv.writer`; each untrusted text field is passed through `_csv_safe()` first (see Part 8).

### 4.10 Security protections implemented (summarized here, detailed in Part 8)
`_safe_filename()` (sanitizes upload filename), `MAX_CONTENT_LENGTH` (15 MB cap, 413 handler), the `static_files()` path-containment check, generic error messages with real exceptions logged server-side only (`log.exception(...)` + a plain client-facing message), and the HTML/CSV escaping described above.

### Tracing one uploaded CSV through the real code
Using the sample used in this session's own earlier live verification (20 synthetic rows uploaded through the real browser UI): `script.js` → `POST /api/analyze` → `app.api_analyze()` → `analysis.parse_and_validate_csv()` (20/20 rows accepted) → `analysis.compute_statistics()` → `detection_engine.run_detections()` (one finding fired: "Exposure of Sensitive Administrative Ports", HIGH, T1133) → `detection_engine.compute_risk_score()` (score 18, LOW) → `report_generator.generate_report()` → JSON returned → `script.js` renders dashboard/charts/findings/report → user downloads PDF/JSON/CSV, each hitting its export route against the same `_LAST_RESULT`. This exact trace was independently observed running in this folder earlier in this session (see `FINAL_HANDOVER_REPORT.md`), and this audit separately re-confirms it is what the current source code implements.

---

## Part 5 — Frontend Walkthrough

### HTML page structure (`frontend/index.html`)
A fixed `<nav>` with three in-page anchor links (`#dashboard`, `#charts`, `#report`), a page-intro header, an upload card (`<label for="logFile">` wrapping a hidden `<input type="file" id="logFile" accept=".csv">` plus an "Analyze Logs" `<button>`), a `#dashboard` section with 8 `.stat-card` elements (each with a `data-metric` attribute and a `.card-value` span with a specific `id`), a `#charts` section with 5 `<canvas>` elements, a `#findings-section` with an empty `#findingsList` container, and a `#report` section with `#aiReport` plus 3 export buttons. CDN script tags for `marked` and `Chart.js` are loaded before the local `script.js`.

### CSS styling and responsive layout (`frontend/style.css`)
A CSS-custom-property-driven dark theme (`:root` defines background, surface, border, text, and accent colors as variables). Uses CSS Grid/Flexbox for the stat-card grid and chart grid. Three responsive breakpoints are defined: `@media (max-width: 980px)`, `640px`, and `420px`. Severity-specific left-border colors are defined for finding cards (`.finding-card.severity-{critical,high,medium,low}`).

### JavaScript initialization and event handlers (`frontend/script.js`)
On script load: grabs every needed DOM element by `id`, sets `Chart.defaults` globally (font, colors, tooltip styling) to match the dark theme, and defines a shared `COLORS`/`COUNTRY_PALETTE` object. Two event listeners are attached: `fileInput`'s `change` (stores the selected file, updates the status text — no network call) and `analyzeButton`'s `click` (the actual upload/analyze flow). Three more listeners are attached to the export buttons.

### CSV file selection and upload
Selecting a file only updates local UI state (`selectedCSVFile`, filename/size display, status text). The actual upload happens only on the "Analyze Logs" click, via a `FormData` POST to `/api/analyze`.

### Requests sent to Flask endpoints
`POST /api/analyze` (upload), `GET /api/export/pdf`, `GET /api/export/json`, `GET /api/export/findings.csv` (each opened in a new tab via `window.open(...)`, which triggers the browser's native file-download/attachment handling because of the server's `Content-Disposition: attachment` header).

### How the returned data updates dashboard metrics and charts
`renderAll(result)` is the single entry point called after a successful analyze response: it calls `updateDashboard()` (fills the 8 stat-card values and applies a LOW/MEDIUM/HIGH/CRITICAL CSS class via `updateThreatColor()`), then 5 separate `createXChart(stats)` functions (each destroys any previous Chart.js instance before creating a new one, so re-analyzing doesn't leak chart instances), then `renderFindings(result.findings)`, then sets `aiReport.innerHTML = marked.parse(result.report)`.

### How findings and the report are rendered
`renderFindings()` builds one `.finding-card` per finding via template-literal `innerHTML`, but **every dynamic value is passed through a local `escapeHtml()` helper first** (a `div.textContent = value; return div.innerHTML` idiom) — this is the frontend's own defense-in-depth layer, independent of the backend's own HTML-escaping of the report text. Secondary details ("Why it matters" / "Limitations" / next-step text) are placed inside a native `<details>`/`<summary>` disclosure so the card stays compact by default.

### How each export button works
Each of the three export buttons first checks a local `hasAnalysis` boolean (set `true` only after a successful `/api/analyze` response) and shows an error status if nothing has been analyzed yet; otherwise it calls `window.open()` on the relevant export URL.

### How errors and loading states are handled
During analysis, the button is disabled (`analyzeButton.disabled = true`) and the status area shows an "Uploading and analyzing..." message; on failure, `fetch`'s rejected/caught error (or a non-OK response's `error` field) is shown via `setStatus(..., "error")` and logged to `console.error`. Rejected/warned-about rows from a partially-valid upload are summarized in the status line and logged in full to the browser console (`console.warn`) rather than shown inline, matching the backend's per-row warning behavior.

### Python vs. JavaScript division of labor
**Everything computed is done in Python** (parsing, validation, statistics, detection rules, risk score, report text). **JavaScript does no analysis of its own** — it only renders what the backend already computed: it builds chart data structures directly from `stats.*` fields returned by the API, assembles finding-card HTML from the findings array, and renders the already-built markdown report string. The only "calculation" done client-side is cosmetic (e.g., formatting bytes to MB for the stat-card display, `toFixed()` calls, and chart bucket-to-MB conversion for display).

---

## Part 6 — Data and Cybersecurity Logic

### CSV schema
**Required columns** (`validators.REQUIRED_COLUMNS`): `Timestamp`, `Source_IP`, `Destination_IP`, `Source_Port`, `Destination_Port`, `Protocol`, `Action`, `Country`, `Bytes`. A generous alias table (`COLUMN_ALIASES`) auto-maps common variant header names (e.g. `src_ip`, `dst_port`, `verdict`, `geo_country`, `byte_count`) to the canonical names, case/whitespace/punctuation tolerant via `_normalize_header()`. If any required column (after alias resolution) is still missing, the whole upload is rejected with a `CSVParseError` (HTTP 422) listing exactly which columns are missing.

### Expected data types / accepted values
- `Timestamp`: parsed against `"%Y-%m-%d %H:%M:%S"`, `"%Y-%m-%dT%H:%M:%S"`, or `"%Y-%m-%d %H:%M"`; anything else is a validation error on that row (but does not hard-reject the row).
- `Source_IP` / `Destination_IP`: validated with Python's `ipaddress.ip_address()` (accepts both IPv4 and IPv6); an invalid value is flagged but the row is still kept (with that field effectively treated as absent for aggregate purposes, since it's not added to the IP sets, though it is kept as raw text for the raw CSV export).
- `Source_Port` / `Destination_Port`: must match `^\d+$` and be in `0..65535`. **`Destination_Port` is one of only two hard-reject conditions** — a row with no valid `Destination_Port` is excluded from the dataset entirely.
- `Protocol`: free text, upper-cased; **no enforced vocabulary** — `VALID_PROTOCOLS = {"TCP","UDP","ICMP"}` is defined in `validators.py` but, on inspection, is not actually referenced by `validate_row()` — any string is accepted and upper-cased (this means `Protocol` is *not* actually restricted to TCP/UDP/ICMP despite the constant's name — see "false negative" note below).
- `Action`: normalized against `ALLOW_VALUES`/`BLOCK_VALUES` (ALLOW/ALLOWED/PERMIT/PERMITTED/ACCEPT/ACCEPTED → `"ALLOW"`; BLOCK/BLOCKED/DENY/DENIED/DROP/DROPPED/REJECT/REJECTED → `"BLOCK"`); any other non-empty value becomes `"UNKNOWN"` and is counted separately (not silently folded into ALLOW or BLOCK — a deliberate design choice stated in the module docstring). **Missing `Action` is the other hard-reject condition.**
- `Country`: free text; empty becomes `"Unknown"`.
- `Bytes`: parsed as `int(float(bytes_raw))`; negative or unparseable values are flagged (row kept, `Bytes` treated as `0` for that row).

### Missing-value and malformed-row handling
Two-tier handling, by design (see `validators.py` docstring): a row is **hard-rejected** (excluded, reason logged in `rejected_reasons`, capped at 25 shown) only for a missing/invalid `Action` or a missing/invalid `Destination_Port`. Every other field-level problem is a **soft warning** (row kept, issue noted in `warnings`, capped at 25 shown) — the row still contributes to totals with the problem field nulled/defaulted.

### Allowed vs. blocked connections
Determined purely by the normalized `Action` value as described above; `"UNKNOWN"` actions are tracked separately in `unrecognized_action_count` and excluded from both the allowed and blocked totals (and therefore from `block_rate` in the risk formula).

### Protocols, countries, ports, IPs, timestamps
Handled as described above; ports feed both the capped "top 10" chart data and the uncapped aggregates used for detection (Part 4.4); timestamps feed the hourly traffic-over-time chart and the burst-detection sliding window.

### Exact suspicious-activity detection rules
See Part 4.6 for the full list of all 8 rules with their thresholds.

### Risk score — exact calculation and interpretation
See Part 4.5. In interpretation terms: `block_rate` rewards datasets with a lot of denied traffic (classic "under attack and successfully defended" signal); `high_risk_port_ratio` specifically rewards/punishes *actual exposure* (sensitive ports that were let through); `icmp_ratio` is a reconnaissance-volume signal; `scan_findings_weight` adds corroboration from the rule-based findings themselves, capped so a single noisy entity can't dominate the score.

### What each finding means
Each finding object directly carries its own `description` (what was observed), `evidence` (the specific numbers/values backing it), `affected` (the entity — usually a source or destination IP, sometimes "network-wide" or "multiple sources"), `record_count`, `rationale` ("why this matters"), `recommended_action`, `next_steps` (a suggested manual-verification step), and `limitations` (an explicit false-positive caveat specific to that rule).

### Observed indicator vs. suspicious pattern vs. confirmed malicious activity
This distinction is explicit in the code's own design, not something this audit is inferring:
- An **observed indicator** is a raw fact from the log (e.g., "ALLOW traffic to port 3389 occurred").
- A **suspicious pattern** is what a detection rule flags when an indicator crosses a threshold (e.g., ≥15 distinct ports from one source → "Potential Port Scan"). Each pattern carries its own stated `confidence`, reflecting how certain that interpretation is.
- **Confirmed malicious activity** is explicitly *never* claimed anywhere in the codebase. The module docstring states the analyzer "has no authentication logs, no endpoint/process telemetry, and no packet payload visibility. It can observe that traffic was attempted/allowed/blocked... it cannot confirm that any attempt succeeded, that credentials were used, or that a host was compromised." Every MITRE mapping is explicitly labeled "(behavioral association, not confirmed adversary activity)" in both the UI and the generated report/PDF.

### Potential false positives (explicitly acknowledged in the code's own `limitations` text per rule)
- Port Scan: a legitimate vulnerability scanner or load-balancer health-checker.
- Repeated Blocked Connections: a misconfigured legitimate client retrying a failed connection.
- Exposure of Sensitive Administrative Ports: presence of traffic doesn't confirm the service version or that any connection succeeded at the application layer.
- Elevated ICMP Volume: legitimate diagnostics/monitoring (path MTU discovery, uptime checks).
- Concentrated Traffic to Single Destination: a popular legitimate service, gateway, or load balancer.
- High-Volume Source: internal gateways/proxies/NAT devices routinely produce this pattern.
- Rapid Connection Burst: a legitimate retry storm, batch job, or monitoring probe; also sensitive to the source log's timestamp precision.

### Potential false negatives (identified by this audit from reading the code, not stated verbatim in the code itself)
- `VALID_PROTOCOLS` is defined but, on inspection, never actually enforced in `validate_row()` — any `Protocol` string is accepted, so a malformed or unexpected protocol value would not be flagged or rejected, it would just appear as its own distinct value in `protocol_distribution`.
- Detection thresholds are fixed constants (e.g., port-scan threshold of 15 distinct ports) — an attacker staying just under a threshold (e.g., 14 ports, or spreading activity across multiple source IPs) would not trigger that rule; `tests/fixtures/validation_phase/boundary_portscan_14_no_trigger.csv` exists specifically to document/test this boundary.
- The dataset is treated as a single, un-ordered batch per upload; there is no cross-upload/session correlation — activity split across two separate CSV uploads (each analyzed independently, overwriting `_LAST_RESULT`) would not be correlated.

---

## Part 7 — Testing and Verification

**This audit did not run any tests.** Everything in this section is either (a) read directly from the test source files (test names, what each asserts), or (b) historical results already recorded in `FINAL_HANDOVER_REPORT.md` from a prior session, clearly labeled as historical and not re-verified here.

### Test files and their purpose
- **`tests/test_analysis.py`** (35 test functions) — unit tests against the analysis/detection/risk-score layer directly (no Flask, no HTTP), covering: basic parsing of valid/allowed-only/blocked-only/mixed datasets; empty/header-only/missing-column rejection; malformed rows, invalid ports/bytes, bad timestamps not crashing; each detection rule individually (port scan, high-volume source, rapid burst, admin-port allowed vs. blocked-only, repeated-block auth vs. non-auth port, elevated ICMP with its MITRE mapping, high-risk ports beyond the "top 10" cap); risk-score bounds/determinism/exact threshold boundaries and the specific `high_risk_port_ratio` denominator regression; findings confidence/next-steps fields; a cross-check against the real 500-row sample's known exact values (`total_records==500`, `allowed_connections==309`, `blocked_connections==191`, `countries==7`, `protocols==3`, `total_traffic_bytes==37877294`); HTML-escaping of injection payloads in the markdown report; PDF export not crashing on injection payloads; CSV-export formula-injection neutralization; a large-input performance/limit test; and constructed datasets reaching each of the 4 threat levels.
- **`tests/test_api.py`** (9 test functions) — integration tests through the real Flask test client: health check (and confirms `gemini_configured` key exists), export-before-analyze returning 404, a full analyze+all-three-exports pass against the real 500-row sample, rejecting a non-`.csv` upload, rejecting missing columns, rejecting an empty file, confirming re-analysis replaces `_LAST_RESULT`, and two end-to-end hardening regression tests (injection payloads safe across report/PDF/CSV, and that the hardening didn't break a clean/benign upload).

### Historical recorded test results (from `FINAL_HANDOVER_REPORT.md`, this session, not re-run by this audit)
- Full suite: **44 / 44 passed** (reported twice, independently, at different points this session, most recently after a from-scratch environment rebuild).
- The standalone `_critical_fixture_check.py` script (exercising the CRITICAL-risk fixture through the real Flask test client): risk score **94 (CRITICAL)**, 20 findings, all three export formats returning HTTP 200.
- A live, UI-driven verification (real file input + real "Analyze Logs" click in an actual browser) against a freshly built environment produced a correctly computed, non-cached result consistent with the uploaded data.

**These are historical results, reported here as evidence that the suite has passed before — not as proof that it passes at this exact moment, per the audit's instructions.**

### Which features have evidence of successful testing
Everything covered by the 44 named tests above has direct, specific test evidence (not just a passing count): schema validation, all 8 detection rules individually, the exact risk-score formula and its threshold boundaries, the known-exact statistics for the real sample CSV, HTML/CSV/PDF injection-safety, and the full API surface (`/api/analyze`, all three export routes, `/api/health`).

### Which features have not been independently (automatically) verified
- The frontend's JavaScript logic (`script.js`) has **no automated test coverage** found in this repository — no `.test.js`/Jest/Playwright/Cypress files exist anywhere in the tree. Its correctness has only been checked manually/visually (per `FINAL_HANDOVER_REPORT.md`'s live browser verification), not via an automated frontend test suite.
- CSS visual appearance/responsiveness is not automatically tested.
- There is no automated test exercising IPv6 input specifically (the validator accepts it via `ipaddress.ip_address()`, but no fixture file was found containing IPv6 addresses).

### Known limitations and unresolved issues (from the project's own documentation and this audit's own file inspection)
- Development server only (`app.run(..., debug=False)` — a Flask/Werkzeug dev server, not a production WSGI server); see Part 8 for detail.
- No automated frontend tests.
- `VALID_PROTOCOLS` defined but unused/unenforced (identified by this audit; not previously documented elsewhere found in this folder).
- Single global `_LAST_RESULT` means only one "latest analysis" can be held at a time per running server process — concurrent users of one running instance would see each other's analysis overwrite one another.

---

## Part 8 — Security Review

| Protection area | Status | Implementing code |
|---|---|---|
| Malicious/malformed CSV | **Handled** | `validators.validate_row()` per-field validation; hard-reject only for missing `Action`/`Destination_Port`; `MAX_ROWS = 200_000` cap; generic try/except around parsing in `app.py` returning a non-leaky error |
| CSV/spreadsheet formula injection (on *export*) | **Handled** | `app.py::_csv_safe()` — prefixes any value starting with `=`, `+`, `-`, `@`, tab, or CR with a single quote before writing to `findings.csv`; verified by `tests/test_api.py::test_injection_payloads_safe_end_to_end_via_api` |
| Cross-site scripting (XSS) in the rendered report | **Handled, in two independent layers** | Server: `report_generator._esc()` HTML-escapes CSV-derived text before it enters the markdown report. Client: `script.js::escapeHtml()` escapes every dynamic value before building finding-card `innerHTML`. The report is rendered via `marked.parse(result.report)` — since the server already escaped embedded HTML, `marked` renders the escaped entities as literal text, not markup |
| Unsafe report/PDF rendering | **Handled** | `pdf_export._esc()` (`xml.sax.saxutils.escape`) before any untrusted value enters a ReportLab `Paragraph`, which otherwise parses a small HTML-like markup dialect and could raise an error or misrender on unescaped `<`/`>`/`&` |
| Invalid input / oversized uploads | **Handled** | `app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024`, with a dedicated `@app.errorhandler(413)`; non-`.csv` extension rejected with 400; `"file" not in request.files` / empty filename rejected with 400 |
| Unsafe file paths | **Handled** | `_safe_filename()` strips directory components and NUL bytes from the uploaded filename before using it anywhere (export filenames, logs); `static_files()` route computes `os.path.abspath` and checks `target.startswith(safe_root)` before serving any frontend file, preventing path traversal outside `FRONTEND_DIR` |
| Sensitive data exposure (in error responses) | **Handled** | Every route's `except Exception` block calls `log.exception(...)` (full traceback to the server log only) and returns a generic client-facing message ("Internal error while..."); the global `@app.errorhandler(500)` is the same pattern as a final catch-all, explicitly documented as never leaking "internal details (file paths, library internals, stack traces)" |
| JSON export escaping | **Intentionally NOT escaped** | `app.py::export_json()` returns the raw `_LAST_RESULT` via `json.dumps(...)`. This is a **documented deliberate choice**, not an oversight: `tests/test_api.py::test_injection_payloads_safe_end_to_end_via_api`'s own comment explains "JSON export is intentionally RAW/unescaped — it is not rendered as HTML by this application, so escaping it would corrupt the true underlying values for any downstream consumer... escape at the point of output, not point of storage" |

### Flask development server limitations vs. production deployment
`app.run(host="127.0.0.1", port=port, debug=False)` runs Werkzeug's built-in development server, which Flask's own startup banner itself warns is not intended for production use. Specific limitations (general Flask/Werkzeug knowledge, applicable to this app's configuration): it is single-process/limited-concurrency by default rather than a multi-worker production WSGI server (e.g. gunicorn/waitress behind a reverse proxy); it has no built-in TLS termination; and — specific to this app's design — it keeps all state (`_LAST_RESULT`) in a single process's memory, so there is no multi-instance/load-balanced deployment story without re-architecting that shared state. Binding to `127.0.0.1` (not `0.0.0.0`) does limit it to local-machine access only, which is appropriate for this project's stated scope (a local demonstration tool), not a multi-user production deployment.

---

## Part 9 — Dependencies and Running the Project

### What `requirements.txt` installs
```
Flask>=3.0
reportlab>=4.0
pytest>=8.0
```
Flask pulls in its own dependencies transitively (Werkzeug, Jinja2, MarkupSafe, click, blinker, itsdangerous — observed during this session's own environment rebuild). `reportlab` pulls in `pillow` and `charset-normalizer`. `pytest` pulls in `pluggy`, `iniconfig`, `packaging`, `pygments`, `colorama`.

### `run.bat`, line by line
```bat
@echo off
cd /d "%~dp0"                                   REM move to this folder regardless of where it's invoked from
if exist venv\Scripts\activate.bat goto :haveenv REM reuse an existing venv if present
py -3 -m venv venv                              REM otherwise create one with the Python launcher
:haveenv
if exist venv\Scripts\activate.bat goto :activate
REM (if venv creation still failed, print a clear error pointing to python.org and exit 1)
:activate
call venv\Scripts\activate.bat                  REM activate the venv for this script's session
pip install -r requirements.txt                 REM install/upgrade the three pinned dependencies
python backend\app.py                           REM start the Flask dev server (blocks until Ctrl+C)
pause                                            REM keep the window open after the server stops
```

### How the virtual environment works
`py -3 -m venv venv` creates an isolated Python environment under `venv/` containing its own interpreter copy and `site-packages`, so the three dependencies are installed there rather than into any system-wide Python installation. `venv\Scripts\activate.bat` modifies the current shell's `PATH` so that `python`/`pip` resolve to the venv's copies for the remainder of that script's session.

### Why it runs on `127.0.0.1:5000`
`app.run(host="127.0.0.1", port=port, debug=False)` in `app.py`, with `port = int(os.environ.get("PORT", 5000))` — `127.0.0.1` (loopback-only) and port `5000` are simply this app's chosen defaults; `PORT` can be overridden via an environment variable (see `.env.example`), though nothing in the inspected code actually loads a `.env` file automatically (no `python-dotenv` import found) — `PORT` would need to be set as a real OS environment variable to take effect.

### How the frontend connects to the backend
Same-origin: Flask serves both the frontend files and the API from the same `127.0.0.1:5000` origin, so `script.js`'s `fetch("/api/analyze", ...)` and `window.open("/api/export/...")` calls are simple relative-path requests with no CORS configuration needed or present.

### What must be installed on another Windows computer
Python 3.10+ (the `run.bat` error message's own stated minimum) with the `py` launcher available on `PATH` (so `py --version` works in a normal Command Prompt) — `run.bat` handles everything else (venv creation, dependency installation) automatically. No other system software (no database, no Node.js, no separate web server) is required, per the full dependency list above.

### Which files are necessary to transfer the project to another computer
`backend/`, `frontend/`, `requirements.txt`, `run.bat`, and `data/sample_firewall_logs.csv` (for a ready demo) are sufficient to run the application. `tests/` is needed only to run the automated test suite. `reference/` is historical documentation, not required to run or test the app. `venv/` should **not** be copied between machines (it is Windows/Python-version-specific); `run.bat` rebuilds it automatically on first run.

---

## Part 10 — Development History and Changes

**No `.git` directory exists anywhere under this folder** (confirmed by this audit's own directory listing) — there is no Git history available to inspect for this folder. Everything below is reconstructed by comparing the current source code against `reference/CyberSight_AI_Project_Handover.docx` (dated **20 October 2026** inside the document itself) and `reference/analysis_result.json`, both kept in this folder specifically as historical references. Where no reliable evidence exists for a specific claim, that is stated rather than guessed.

### Original architecture (per the handover document) vs. current architecture
| Aspect | Original (documented 2026-10-20) | Current (this folder) |
|---|---|---|
| Backend analysis | Google Colab notebook, Python + **Pandas + NumPy** | Flask app, Python **standard library only** (no Pandas/NumPy) |
| AI report | **Gemini**-generated | **Template-generated**, explicitly no external AI call |
| Orchestration | **LangGraph** workflow (`langgraph_statistics`/`langgraph_risk`/`langgraph_recommendations` in the result JSON) | None — a plain, direct function-call pipeline in `app.py` |
| Data exchange | Static `data/analysis_result.json` file, manually produced in Colab and read by the frontend | Live `POST /api/analyze` HTTP endpoint; no static JSON hand-off |
| Frontend hosting | VS Code **Live Server** (static files only) | Flask serves the frontend itself, same origin as the API |
| CSV upload → analysis | **Explicitly documented as NOT connected** — the handover doc's own "Integration note" states "A browser CSV upload does not automatically invoke Python analysis unless an API or another integration mechanism is implemented" | Fully connected: the upload directly triggers the whole Flask pipeline |
| Result schema | Flat: `risk_score`, `threat_level`, `action_distribution`, no structured findings list, no MITRE mappings, no confidence/severity split | Nested, richer: `risk: {score, threat_level, components, explanation}`, a structured `findings` array with severity/confidence/MITRE per finding, full `validation` block |
| Detection logic | Not described as rule-based in the handover document; the result schema has no equivalent of today's 8-rule findings array | A dedicated, documented 8-rule detection engine (`detection_engine.py`) with its own module-level formula documentation |

### Which files were newly created / changed / redesigned
Based on the handover document's own file list (`index.html`, `style.css`, `script.js`, `data/analysis_result.json`, `reports/CyberSight_AI_Report.pdf`) versus the current folder:
- `index.html` / `style.css` / `script.js` exist in both, but the current versions are a live-API-driven redesign (the handover doc even flags the earlier version's unresolved `ReferenceError: Cannot access 'colors' before initialization` bug in `createCountryChart` — this exact bug is **not present** in the current `script.js`, where the `colors` array is constructed and used within the same statement scope before the chart is created, consistent with the fix the handover document's own "Next Work Plan" called for).
- The entire `backend/` folder (`app.py`, `analysis.py`, `detection_engine.py`, `report_generator.py`, `pdf_export.py`, `validators.py`) is **new** relative to the documented original architecture, which had no Flask backend at all — analysis lived entirely in a separate Colab notebook not present in this folder.
- `tests/` (44 automated tests) is new relative to the original handover document, which describes no automated test suite.

### Which earlier features were removed, replaced, or never implemented
- **Removed/replaced:** Pandas/NumPy-based analysis (replaced by the stdlib-based `analysis.py`); Gemini-based report generation (replaced by the deterministic `report_generator.py`); LangGraph orchestration (replaced by direct function calls in `app.py`); the static-JSON hand-off pattern (replaced by the live `/api/analyze` endpoint).
- **Never implemented (per the handover document's own framing as aspirational/in-progress, and absent from the current code):** a working Gemini-generated report, a working LangGraph pipeline, Google Colab as part of the shipped application (it was a development-time tool only, even in the original design).

### Old files kept only as historical references
`reference/CyberSight_AI_Project_Handover.docx`, `reference/CyberSight_AI_Report.pdf`, and `reference/analysis_result.json` — all three are explicitly excluded from being read by the running application (confirmed by this audit: no code anywhere in `backend/` or `frontend/` references the `reference/` folder).

### Bugs fixed, and how the current code addresses them
1. **`ReferenceError: Cannot access 'colors' before initialization`** in the old `createCountryChart` (documented in the handover doc, Section 10, with the exact console error and file/line). The current `script.js::createCountryChart()` declares `const colors = labels.map(...)` and uses it in the `Chart(...)` call within the same function body before any later reference — the specific ordering bug described is not present in the current code.
2. **Risk-score ceiling bug** (documented inside `detection_engine.py`'s own "Revision note," and covered by `test_high_risk_port_ratio_denominator_is_allowed_not_total`): an earlier version of the risk formula divided `high_risk_port_ratio` by `total_records` instead of `allowed_connections`, which the code's own comment says made the CRITICAL band (80–100) "effectively unreachable (verified ceiling ~70/100 under the old denominator, see VALIDATION_REPORT.md / HARDENING_REPORT.md)." **Note:** `VALIDATION_REPORT.md` and `HARDENING_REPORT.md` are referenced by this comment but **do not exist in this folder** (they are listed as intentionally excluded/superseded in `FINAL_HANDOVER_REPORT.md`, Section 3) — this audit can confirm the comment's existence and the regression test that encodes the fix, but cannot independently verify the original "~70/100 ceiling" figure since the underlying report is not present here.
3. **Injection/XSS and CSV-formula-injection hardening** (documented via code comments referencing a "Section 5 requirement" and a "final hardening phase," and covered by multiple tests in both test files) — the three-layer escaping described in Part 8.

### A note on authorship
Nothing in the inspected files establishes who personally wrote any specific line of code; this audit does not claim or assume authorship on the user's behalf.

---

## Part 11 — Limitations and Future Improvements

**Current functionality** (confirmed by source inspection) vs. **proposed improvements** (this audit's own suggestions, not implemented) are kept clearly separate below.

### Current technical limitations
- Single-process, single-`_LAST_RESULT` design — no concurrent-user isolation.
- No persistence — every result is lost on server restart or the next analysis.
- No automated frontend test coverage.
- `VALID_PROTOCOLS` defined but not enforced (dead validation constant).
- Flask development server only; not configured for production (no WSGI server, no TLS).
- Relies on three CDN-hosted JS libraries (Chart.js, marked.js, Font Awesome) — the app requires outbound internet access for its frontend assets to render correctly, despite the backend itself being fully local/offline.

### Analytical limitations
- Fixed, non-adaptive thresholds for every detection rule (e.g., always 15 ports for port-scan) — no per-environment tuning, baselining, or anomaly-detection approach.
- No cross-upload/session correlation.
- Firewall-log-only visibility — explicitly cannot confirm authentication success, payload content, or actual compromise (stated repeatedly in the code's own documentation, not just this audit's observation).

### Security limitations
- JSON export is intentionally unescaped (by design, documented — see Part 8), so a downstream consumer that naively renders the raw JSON as HTML without its own escaping would reintroduce an XSS risk; this is explicitly outside this application's own rendering path, but worth noting for anyone building on top of the JSON export.
- No authentication/authorization on any route — anyone who can reach `127.0.0.1:5000` on the host machine can use the app and see the last analysis result.
- No rate-limiting on `/api/analyze`.

### Missing or unimplemented features
- No working AI-generated report (Gemini is a documented-but-unimplemented placeholder — see Part 3).
- No multi-file/batch upload.
- No historical trend view across multiple analyses (each analysis fully replaces the last).
- No user accounts or saved-analysis history.

### Improvements that would be valuable for a future version (proposed, not implemented)
- Persist analysis history (e.g., to SQLite) so multiple results can be compared over time.
- Replace the fixed detection thresholds with configurable or statistically-derived baselines.
- Add automated frontend tests (e.g., Playwright) to cover the gap noted in Part 7.
- Vendor the CDN JS libraries locally for fully offline operation.
- If AI-assisted reporting is wanted, implement it as an explicitly-labeled, clearly-optional second report path (as `.env.example` already anticipates), rather than mixing it into the deterministic report.

---

## Part 12 — Interview Preparation

### 1. 60-second explanation (simple)
"CyberSight AI is a web tool I can upload a firewall log CSV to, and it analyzes the traffic — allowed vs. blocked connections, which countries and ports were involved — and gives me a 0-to-100 risk score with a threat level. It also flags specific suspicious patterns, like a single source touching a lot of different ports, which can indicate scanning, or traffic reaching sensitive ports like RDP or SSH that should probably be restricted. Everything runs locally — there's a Flask backend doing the analysis and a dashboard frontend with charts, and I can export the result as a PDF, JSON, or CSV."

### 2. 3-minute explanation (more technical)
"The backend is a small Flask app. When you upload a CSV, it's parsed and validated against a required schema — Timestamp, Source/Destination IP, ports, protocol, action, country, and bytes — with alias-matching for slightly different column names, and row-level validation that only hard-rejects a row if the action or destination port is unusable; everything else is kept with a warning so one bad field doesn't throw away a whole row.

From the clean rows, I compute aggregate statistics — counts, distributions by country/protocol/port, and a few uncapped aggregates specifically reserved for detection, since the UI only needs the top 10 for charts but detection needs to see everything.

On top of those statistics, eight rule-based detection functions run — things like a port-scan rule (≥15 distinct ports from one source), a sensitive-port-exposure rule, an ICMP-volume rule, and a time-windowed burst-detection rule using a sliding-window algorithm. Each finding carries its own severity, a separate confidence rating, and where it's justified, a MITRE ATT&CK mapping — always labeled as a behavioral association, never confirmed activity.

Those findings feed into a documented, deterministic risk-score formula — four weighted components: block rate, high-risk-port exposure ratio (measured against allowed traffic specifically, not total traffic, which was actually a bug I can point to in the code's own revision notes), ICMP ratio, and a findings-corroboration weight — clamped 0 to 100 with fixed LOW/MEDIUM/HIGH/CRITICAL thresholds.

There's no external AI involved — the written report is template-generated from the same data, explicitly labeled as such in the UI. On the frontend side, it's vanilla JS with Chart.js for the five charts and marked.js to render the markdown report; all backend-origin text is HTML-escaped server-side and again client-side before being inserted into the DOM, specifically to prevent a malicious CSV value from becoming executable script. There's a 44-test pytest suite covering the detection logic, the risk formula's exact threshold boundaries, and injection-safety across the report, PDF, and CSV export paths."

### 3. Twenty likely technical interview questions, with accurate answers based on the source code

1. **Q: What libraries does the backend actually use?**
   A: Flask, ReportLab, and pytest (dev/test). No Pandas or NumPy — `analysis.py` uses only the Python standard library.
2. **Q: Is Gemini actually used to generate the report?**
   A: No. The report is template-generated in `report_generator.py`. `GEMINI_API_KEY` exists only as an unused, documented-as-future/optional environment variable checked by `/api/health`.
3. **Q: What are the two conditions that cause a CSV row to be hard-rejected?**
   A: A missing/unparseable `Action` value, or a missing/invalid `Destination_Port`. Every other field issue is a soft warning that keeps the row.
4. **Q: Walk me through the risk-score formula.**
   A: `score = round(min(100, block_rate*40 + high_risk_port_ratio*30 + icmp_ratio*15 + scan_findings_weight*15))`, with `high_risk_port_ratio` measured against *allowed* connections specifically.
5. **Q: Why is `high_risk_port_ratio` divided by allowed connections instead of total records?**
   A: Dividing by total records made it structurally compete with `block_rate` for the same denominator, making the documented CRITICAL band unreachable; dividing by allowed connections measures actual exposure within the traffic that got through, independent of how much other traffic was blocked.
6. **Q: What's the difference between a finding's severity and its confidence?**
   A: Severity is how impactful the finding would be if the interpretation holds; confidence is how certain that interpretation itself is, given that the tool only has a connection log (no auth logs, no payload visibility).
7. **Q: How does the app detect a port scan?**
   A: A single source IP contacting ≥15 distinct destination ports (`PORT_SCAN_THRESHOLD`); severity escalates to HIGH at ≥30.
8. **Q: How does burst detection work technically?**
   A: A sliding-window two-pointer algorithm (`_max_events_in_window`) over each source IP's sorted timestamps, looking for ≥15 events within any 60-second window.
9. **Q: How are MITRE ATT&CK techniques assigned?**
   A: Only where the available evidence reasonably supports it (e.g., auth-port blocks → T1110 Brute Force, allowed sensitive-port traffic → T1133 External Remote Services, high ICMP/port-scan → T1595.001). Where it doesn't, `mitre` is explicitly `None` rather than guessed.
10. **Q: How is XSS prevented?**
    A: Two independent layers — server-side `html.escape()` in `report_generator.py` before text enters the markdown report, and client-side `escapeHtml()` in `script.js` before any value is inserted via `innerHTML`.
11. **Q: How is CSV formula injection prevented?**
    A: `app.py::_csv_safe()` prefixes any value starting with `=`, `+`, `-`, `@`, tab, or CR with a single quote before writing `findings.csv`.
12. **Q: Why is the JSON export not escaped the same way?**
    A: It's a deliberate choice — JSON isn't rendered as HTML by this app, so escaping it would corrupt the true values for any downstream consumer; escaping happens at the point of output (HTML/PDF/CSV), not at the point of storage.
13. **Q: How does the app prevent path traversal when serving frontend files?**
    A: The `static_files()` route computes the absolute target path and rejects (404) anything that doesn't start with the absolute `FRONTEND_DIR` path.
14. **Q: What happens if the uploaded file is bigger than the limit?**
    A: Flask's `MAX_CONTENT_LENGTH` (15 MB) triggers a 413 response via a dedicated error handler.
15. **Q: Where does the app run, and why does that matter?**
    A: `127.0.0.1:5000` — loopback only, so it's reachable only from the local machine, appropriate for a local demo but not multi-user production use.
16. **Q: How many automated tests exist, and what do they cover?**
    A: 44 total — 35 unit tests (`test_analysis.py`) against the analysis/detection/risk layer directly, 9 integration tests (`test_api.py`) through the real Flask API, together covering parsing/validation, every detection rule, the exact risk thresholds, the real sample's known values, and injection-safety.
17. **Q: Does the backend persist analysis results to disk or a database?**
    A: No — `_LAST_RESULT` is an in-memory dict in the Flask process, overwritten by each new analysis and lost on restart.
18. **Q: How does the frontend get its chart/report data — does it do any of its own analysis?**
    A: No. All computation happens in Python; the frontend only renders the JSON the backend already computed.
19. **Q: What was the original architecture before this version, and how do you know?**
    A: Per `reference/CyberSight_AI_Project_Handover.docx`, the original design used Google Colab, Pandas/NumPy, Gemini, and LangGraph, with a static `analysis_result.json` hand-off and no live CSV-to-analysis connection — explicitly documented in that file, kept in the `reference/` folder for historical comparison only.
20. **Q: Why does `Protocol` accept arbitrary values even though `VALID_PROTOCOLS` is defined?**
    A: `VALID_PROTOCOLS = {"TCP","UDP","ICMP"}` exists in `validators.py` but is never referenced inside `validate_row()` — it's effectively dead code, identified during this audit; any protocol string is currently accepted and upper-cased without restriction.

### 4. Ten questions about design choices, limitations, and trade-offs

1. **Q: Why keep `_LAST_RESULT` in memory instead of a database?**
   A: Matches the project's stated scope (a local, single-user demonstration tool, "processed in memory only" is even shown as a UI badge) — simplicity over durability/multi-user support.
2. **Q: Why separate "severity" from "confidence" on each finding instead of one combined score?**
   A: So a high-impact-if-true pattern with weak supporting evidence (e.g., a single blocked connection to a sensitive port) isn't conflated with a high-impact pattern with strong evidence — the trade-off is a slightly more complex finding object in exchange for more honest, non-overstated claims.
3. **Q: Why hard-reject on `Destination_Port`/`Action` but soft-warn on everything else (like IP format)?**
   A: Those two fields are load-bearing for every downstream calculation (port-based detection rules, allow/block counting); everything else can degrade gracefully (e.g., an unparseable IP just isn't counted in the unique-IP sets) without invalidating the row's other useful data.
4. **Q: Why use the Python standard library instead of Pandas, given the original design used it?**
   A: Not stated explicitly in the code; this audit cannot confirm the reason from the available evidence. A plausible trade-off (not verified): avoiding a heavier dependency for a dataset size this project targets (≤200,000 rows).
5. **Q: Why is the AI report explicitly NOT AI-generated, despite the project's name and the historical Gemini plan?**
   A: The code and `.env.example` treat Gemini as optional/future, not required; the current, shipped choice is a deterministic, fully-offline, reproducible template report — a trade-off favoring reliability and zero external dependency/cost over the richer, more varied prose an LLM-generated report might offer.
6. **Q: Why cap `top_destination_ports` etc. at 10 but keep uncapped versions for detection?**
   A: Chart/UI readability needs a short list; detection correctness needs the full picture. Keeping both avoids the trade-off of either an unreadable chart or blind detection logic.
7. **Q: Why escape HTML server-side AND client-side, instead of trusting one layer?**
   A: Defense-in-depth — if either layer is ever bypassed or a new rendering path is added that forgets to escape, the other layer still protects against it.
8. **Q: Why fixed detection thresholds instead of adaptive/statistical baselining?**
   A: Simplicity and predictability for a teaching/portfolio project — the trade-off is reduced accuracy in environments whose "normal" traffic doesn't match the chosen constants (acknowledged in Part 11 as a limitation).
9. **Q: Why run on Flask's built-in dev server instead of a production WSGI server?**
   A: Matches the project's local-demonstration scope; a production server would add setup complexity not needed for this use case — explicitly a limitation, not a design strength, per Part 8.
10. **Q: Why keep the old `reference/` files (Gemini-era docx/PDF/JSON) in the final folder at all?**
    A: Per `README.md`/`FINAL_HANDOVER_REPORT.md`, kept intentionally as historical context for comparison, while explicitly confirmed not to be read by the running application — a documentation/traceability choice, not a functional dependency.

### 5. Five practical scenarios

1. **An invalid CSV (e.g., missing the `Destination_Port` column entirely) is uploaded.**
   `resolve_schema()` finds it's missing from `REQUIRED_COLUMNS`; `parse_and_validate_csv()` raises `CSVParseError("Missing required column(s): Destination_Port...")`; `app.py` catches this specific exception and returns **HTTP 422** with that message in `{"error": ...}`. The frontend's `catch` block shows "Analysis failed: Missing required column(s)..." in the status area; no dashboard/chart/report update happens.

2. **A CSV produces a high risk score (e.g., 94, CRITICAL).**
   The dashboard's `threatCount`/`threatLevel` cards get the `.critical` CSS class (red/high-visibility styling via `updateThreatColor()`); the findings list shows whatever HIGH/CRITICAL findings actually fired, sorted first; the report's "Overall Assessment" section states `POSTURE: CRITICAL RISK (score 94/100)`; all three exports remain available and reflect the same CRITICAL result.

3. **Traffic to a suspicious/sensitive port is observed (e.g., ALLOWED traffic to port 3389/RDP).**
   Rule 3 ("Exposure of Sensitive Administrative Ports") fires; since at least one connection was ALLOWED, severity is HIGH (if >5% of records) or MEDIUM, confidence MEDIUM, and it's mapped to MITRE T1133 with the explicit "(behavioral association, not confirmed adversary activity)" caveat appended in the report text.

4. **A PDF export is attempted before any analysis has run.**
   `GET /api/export/pdf` checks `if not _LAST_RESULT["data"]:` and returns **HTTP 404** with `{"error": "No analysis has been run yet."}`. On the frontend, the button handler actually checks the local `hasAnalysis` flag first and shows "Run an analysis first, then download the report." without even making the request — so this 404 path would only be reached via a direct API call bypassing the UI.

5. **A PDF export fails for an unanticipated reason (e.g., a crafted value breaks ReportLab's Paragraph parser).**
   `export_pdf()`'s `try/except Exception` catches it, calls `log.exception("PDF export failed")` (full traceback server-side only), and returns a generic **HTTP 500** `{"error": "Internal error while building the PDF export."}` — the client never sees internal details. (The known XSS/crash-causing inputs discovered during the project's hardening phase are specifically covered by `tests/test_analysis.py::test_injection_payloads_do_not_crash_pdf_export` and are not expected to trigger this path anymore, per that test's current passing status reported in `FINAL_HANDOVER_REPORT.md`.)

### 6. Glossary

- **ALLOW / BLOCK** — The two normalized connection-outcome values this app recognizes (from a wider set of vendor-specific input synonyms like PERMIT, DENY, DROP).
- **Allowed-high-risk ratio (`high_risk_port_ratio`)** — Share of *allowed* connections that hit a sensitive port; one of the four risk-score components.
- **Block rate** — Share of all connections that were blocked; one of the four risk-score components.
- **CDN** — Content Delivery Network; where this app loads Chart.js, marked.js, and Font Awesome from, rather than bundling them locally.
- **Confidence (finding field)** — How certain a finding's interpretation is, independent of its severity.
- **CSV formula injection** — A spreadsheet-application vulnerability where a cell value starting with `=`, `+`, `-`, or `@` is interpreted as a formula when opened; mitigated here via `_csv_safe()`.
- **`_LAST_RESULT`** — The module-level in-memory dict in `app.py` holding the most recent analysis result.
- **MITRE ATT&CK** — A public knowledge base of adversary tactics/techniques; this app maps some findings to specific technique IDs (e.g., T1133, T1110, T1595.001) as a behavioral association, never a confirmed-activity claim.
- **Risk score** — The 0–100 deterministic score computed by `compute_risk_score()`.
- **Severity (finding field)** — How impactful a finding would be if its interpretation holds (LOW/MEDIUM/HIGH/CRITICAL).
- **Threat level** — The LOW/MEDIUM/HIGH/CRITICAL label derived from the risk score via fixed thresholds.
- **`venv`** — Python's built-in virtual-environment tool, used here to isolate this project's dependencies.
- **Werkzeug** — The WSGI toolkit underlying Flask's development server.
- **XSS (Cross-Site Scripting)** — Injecting executable script into a page via unescaped user-controlled content; mitigated here via server- and client-side HTML escaping.

---

## Audit Summary

- **Exact project directory inspected:** `CyberSight AI - Final Project` (the folder confirmed earlier in this engagement to be a sibling of, and independent from, the original `CyberSightAI-Frontend` folder). No file inside `CyberSightAI-Frontend` or any `_backup_*` folder was read for this audit.
- **Actual technologies verified:** Python 3, Flask, ReportLab, pytest (backend); HTML5, CSS3, vanilla JavaScript, Chart.js 4.4.1, marked.js 15.0.12, Font Awesome 6.5.1 (frontend, Chart.js/marked/Font Awesome loaded via CDN). **No Pandas, no NumPy.**
- **Key files inspected:** all 6 `backend/*.py` files, all 3 `frontend/*` files, both `tests/*.py` files (contents and/or full test-name listing), `requirements.txt`, `run.bat`, `README.md`, `.env.example`, `.gitignore`, `data/sample_firewall_logs.csv` (header + row count), all three `reference/` files (the `.docx` and the `.json` were read in full; the `.pdf`'s existence and size were confirmed but its content was not extracted), and the full project directory tree (excluding `venv/` contents).
- **Features confirmed by source inspection:** CSV upload → Flask `/api/analyze` → validation → statistics → 8 rule-based detections → 4-component deterministic risk score → template-generated markdown report → dashboard/chart/finding rendering → PDF/JSON/CSV export. All backend logic runs without Pandas/NumPy/Gemini/LangGraph. HTML-escaping (server + client), CSV formula-injection neutralization, path-traversal protection on static file serving, and generic (non-leaky) error responses are all present in the current code.
- **Features that remain uncertain or unverified by this audit:** whether the 44/44 test-pass and CRITICAL-fixture results reported in `FINAL_HANDOVER_REPORT.md` still hold at this exact moment (this audit did not run tests, per its instructions — those are reported as historical evidence only); the original rationale for choosing stdlib over Pandas (not stated in any inspected file); the precise original "~70/100 risk-score ceiling" figure referenced by a code comment (the report it cites, `VALIDATION_REPORT.md`/`HARDENING_REPORT.md`, is not present in this folder).
- **Whether Gemini, LangGraph, Google Sheets, and external AI services are actually integrated:** **No.** Verified by direct source inspection (Part 3) — Gemini and LangGraph appear only as historical/placeholder references, never as working integrations; Google Sheets does not appear anywhere in the codebase at all.
- **Whether any project files or settings were changed during this audit:** **No.** This audit was read-only throughout: no file was created, modified, deleted, renamed, or moved except for this new document itself, no package was installed, and no server or process was started or stopped.
