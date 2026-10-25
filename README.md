# SentinelLog — Firewall Log Analyzer

*(This project was developed under the working name "CyberSight AI"; the
code, reports, and user interface now display "SentinelLog". A few
historical reference files below still carry the old name intentionally —
see section 1.)*

SentinelLog analyzes firewall connection logs (CSV) and produces a risk score,
threat level, traffic breakdown, rule-based suspicious-activity findings, and a
template-generated summary report. Exports are available as PDF, JSON, and CSV.

This folder, **`CyberSight AI - Final Project`**, is the single,
self-contained, final copy of the project (the folder itself was not
renamed, to avoid disrupting any existing local references to it). It does
not depend on any other folder on this computer — it does not read code,
sample data, or configuration from anywhere outside itself, and it builds
its own Python virtual environment the first time it runs.

## 1. What's in this folder

```
backend/        Flask application (analysis engine, detection rules, PDF export,
                 report generation, input validation)
frontend/        Static HTML/CSS/JS served by the backend
tests/            Automated test suite (pytest) and its CSV fixtures,
                 including tests/fixtures/validation_phase/ used for the
                 critical-risk verification described below
data/             sample_firewall_logs.csv — a ready-to-use sample log for
                 trying the app immediately after setup
reference/        Original pre-engagement reference materials, kept for context
                 only (not read by the running application). These still use
                 the project's original working name intentionally, as a
                 historical record of that earlier phase:
                   - CyberSight_AI_Project_Handover.docx — original project
                     handover document
                   - CyberSight_AI_Report.pdf — an earlier, differently-generated
                     sample report (Gemini-based prototype) on the same 500-row
                     sample data, kept for historical comparison
                   - analysis_result.json — the JSON result that accompanied
                     that earlier report
requirements.txt  Pinned Python dependencies (Flask, reportlab, pytest, waitress)
run.bat           One-click local launcher — creates/uses its own venv, installs
                 dependencies, and starts the Flask development server
production_server.py  Production WSGI entrypoint (Waitress) — used both for a
                 real deployment (e.g. Render) and for testing a production-style
                 run locally. See section 7.
Procfile          `web: python production_server.py` — the process-type
                 declaration Render (and similar platforms) read to know how
                 to start the app.
_critical_fixture_check.py  Standalone script that exercises the live Flask
                 routes (via Flask's test client) against the CRITICAL-risk
                 fixture and prints the result — used for independent
                 verification, not required to run the app itself
.env.example       Template for optional environment variables
.gitignore
```

## 2. Running the app locally (development)

1. Make sure Python 3.10+ is installed and `py --version` works in a normal
   Command Prompt.
2. Double-click `run.bat` in this folder (or run it from a terminal).
   - On first run it creates a virtual environment in `venv/` (inside this
     folder only) using the Python launcher (`py -3 -m venv venv`), then
     installs everything listed in `requirements.txt`.
   - It then starts the Flask development server.
3. Open **http://127.0.0.1:5000** in a browser.
4. Upload a CSV log file (or use `data/sample_firewall_logs.csv`) and click
   **Analyze Logs**.
5. Review the Dashboard, Analytics, Findings, and AI Report tabs, and use the
   PDF / JSON / CSV export buttons as needed.

Press `CTRL+C` in the console window to stop the server.

If port 5000 is already in use (for example because a previous run of this
app is still running in another window), close that window first, or edit
`backend/app.py` / set the `PORT` environment variable to use a different port.

## 3. Running the tests

```
venv\Scripts\activate
python -m pytest tests\ -v
```

(Run `run.bat` once first if `venv\` does not exist yet, or create the
virtual environment manually with `py -3 -m venv venv` followed by
`venv\Scripts\pip install -r requirements.txt`.)

## 4. Critical-risk verification script

`_critical_fixture_check.py` is a small standalone script that posts
`tests/fixtures/validation_phase/critical_multi_vector_demo.csv` to the
running analysis routes via Flask's own test client (not a mocked response)
and prints the resulting risk score, threat level, findings count, and the
HTTP status of all three export formats. It is a verification aid, not part
of the application itself:

```
venv\Scripts\activate
python _critical_fixture_check.py
```

## 5. Architecture notes

- The backend resolves every path relative to its own file location
  (`backend/app.py`'s own directory), so the application works correctly no
  matter where this folder is placed on disk, and never reads from any other
  project folder.
- Analysis results are kept in memory only (no database, no files written to
  disk by the app itself) — see the "Processed in memory only" badge in the
  UI. Starting with the Render-preparation pass, each result is also scoped
  to the visitor's own browser session (via a signed session cookie), so
  concurrent visitors to a shared deployment never see each other's result —
  see section 6.
- The AI Report is a template-generated summary assembled from the computed
  statistics and findings. It is explicitly labeled in the UI and in the
  report text as "Template-generated summary... not an AI-written
  assessment" — there is no live call to an external AI service in this
  build.

## 6. Known limitations

- `run.bat` / `python backend\app.py` still runs Flask's built-in
  `werkzeug` development server, bound to `127.0.0.1` only — fine for local
  use, not meant to be exposed directly to the internet. For anything
  publicly reachable, use `production_server.py` instead (section 7).
- Analysis results are not persisted to disk, and are cleared if the process
  restarts (by design — see the "processed in memory only" note above). The
  per-session result store is also bounded (oldest entries are evicted past
  500 concurrent sessions) to avoid unbounded memory growth from anonymous
  public traffic.
- The `reference/` folder's PDF and `.docx` describe an earlier, different
  prototype of this project (built around Gemini/Pandas) and are kept only
  as historical context; they are not generated by, or read by, the current
  application.
- CSV uploads are capped at 15 MB and validated before processing (see
  `backend/validators.py`), but, as with any publicly reachable upload
  endpoint, review your own deployment's rate-limiting/abuse protections
  before relying on this for untrusted public traffic — none is implemented
  at the application level beyond the size cap and CSV-format checks.

## 7. Deploying to Render (free tier)

This app is now set up to run as a standard Render **Web Service**:

1. **Start command**: Render reads the included `Procfile`
   (`web: python production_server.py`) automatically, so the default start
   command field can usually be left blank. If Render asks for one anyway,
   use `python production_server.py`.
2. **Build command**: `pip install -r requirements.txt`
3. **Environment variables** (Render → your service → Environment):
   - `PORT` — set automatically by Render; do not set it yourself.
   - `SECRET_KEY` — set this to a long random string for a real deployment,
     so a redeploy/restart does not invalidate every visitor's current
     session (if left unset, a random key is generated at each process
     startup instead, which is fine but means sessions reset on every
     restart).
   - `GEMINI_API_KEY` — leave unset; this is an optional, currently-unused
     placeholder (see `backend/report_generator.py`'s own docstring) and the
     app is fully functional without it.
4. `production_server.py` reads `PORT` from the environment and binds to
   `0.0.0.0` (required for Render's proxy to reach the container), serving
   the same Flask app through Waitress — a pure-Python production WSGI
   server — instead of Flask's development server.
5. This repository has **not** been pushed to GitHub or connected to Render
   yet; that step requires your explicit go-ahead.
