# CyberSight AI — Final Handover Report

**Folder:** `CyberSight AI - Final Project` (sibling of the original
`CyberSightAI-Frontend` project folder on the Desktop)

**Status:** Independently built, installed, and verified from inside this
folder only. All results below are actual outputs captured during this
verification session, not assumptions.

## 1. What this folder is

This is the single, self-contained final copy of the CyberSight AI project,
created by copying only the files required to run the application, serve its
frontend/backend, install dependencies, load sample data and configuration,
and run the automated tests and critical-risk verification. It was built
from — and verified against — the current working implementation in the
original project folder. See `README.md` in this folder for how to run it.

## 2. Verification performed, and actual results

### 2.1 Dependency installation (from scratch)
A new virtual environment was created inside this folder with
`py -3 -m venv venv`, and dependencies were installed with
`pip install -r requirements.txt` using only the `requirements.txt` shipped
in this folder — no reference to the old project's virtual environment.

**Result:** Clean install succeeded. Flask 3.1.3, reportlab 5.1.0,
pytest 9.1.1, and their transitive dependencies installed without errors.

### 2.2 Automated test suite
```
python -m pytest tests\ -v
```
**Result: 44 / 44 tests passed in 0.82s.**

### 2.3 Critical-risk fixture verification
`_critical_fixture_check.py` was run against the live Flask application in
this folder (via Flask's own test client, exercising the real
`/api/analyze` and `/api/export/*` routes — not a mocked response), using
`tests/fixtures/validation_phase/critical_multi_vector_demo.csv`.

**Result:**
- `/api/analyze` → HTTP 200
- Risk score: **94**, Threat level: **CRITICAL**
- AI report: present, mentions CRITICAL, length 24,056 characters
- Findings returned: **20**
- `/api/export/pdf` → HTTP 200 (17,356 bytes, `application/pdf`)
- `/api/export/json` → HTTP 200
- `/api/export/findings.csv` → HTTP 200 (5,096 bytes)

### 2.4 Live application via `run.bat`, verified in a real browser
`run.bat` was double-clicked from this folder. It created/activated its own
`venv`, installed dependencies, and started the server
(`http://127.0.0.1:5000`). The running app was then driven through its
**actual UI** in the built-in browser pane (a 20-row firewall-log CSV was
attached to the real file input and the real "Analyze Logs" button was
clicked — the same code path a user would trigger):

- **Dashboard** — loaded and updated with real figures: Risk Score 29,
  Threat Level LOW, Blocked 3, Allowed 17, Countries 6, Protocols 3, Total
  traffic 1.29 MB, Top port 123.
- **Analytics** — rendered country breakdown (UAE 25%, USA 25%, India 15%,
  Japan 15%, UK 15%, Germany 5%) and protocol/port/traffic-over-time charts.
- **Findings** — 2 real findings rendered with evidence and MITRE ATT&CK
  mappings: F001 "Exposure of Sensitive Administrative Ports" (HIGH) and
  F002 "Elevated ICMP Volume" (MEDIUM).
- **AI Report** — the template-generated summary rendered in full,
  correctly labeled "Template-generated summary... not an AI-written
  assessment," matching the risk score and findings above.
- **Exports** — PDF (HTTP 200, `application/pdf`), JSON (HTTP 200), and
  Findings CSV (HTTP 200, `text/csv`) all succeeded against this same live
  analysis result.

### 2.5 No dependency on the old project folder
`backend/app.py` resolves `PROJECT_ROOT` and `FRONTEND_DIR` purely from its
own file location (`os.path.dirname(os.path.abspath(__file__))`), with no
hardcoded paths anywhere in `backend/`, `tests/`, or the launcher scripts
(confirmed by searching the copied source for absolute paths and for any
reference to the old folder's name — none found). The app was started and
fully exercised from this folder's own `run.bat`/`venv`, and never touched
the original project folder during verification.

## 3. Files copied vs. intentionally excluded

**Copied** (everything required to run, test, and understand the app):
`backend/`, `frontend/`, `tests/` (including all fixtures), `data/sample_firewall_logs.csv`,
`requirements.txt`, `run.bat`, `.env.example`, `.gitignore`,
`_critical_fixture_check.py`, one current `README.md`, this
`FINAL_HANDOVER_REPORT.md`, and `reference/` (the original handover `.docx`,
the earlier prototype's PDF report, and its accompanying JSON — kept only as
historical context, not read by the running application).

**Intentionally excluded** (per the explicit packaging instructions):
- All five `_backup_*/` folders from the original project
- The obsolete root-level `index.html`, `script.js`, `style.css`,
  `firewall_logs.csv` (superseded UI snapshot not used by the app)
- `HARDENING_REPORT.md` and `VALIDATION_REPORT.md` (superseded by this
  single handover report)
- Temporary logs and caches generated during this verification itself
  (`_pip_install.log`, `_setup_pytest_output.log`,
  `_critical_fixture_check.log`, `.pytest_cache/`, `__pycache__/`, and the
  two throwaway `.bat` scripts used only to drive this verification)
- The old project's own `venv/` — never copied; this folder built its own

## 4. Launch instructions (summary)

1. Double-click `run.bat` in this folder.
2. Open `http://127.0.0.1:5000`.
3. Upload a CSV (or use `data/sample_firewall_logs.csv`) and click
   "Analyze Logs."

Full details, including running the tests and the verification script
independently, are in `README.md`.

## 5. Post-verification safety checks (2026-10-24)

After the verification in Section 2, a stale Python process from that
verification session was found still holding 3 files open inside this
folder's `venv\` (`venv\Scripts\python.exe` and two native extension files
under `venv\Lib\site-packages\`), which blocked deleting or rebuilding the
environment. This was root-caused (not assumed) using Windows process
diagnostics (`Get-CimInstance Win32_Process`) and Resource Monitor's
Associated Handles search, which confirmed the exact PIDs holding the
locked files. Those specific processes were stopped, and the fix was
verified end-to-end from scratch:
- `venv\` was fully deleted with no further I/O errors.
- A fresh virtual environment was rebuilt with `py -3 -m venv venv`.
- Dependencies were reinstalled from this folder's own `requirements.txt`
  (Flask 3.1.3, reportlab 5.1.0, pytest 9.1.1 -- same versions as Section 2).
- The full automated test suite was re-run: **44 / 44 passed**.
- The critical-risk fixture check was re-run: risk score 94 (CRITICAL), 20
  findings, all 3 export formats HTTP 200 -- matching Section 2.
- The app was relaunched via this folder's own `run.bat` and driven
  through the real browser UI with a new, freshly uploaded CSV (not the
  Section 2 sample): Dashboard, Analytics, Findings, AI Report, and all 3
  exports (PDF/JSON/CSV) all rendered correctly with figures matching the
  uploaded data exactly.
- This confirms the final folder builds, runs, and serves correctly on its
  own, independent of the original project folder, after a completely
  clean environment rebuild.

**Known remaining item:** stale `python.exe` processes from earlier
verification/testing of the *original* `CyberSightAI-Frontend` folder may
still be running in the background (confirmed, via their own
`ExecutablePath`, to be using that folder's own virtual environment, not
this one). They do not hold any lock on this folder and do not affect its
correctness, but if `run.bat` ever reports port 5000 already in use, end
any leftover `python.exe` processes via Task Manager (Details tab -> select
the process -> End task) or restart the computer.

## 6. Remaining limitations

- This is a development server, not hardened for production deployment.
- The AI Report is a template-generated summary, not a call to an external
  AI model, exactly as labeled in the UI.
- Analysis results are in-memory only and are not persisted between
  requests or server restarts.
