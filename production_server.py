"""
SentinelLog - production_server.py
Production WSGI entrypoint, used both on Render and for local
production-style testing on this machine. Serves the exact same Flask app
object as backend/app.py, but through Waitress (a pure-Python WSGI server
that works on Windows, Linux and Render's containers alike) instead of
Flask's own development server, and binds to 0.0.0.0 so a platform like
Render -- which proxies external traffic to a container-internal port --
can actually reach it.

Local development should keep using run.bat / `python backend\app.py`,
which binds to 127.0.0.1 only (see backend/app.py's own docstring) -- this
file is only for simulating or performing a real deployment.

Run locally:            python production_server.py
Render start command:   python production_server.py
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "backend"))

from waitress import serve
from app import app  # noqa: E402  (backend/app.py's Flask instance)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"SentinelLog (production/Waitress) starting on http://{host}:{port}")
    serve(app, host=host, port=port)
