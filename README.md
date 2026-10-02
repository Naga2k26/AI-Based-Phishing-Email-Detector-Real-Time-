# AI-Based Phishing Email Detector

Lightweight Flask app to detect and manage phishing email events. It includes
an ML wrapper, IMAP-based email scanning, a scheduler, alerting, and simple
dashboard UI pages.

## Quickstart (Windows / PowerShell)

1. Create and activate a virtual environment (recommended):

   & "python" -m venv .venv; .\.venv\Scripts\Activate.ps1

2. Install dependencies (Flask and others):

   & ".venv\Scripts\python.exe" -m pip install -r requirements.txt

   If you don't have a `requirements.txt`, at minimum install Flask:

   & ".venv\Scripts\python.exe" -m pip install flask

3. Copy `.env.example` to `.env` and fill in your credentials and settings.

4. Run the app:

   - Use the venv python directly (no activation required):

     & ".venv\Scripts\python.exe" app.py

   - Or use the provided wrapper scripts (Windows/PowerShell/Cross-platform):

     PowerShell: .\run.ps1
     Batch:       .\start.bat
     Bash:        ./run.sh

   The app will run in debug mode at http://127.0.0.1:5454 by default.

## Notes
- The app will create a SQLite DB at `data/detections.db` by default (can be
  overridden with `DATABASE_PATH` in `.env`).
- To enable automated inbox scanning and alerts, set `EMAIL_USERNAME`,
  `EMAIL_PASSWORD`, and appropriate SMTP settings in `.env`.
- For convenience install `python-dotenv` in your venv so the app will
  automatically load `.env` on startup:

  & ".venv\Scripts\python.exe" -m pip install python-dotenv

## Files added by setup
- `config.py` — central configuration (reads from env)
- `ml_model.py` — model wrapper that loads pickled assets from `models/`
- `email_monitor.py` — IMAP scanning logic
- `alert_system.py` — SMTP-based alert sender
- `threat_intelligence.py` — blueprint for threat intel UI and API
- `security_monitor_routes.py` — routes for security monitor UI/API

## Next steps (recommended)
- Add a `requirements.txt` listing `flask` and any other runtime deps.
- Add or retrain the ML model and vectorizer files into `models/`.
- Add tests for the core modules and API endpoints.

## Security
- Do not commit real secrets into the repository. Use `.env` (and keep it out
  of version control) or a secret manager for production deployments.
