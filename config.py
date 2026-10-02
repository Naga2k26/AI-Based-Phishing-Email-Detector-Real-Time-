import os

# Attempt to load environment variables from a .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # dotenv is optional; if it's not installed we fall back to os.environ
    pass


class Config:
    """Application configuration loaded from environment variables.

    Provides sensible defaults so the app can run in development without
    requiring additional setup. Production deployments should set the
    appropriate environment variables or provide a .env file.
    """

    base_dir = os.path.abspath(os.path.dirname(__file__))

    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(base_dir, 'data', 'detections.db'))

    # Email credentials for automated inbox scanning (leave blank to disable)
    EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    EMAIL_HOST = os.environ.get('EMAIL_HOST', 'imap.gmail.com')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 993))

    # Scan interval used by the Scheduler (minutes)
    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 5))

    # Optional alerting / SMTP settings (used by alert system if present)
    ALERT_SMTP_HOST = os.environ.get('ALERT_SMTP_HOST', 'smtp.gmail.com')
    ALERT_SMTP_PORT = int(os.environ.get('ALERT_SMTP_PORT', 587))
    ALERT_FROM = os.environ.get('ALERT_FROM', 'ashajothi2301@gmail.com')

    # Any other defaults can be added here as needed by other modules
