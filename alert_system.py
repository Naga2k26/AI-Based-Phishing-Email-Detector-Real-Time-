import smtplib
import logging
from email.message import EmailMessage

from config import Config
from database import Database


logger = logging.getLogger(__name__)


class AlertSystem:
    """Basic alerting system that can send email alerts and record them to the DB."""

    def __init__(self, db: Database = None):
        self.db = db or Database()

    def send_email(self, recipient: str, subject: str, body: str) -> bool:
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = Config.ALERT_FROM
            msg['To'] = recipient
            msg.set_content(body)

            with smtplib.SMTP(Config.ALERT_SMTP_HOST, Config.ALERT_SMTP_PORT, timeout=10) as smtp:
                try:
                    smtp.starttls()
                except Exception:
                    pass
                # Try login with email creds if available
                if Config.EMAIL_USERNAME and Config.EMAIL_PASSWORD:
                    try:
                        smtp.login(Config.EMAIL_USERNAME, Config.EMAIL_PASSWORD)
                    except Exception:
                        logger.debug('SMTP login failed, continuing without auth')
                smtp.send_message(msg)

            return True
        except Exception:
            logger.exception('Failed to send alert email')
            return False

    def log_alert(self, detection_id, alert_type, recipient, status):
        try:
            self.db.log_alert(detection_id, alert_type, recipient, status)
        except Exception:
            logger.exception('Failed to log alert to DB')
