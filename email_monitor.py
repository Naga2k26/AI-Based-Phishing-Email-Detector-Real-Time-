import time
import imaplib
import logging
import email
from email import policy
from typing import List

from config import Config
from ml_model import PhishingDetector
from database import Database


logger = logging.getLogger(__name__)


class EmailMonitor:
    """Basic email monitor that connects to an IMAP server and scans the inbox.

    This implementation is intentionally defensive: if credentials or network
    access are not available it will fail cleanly (returning False from
    `connect`) instead of raising exceptions.
    """

    def __init__(self, detector: PhishingDetector = None, db: Database = None):
        self.detector = detector or PhishingDetector()
        self.db = db or Database()
        self.imap = None
        self.running = False

    def connect(self) -> bool:
        """Attempt to connect and login to the IMAP server."""
        if not Config.EMAIL_USERNAME or not Config.EMAIL_PASSWORD:
            return False

        try:
            self.imap = imaplib.IMAP4_SSL(Config.EMAIL_HOST, Config.EMAIL_PORT)
            self.imap.login(Config.EMAIL_USERNAME, Config.EMAIL_PASSWORD)
            return True
        except Exception as e:
            logger.debug('IMAP connect failed: %s', e)
            self.imap = None
            return False

    def disconnect(self):
        """Logout and clean up the IMAP connection."""
        try:
            if self.imap:
                try:
                    self.imap.logout()
                except Exception:
                    pass
        finally:
            self.imap = None

    def scan_inbox(self) -> List[dict]:
        """Scan the inbox for unseen messages, analyze them, and log results.

        Returns a list of processed detection dicts (may be empty).
        """
        results = []
        if not self.connect():
            return results

        try:
            self.imap.select('INBOX')
            typ, data = self.imap.search(None, 'UNSEEN')
            if typ != 'OK':
                return results

            msg_ids = data[0].split()
            for mid in msg_ids:
                try:
                    typ, msg_data = self.imap.fetch(mid, '(RFC822)')
                    if typ != 'OK':
                        continue
                    raw = msg_data[0][1]
                    msg = email.message_from_bytes(raw, policy=policy.default)

                    # Extract basic fields
                    subject = msg.get('subject', '')
                    from_ = msg.get('from', '')
                    to = msg.get('to', '')
                    body = ''
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == 'text/plain':
                                body += part.get_content()
                    else:
                        body = msg.get_content()

                    # Run through detector
                    pred = self.detector.predict(body)

                    # Attach basic email_data
                    pred['email_data'].update({'subject': subject, 'from': from_, 'to': to})

                    # Log to DB
                    try:
                        self.db.log_detection(pred['email_data'], pred['classification'], pred['confidence'], pred['threat_indicators'])
                    except Exception:
                        logger.exception('Failed to log detection')

                    # Mark message seen
                    try:
                        self.imap.store(mid, '+FLAGS', '\\Seen')
                    except Exception:
                        pass

                    results.append(pred)
                except Exception:
                    logger.exception('Failed to process message %s', mid)

            return results
        finally:
            self.disconnect()

    def start_monitoring(self):
        """Run continuous monitoring until `stop_monitoring` is called."""
        self.running = True
        while self.running:
            try:
                self.scan_inbox()
            except Exception:
                logger.exception('Error during scan')
            time.sleep(max(1, Config.SCAN_INTERVAL_MINUTES * 60))

    def stop_monitoring(self):
        self.running = False
        # ensure any open connection is closed
        self.disconnect()
