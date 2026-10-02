import sqlite3
from datetime import datetime
import json
from config import Config

class Database:
    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.init_db()
    
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Detection history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                email_subject TEXT,
                email_from TEXT,
                email_to TEXT,
                classification TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_indicators TEXT,
                email_content TEXT,
                quarantined INTEGER DEFAULT 0
            )
        ''')
        
        # Quarantine table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY,
                detection_id INTEGER,
                timestamp TEXT NOT NULL,
                email_data TEXT NOT NULL,
                restored INTEGER DEFAULT 0,
                FOREIGN KEY (detection_id) REFERENCES detections (id)
            )
        ''')
        
        # Automation logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS automation_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            )
        ''')
        
        # Alert history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                detection_id INTEGER,
                alert_type TEXT NOT NULL,
                recipient TEXT,
                status TEXT NOT NULL,
                FOREIGN KEY (detection_id) REFERENCES detections (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_detection(self, email_data, classification, confidence, threat_indicators):
        """Log email detection result"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO detections 
            (timestamp, email_subject, email_from, email_to, classification, 
             confidence, threat_indicators, email_content, quarantined)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            email_data.get('subject', ''),
            email_data.get('from', ''),
            email_data.get('to', ''),
            classification,
            confidence,
            json.dumps(threat_indicators),
            email_data.get('body', ''),
            0
        ))
        
        detection_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return detection_id
    
    def add_to_quarantine(self, detection_id, email_data):
        """Add email to quarantine"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO quarantine (detection_id, timestamp, email_data)
            VALUES (?, ?, ?)
        ''', (detection_id, datetime.now().isoformat(), json.dumps(email_data)))
        
        # Update detection record
        cursor.execute('''
            UPDATE detections SET quarantined = 1 WHERE id = ?
        ''', (detection_id,))
        
        conn.commit()
        conn.close()
    
    def get_detection_history(self, limit=100):
        """Get recent detection history"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM detections 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_statistics(self):
        """Get detection statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total detections
        cursor.execute('SELECT COUNT(*) as total FROM detections')
        total = cursor.fetchone()['total']
        
        # Phishing count
        cursor.execute("SELECT COUNT(*) as count FROM detections WHERE classification = 'phishing'")
        phishing_count = cursor.fetchone()['count']
        
        # Legitimate count
        cursor.execute("SELECT COUNT(*) as count FROM detections WHERE classification = 'legitimate'")
        legitimate_count = cursor.fetchone()['count']
        
        # Quarantined count
        cursor.execute('SELECT COUNT(*) as count FROM detections WHERE quarantined = 1')
        quarantined_count = cursor.fetchone()['count']
        
        # Today's detections
        cursor.execute('''
            SELECT COUNT(*) as count FROM detections 
            WHERE DATE(timestamp) = DATE('now')
        ''')
        today_count = cursor.fetchone()['count']
        
        conn.close()
        
        return {
            'total': total,
            'phishing': phishing_count,
            'legitimate': legitimate_count,
            'quarantined': quarantined_count,
            'today': today_count
        }
    
    def log_automation_action(self, action, status, details=None):
        """Log automation action"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO automation_logs (timestamp, action, status, details)
            VALUES (?, ?, ?, ?)
        ''', (datetime.now().isoformat(), action, status, details))
        
        conn.commit()
        conn.close()
    
    def log_alert(self, detection_id, alert_type, recipient, status):
        """Log alert sent"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, detection_id, alert_type, recipient, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), detection_id, alert_type, recipient, status))
        
        conn.commit()
        conn.close()
