from flask import Flask, render_template, request, jsonify
from datetime import datetime
import threading
from config import Config
from database import Database
from ml_model import PhishingDetector
from email_monitor import EmailMonitor
from scheduler import Scheduler
from alert_system import AlertSystem
from threat_intelligence import threat_intel
from security_monitor_routes import security_monitor_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Register blueprints
app.register_blueprint(threat_intel)
app.register_blueprint(security_monitor_bp)

# Initialize components
db = Database()
detector = PhishingDetector()
email_monitor = EmailMonitor()
scheduler = Scheduler()
alert_system = AlertSystem()

# Monitoring state
monitoring_active = False
monitoring_thread = None

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/automation')
def automation_page():
    """Automation configuration page"""
    return render_template('automation.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """Analyze email content for phishing"""
    try:
        data = request.get_json()
        email_content = data.get('email', '')
        
        if not email_content:
            return jsonify({'error': 'No email content provided'}), 400
        
        # Analyze with ML model
        result = detector.predict(email_content)
        
        # Log to database
        db.log_detection(
            result['email_data'],
            result['classification'],
            result['confidence'],
            result['threat_indicators']
        )
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def get_history():
    """Get detection history"""
    try:
        limit = request.args.get('limit', 100, type=int)
        history = db.get_detection_history(limit)
        
        # Parse threat indicators
        for item in history:
            import json
            if item.get('threat_indicators'):
                try:
                    item['threat_indicators'] = json.loads(item['threat_indicators'])
                except:
                    item['threat_indicators'] = []
        
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get detection statistics"""
    try:
        stats = db.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/automation/start', methods=['POST'])
def start_automation():
    """Start automated email monitoring"""
    global monitoring_active, monitoring_thread
    
    try:
        if monitoring_active:
            return jsonify({'error': 'Monitoring already active'}), 400
        
        # Check if email is configured
        if not Config.EMAIL_USERNAME or not Config.EMAIL_PASSWORD:
            return jsonify({
                'error': 'Email credentials not configured',
                'message': 'Please configure EMAIL_USERNAME and EMAIL_PASSWORD in .env file to enable automation'
            }), 400
        
        # Test connection first
        test_monitor = EmailMonitor()
        if not test_monitor.connect():
            test_monitor.disconnect()
            return jsonify({
                'error': 'Failed to connect to email server',
                'message': 'Please check your email credentials and server settings in .env file'
            }), 400
        test_monitor.disconnect()
        
        # Start monitoring
        monitoring_active = True
        monitoring_thread = threading.Thread(target=email_monitor.start_monitoring, daemon=True)
        monitoring_thread.start()
        
        scheduler.start()
        scheduler.add_email_scan_job(email_monitor.scan_inbox)
        
        db.log_automation_action('monitoring_start', 'success', 'Email monitoring started')
        
        return jsonify({
            'success': True,
            'message': 'Email monitoring started successfully',
            'interval': Config.SCAN_INTERVAL_MINUTES
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Failed to start monitoring. Check server logs for details.'
        }), 500

@app.route('/api/automation/stop', methods=['POST'])
def stop_automation():
    """Stop automated email monitoring"""
    global monitoring_active
    
    try:
        if not monitoring_active:
            return jsonify({'error': 'Monitoring not active'}), 400
        
        monitoring_active = False
        email_monitor.stop_monitoring()
        scheduler.stop()
        
        db.log_automation_action('monitoring_stop', 'success', 'Email monitoring stopped')
        
        return jsonify({
            'success': True,
            'message': 'Email monitoring stopped'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/automation/status')
def automation_status():
    """Get automation status"""
    try:
        jobs = scheduler.get_jobs() if scheduler.scheduler.running else []
        
        return jsonify({
            'active': monitoring_active,
            'scheduler_running': scheduler.scheduler.running,
            'jobs': jobs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """Test email server connection"""
    try:
        if not Config.EMAIL_USERNAME or not Config.EMAIL_PASSWORD:
            return jsonify({
                'error': 'Email credentials not configured',
                'message': 'Please add EMAIL_USERNAME and EMAIL_PASSWORD to your .env file',
                'help': 'Copy .env.example to .env and fill in your email credentials'
            }), 400
        
        test_monitor = EmailMonitor()
        if test_monitor.connect():
            test_monitor.disconnect()
            return jsonify({
                'success': True,
                'message': 'Successfully connected to email server!',
                'server': Config.EMAIL_HOST,
                'username': Config.EMAIL_USERNAME
            })
        else:
            return jsonify({
                'error': 'Connection failed',
                'message': 'Could not connect to email server. Please check your credentials and server settings.',
                'server': Config.EMAIL_HOST,
                'port': Config.EMAIL_PORT
            }), 500
    except Exception as e:
        return jsonify({
            'error': 'Connection error',
            'message': str(e),
            'help': 'Make sure your email server allows IMAP connections and check your firewall settings'
        }), 500

if __name__ == '__main__':
    print("="*60)
    print("AI-Based Phishing Email Detector")
    print("Developed by Naga")
    print("="*60)
    print(f"Starting server at http://localhost:5454")
    print("Press Ctrl+C to stop")
    print("="*60)
    
    app.run(debug=True, host='0.0.0.0', port=5454)
