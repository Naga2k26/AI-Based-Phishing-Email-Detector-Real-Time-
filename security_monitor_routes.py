import json
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request

from database import Database
from email_monitor import EmailMonitor
from alert_system import AlertSystem
from config import Config


security_monitor_bp = Blueprint('security_monitor_bp', __name__)


@security_monitor_bp.route('/security-monitor')
def ui_page():
    return render_template('security_monitor.html')


@security_monitor_bp.route('/api/security/stats')
def api_stats():
    db = Database()
    stats = db.get_statistics()

    return jsonify({
        'total_events': stats.get('total', 0),
        'critical': stats.get('phishing', 0),
        'high': 0,
        'medium': 0,
        'by_type': {
            'phishing': stats.get('phishing', 0),
            'legitimate': stats.get('legitimate', 0)
        }
    })


@security_monitor_bp.route('/api/security/scan', methods=['POST'])
def api_scan():
    payload = request.get_json() or {}
    days = int(payload.get('days', 1))

    monitor = EmailMonitor()
    try:
        results = monitor.scan_inbox()
        return jsonify({'success': True, 'events_found': len(results)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@security_monitor_bp.route('/api/security/events')
def api_events():
    hours = int(request.args.get('hours', 168))
    severity = request.args.get('severity')

    db = Database()
    history = db.get_detection_history(limit=1000)

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    events = []
    for item in history:
        try:
            ts = datetime.fromisoformat(item.get('timestamp'))
        except Exception:
            continue
        if ts < cutoff:
            continue

        classification = item.get('classification', 'unknown')
        sev = 'CRITICAL' if classification == 'phishing' else 'LOW'
        if severity and sev != severity:
            continue

        indicators = []
        try:
            indicators = json.loads(item.get('threat_indicators') or '[]')
        except Exception:
            indicators = []

        events.append({
            'id': item.get('id'),
            'timestamp': item.get('timestamp'),
            'event_type': 'phishing_detection' if classification == 'phishing' else 'detection',
            'severity': sev,
            'email_from': item.get('email_from'),
            'email_subject': item.get('email_subject'),
            'indicators': indicators
        })

    return jsonify({'events': events})


@security_monitor_bp.route('/api/security/report')
def api_report():
    db = Database()
    stats = db.get_statistics()

    summary = (
        f"Security Report - {datetime.utcnow().isoformat()}\n"
        f"Total detections: {stats.get('total', 0)}\n"
        f"Phishing: {stats.get('phishing', 0)}\n"
        f"Legitimate: {stats.get('legitimate', 0)}\n"
    )

    return jsonify({'summary': summary})


@security_monitor_bp.route('/api/security/alert', methods=['POST'])
def api_alert():
    payload = request.get_json() or {}
    event_id = payload.get('event_id')
    alert_type = payload.get('alert_type', 'email')

    db = Database()
    history = db.get_detection_history(limit=1000)
    event = next((e for e in history if e.get('id') == event_id), None)
    if not event:
        return jsonify({'success': False, 'error': 'Event not found'}), 404

    recipient = Config.ALERT_FROM or Config.EMAIL_USERNAME
    subject = f"Security Alert: {event.get('classification')} detected"
    body = f"Event details:\nID: {event.get('id')}\nTime: {event.get('timestamp')}\nSubject: {event.get('email_subject')}\nFrom: {event.get('email_from')}"

    alerter = AlertSystem()
    ok = alerter.send_email(recipient, subject, body)
    alerter.log_alert(event.get('id'), alert_type, recipient, 'success' if ok else 'failed')

    if ok:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to send alert'}), 500
