import json
import os
from flask import Blueprint, render_template, jsonify

from database import Database


threat_intel = Blueprint('threat_intel', __name__)


@threat_intel.route('/threat-intel')
def ui_page():
    return render_template('threat_intel.html')


@threat_intel.route('/api/threat-intel/overview')
def api_overview():
    db = Database()
    stats = db.get_statistics()

    total = stats.get('total', 0)
    phishing = stats.get('phishing', 0)

    score_val = (phishing / total * 100) if total else 0
    if score_val > 70:
        level = 'CRITICAL'
    elif score_val > 40:
        level = 'HIGH'
    elif score_val > 10:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    # Load known patterns to include in the response
    patterns_path = os.path.join(os.path.dirname(__file__), 'data', 'phishing_patterns.json')
    patterns = {}
    try:
        with open(patterns_path, 'r', encoding='utf-8') as f:
            patterns = json.load(f)
    except Exception:
        patterns = {}

    return jsonify({
        'threat_score': {
            'score': float(score_val),
            'level': level,
            'recent_threats': phishing,
            'avg_confidence': 0.5
        },
        'emerging_patterns': {
            'patterns': patterns,
            'total_threats': phishing
        },
        'attack_techniques': {},
        'trends': {}
    })
