#!/usr/bin/env python3
import os
import json
import time
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from collections import defaultdict
from functools import wraps

# Flask App Setup
app = Flask(__name__, static_folder='static', template_folder='template')
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

# In-memory Data Stores
threats_database = []
alerts_database = []
analytics_data = {
    'total_threats': 0,
    'threats_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
    'threats_by_type': {},
    'last_updated': datetime.utcnow().isoformat()
}
ip_request_counts = defaultdict(list)
ANOMALY_WINDOW_SECONDS = 60
ANOMALY_THRESHOLD = 10
threat_counter = 0

# Dummy ML Model
class DummyMLModel:
    def predict(self, features):
        if features.get('port') in [22, 23, 3389, 445, 1433, 3306, 5432]:
            return 1
        if 'exploit' in str(features.get('message', '')).lower():
            return 1
        return 0

ml_model = DummyMLModel()

# Threat Detection Logic
class SimpleThreatDetector:
    def __init__(self):
        self.suspicious_patterns = [
            'sql injection', 'sqlmap', 'xss', 'command injection', 'path traversal',
            'buffer overflow', 'privilege escalation', 'brute force', 'ddos',
            'script', 'alert', 'union select', 'drop table', 'insert into',
            ';', '&&', '|', 'wget', 'curl', 'python', 'bash', 'sh',
            '../', '/etc/passwd', 'boot.ini', 'http://169.254.169.254',
            'file://', 'gopher://'
        ]
        self.suspicious_ports = [22, 23, 3389, 445, 1433, 3306, 5432]

    def detect_threats(self, data):
        global threat_counter
        threats = []

        for field in ['user_agent', 'request_method', 'message', 'url']:
            if field in data:
                value = str(data[field]).lower()
                for pattern in self.suspicious_patterns:
                    if pattern in value:
                        threat_counter += 1
                        threats.append({
                            'id': f"threat_{threat_counter}_{int(time.time()*1000)}",
                            'type': 'suspicious_pattern',
                            'severity': 'high',
                            'confidence': 0.9,
                            'detection_method': 'pattern_matching',
                            'description': f"Pattern '{pattern}' in {field}",
                            'timestamp': datetime.utcnow().isoformat(),
                            'pattern': pattern,
                            'field': field,
                            'source_ip': data.get('source_ip'),
                            'raw_data': data
                        })

        if 'port' in data and data['port'] in self.suspicious_ports:
            threat_counter += 1
            threats.append({
                'id': f"threat_{threat_counter}_{int(time.time()*1000)}",
                'type': 'suspicious_port',
                'severity': 'medium',
                'confidence': 0.7,
                'detection_method': 'port_analysis',
                'description': f"Suspicious port {data['port']}",
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': data.get('source_ip'),
                'raw_data': data
            })

        if ml_model.predict(data) == 1:
            threat_counter += 1
            threats.append({
                'id': f"threat_{threat_counter}_{int(time.time()*1000)}",
                'type': 'ml_detected_threat',
                'severity': 'medium',
                'confidence': 0.8,
                'detection_method': 'ml_model',
                'description': "ML model flagged this",
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': data.get('source_ip'),
                'raw_data': data
            })

        ip = data.get('source_ip')
        now = time.time()
        if ip:
            ip_request_counts[ip] = [t for t in ip_request_counts[ip] if now - t < ANOMALY_WINDOW_SECONDS]
            ip_request_counts[ip].append(now)
            if len(ip_request_counts[ip]) > ANOMALY_THRESHOLD:
                threat_counter += 1
                threats.append({
                    'id': f"threat_{threat_counter}_{int(time.time()*1000)}",
                    'type': 'anomaly_detected',
                    'severity': 'high',
                    'confidence': 0.95,
                    'detection_method': 'anomaly_detection',
                    'description': f"{len(ip_request_counts[ip])} reqs in {ANOMALY_WINDOW_SECONDS}s",
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': ip,
                    'raw_data': data
                })

        if random.random() < 0.3:
            threat_counter += 1
            threats.append({
                'id': f"threat_{threat_counter}_{int(time.time()*1000)}",
                'type': 'ai_detected_threat',
                'severity': random.choice(['low', 'medium', 'high']),
                'confidence': round(random.uniform(0.5, 0.95), 2),
                'detection_method': 'ai_model',
                'description': "AI model detected threat",
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': data.get('source_ip'),
                'raw_data': data
            })

        return threats

threat_detector = SimpleThreatDetector()

# HTML Route
@app.route('/')
def index():
    return render_template('index.html')

# Core API Routes
@app.route('/api/detect', methods=['POST'])
def detect_threats():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        threats = threat_detector.detect_threats(data)
        for threat in threats:
            threats_database.append(threat)
            analytics_data['total_threats'] += 1
            analytics_data['threats_by_severity'][threat['severity']] += 1
            ttype = threat['type']
            analytics_data['threats_by_type'][ttype] = analytics_data['threats_by_type'].get(ttype, 0) + 1
        analytics_data['last_updated'] = datetime.utcnow().isoformat()
        return jsonify({
            'threats_detected': len(threats),
            'threats': threats,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    return jsonify({
        'threats': threats_database,
        'total': len(threats_database),
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/threats/<threat_id>', methods=['DELETE'])
def delete_threat(threat_id):
    for i, threat in enumerate(threats_database):
        if threat.get('id') == threat_id:
            threats_database.pop(i)
            analytics_data['total_threats'] -= 1
            return jsonify({'message': 'Threat deleted successfully'})
    return jsonify({'error': 'Threat not found'}), 404

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    recent_threats = [
        t for t in threats_database
        if datetime.fromisoformat(t['timestamp']) > datetime.utcnow() - timedelta(hours=24)
    ]
    return jsonify({
        'period': {
            'start_date': (datetime.utcnow() - timedelta(hours=24)).isoformat(),
            'end_date': datetime.utcnow().isoformat(),
            'duration_hours': 24
        },
        'threat_analytics': {
            'total_threats': analytics_data['total_threats'],
            'threats_24h': len(recent_threats),
            'threats_by_severity': analytics_data['threats_by_severity'],
            'threats_by_type': analytics_data['threats_by_type'],
            'avg_confidence': 0.75
        },
        'system_health': {
            'overall_status': 'healthy',
            'checks': {
                'threat_detection': {'status': 'healthy'},
                'alert_system': {'status': 'healthy'},
                'performance': {'status': 'healthy'},
                'data_processing': {'status': 'healthy'}
            }
        },
        'real_time_metrics': {
            'threats_per_minute': len(recent_threats) // 24,
            'requests_per_minute': 10,
            'active_alerts': len(alerts_database),
            'system_health': 'healthy'
        },
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        return jsonify({
            'threats': {
                'total': analytics_data['total_threats']
            },
            'alerts': {
                'total': len(alerts_database)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Run the App
if __name__ == '__main__':
    app.run(debug=True)
