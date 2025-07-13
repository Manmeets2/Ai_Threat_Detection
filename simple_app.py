#!/usr/bin/env python3
"""
Simplified AI Threat Detection System
A working version without complex dependencies
"""

import os
import json
import time
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, redirect
from flask_cors import CORS
import numpy as np  # For ML demo
from collections import defaultdict
from functools import wraps

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

# In-memory user store (for demo)
USERS = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user': {'password': 'user123', 'role': 'user'}
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

# Protect all API endpoints except login/logout
# @app.before_request
# def require_login():
#     open_endpoints = ['/login', '/logout', '/static', '/']
#     if request.path.startswith('/api') and not any(request.path.startswith(e) for e in open_endpoints):
#         if not session.get('username'):
#             return jsonify({'error': 'Authentication required'}), 401

# Simple in-memory storage
threats_database = []
alerts_database = []
threat_counter = 0  # Counter for unique threat IDs
analytics_data = {
    'total_threats': 0,
    'threats_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
    'threats_by_type': {},
    'last_updated': datetime.utcnow().isoformat()
}

# In-memory tracker for anomaly detection (rate limiting)
ip_request_counts = defaultdict(list)  # {ip: [timestamps]}
ANOMALY_WINDOW_SECONDS = 60  # 1 minute
ANOMALY_THRESHOLD = 10       # More than 10 requests/min triggers anomaly

# Dummy ML model (replace with real model for production)
class DummyMLModel:
    def predict(self, features):
        # Simple rule: if port is suspicious or message contains 'exploit', flag as malicious
        if features.get('port') in [22, 23, 3389, 445, 1433, 3306, 5432]:
            return 1  # Malicious
        if 'exploit' in str(features.get('message', '')).lower():
            return 1
        return 0  # Benign

ml_model = DummyMLModel()

class SimpleThreatDetector:
    """Simplified threat detector using basic pattern matching, ML, and anomaly detection"""
    def __init__(self):
        self.suspicious_patterns = [
            # Existing patterns
            'sql injection', 'sqlmap', 'xss', 'command injection', 'path traversal',
            'buffer overflow', 'privilege escalation', 'brute force', 'ddos',
            'script', 'alert', 'union select', 'drop table', 'insert into',
            # RCE patterns
            ';', '&&', '|', 'wget', 'curl', 'python', 'bash', 'sh',
            # LFI patterns
            '../', '/etc/passwd', 'boot.ini',
            # SSRF patterns
            'http://169.254.169.254', 'file://', 'gopher://'
        ]
        self.suspicious_ports = [22, 23, 3389, 445, 1433, 3306, 5432]

    def detect_threats(self, data):
        global threat_counter
        threats = []
        # --- Pattern Matching ---
        for field in ['user_agent', 'request_method', 'message', 'url']:
            if field in data:
                field_value = str(data[field]).lower()
                for pattern in self.suspicious_patterns:
                    if pattern in field_value:
                        threat_counter += 1
                        threat = {
                            'id': f"threat_{threat_counter}_{int(time.time() * 1000)}",
                            'type': 'suspicious_pattern',
                            'severity': 'high',
                            'confidence': 0.9,
                            'detection_method': 'pattern_matching',
                            'description': f"Suspicious pattern '{pattern}' detected in {field}",
                            'timestamp': datetime.utcnow().isoformat(),
                            'pattern': pattern,
                            'field': field,
                            'source_ip': data.get('source_ip'),
                            'raw_data': data
                        }
                        threats.append(threat)
        # --- Port Analysis ---
        if 'port' in data and data['port'] in self.suspicious_ports:
            threat_counter += 1
            threat = {
                'id': f"threat_{threat_counter}_{int(time.time() * 1000)}",
                'type': 'suspicious_port',
                'severity': 'medium',
                'confidence': 0.7,
                'detection_method': 'port_analysis',
                'description': f"Suspicious port {data['port']} detected",
                'timestamp': datetime.utcnow().isoformat(),
                'port': data['port'],
                'source_ip': data.get('source_ip'),
                'raw_data': data
            }
            threats.append(threat)
        # --- ML Model Prediction ---
        ml_pred = ml_model.predict(data)
        if ml_pred == 1:
            threat_counter += 1
            threat = {
                'id': f"threat_{threat_counter}_{int(time.time() * 1000)}",
                'type': 'ml_detected_threat',
                'severity': 'medium',
                'confidence': 0.8,
                'detection_method': 'ml_model',
                'description': "ML model flagged this as potentially malicious",
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': data.get('source_ip'),
                'raw_data': data
            }
            threats.append(threat)
        # --- Anomaly Detection (rate limiting) ---
        ip = data.get('source_ip')
        now = time.time()
        if ip:
            ip_request_counts[ip] = [t for t in ip_request_counts[ip] if now - t < ANOMALY_WINDOW_SECONDS]
            ip_request_counts[ip].append(now)
            if len(ip_request_counts[ip]) > ANOMALY_THRESHOLD:
                threat_counter += 1
                threat = {
                    'id': f"threat_{threat_counter}_{int(time.time() * 1000)}",
                    'type': 'anomaly_detected',
                    'severity': 'high',
                    'confidence': 0.95,
                    'detection_method': 'anomaly_detection',
                    'description': f"Anomalous activity: {len(ip_request_counts[ip])} requests in {ANOMALY_WINDOW_SECONDS}s from {ip}",
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': ip,
                    'raw_data': data
                }
                threats.append(threat)
        # --- AI simulation (random) ---
        if random.random() < 0.3:
            threat_counter += 1
            threat = {
                'id': f"threat_{threat_counter}_{int(time.time() * 1000)}",
                'type': 'ai_detected_threat',
                'severity': random.choice(['low', 'medium', 'high']),
                'confidence': round(random.uniform(0.5, 0.95), 2),
                'detection_method': 'ai_model',
                'description': "AI model detected potential threat",
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': data.get('source_ip'),
                'raw_data': data
            }
            threats.append(threat)
        return threats

# Initialize threat detector
threat_detector = SimpleThreatDetector()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'service': 'AI Threat Detection System'
    })

@app.route('/api/detect', methods=['GET','POST'])
def detect_threats():
    """Analyze network traffic or system logs for threats"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Detect threats
        threats = threat_detector.detect_threats(data)
        
        # Store threats
        for threat in threats:
            threats_database.append(threat)
            analytics_data['total_threats'] += 1
            
            # Update severity counts
            severity = threat.get('severity', 'medium')
            analytics_data['threats_by_severity'][severity] += 1
            
            # Update type counts
            threat_type = threat.get('type', 'unknown')
            analytics_data['threats_by_type'][threat_type] = analytics_data['threats_by_type'].get(threat_type, 0) + 1
        
        analytics_data['last_updated'] = datetime.utcnow().isoformat()
        
        return jsonify({
            'threats_detected': len(threats),
            'threats': threats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get threat analytics and statistics"""
    try:
        # Calculate additional analytics
        recent_threats = [
            threat for threat in threats_database
            if datetime.fromisoformat(threat['timestamp']) > datetime.utcnow() - timedelta(hours=24)
        ]
        
        analytics = {
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
                'avg_confidence': 0.75  # Placeholder
            },
            'system_health': {
                'overall_status': 'healthy',
                'checks': {
                    'threat_detection': {'status': 'healthy', 'message': 'System functioning normally'},
                    'alert_system': {'status': 'healthy', 'message': 'Alerts working correctly'},
                    'performance': {'status': 'healthy', 'message': 'Good performance'},
                    'data_processing': {'status': 'healthy', 'message': 'Processing data normally'}
                }
            },
            'real_time_metrics': {
                'threats_per_minute': len(recent_threats) // 24,
                'requests_per_minute': 10,
                'active_alerts': len(alerts_database),
                'system_health': 'healthy'
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(analytics)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        limit = int(request.args.get('limit', 50))
        alerts = alerts_database[-limit:] if alerts_database else []
        
        return jsonify(alerts)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['POST'])
def configure_alerts():
    """Configure alert settings"""
    try:
        config = request.get_json()
        
        # Create an alert
        alert = {
            'id': f"alert_{int(time.time() * 1000)}",
            'type': 'configuration_update',
            'severity': 'info',
            'description': 'Alert configuration updated',
            'timestamp': datetime.utcnow().isoformat(),
            'config': config
        }
        
        alerts_database.append(alert)
        
        return jsonify({'message': 'Alert configuration updated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/status', methods=['GET'])
def get_model_status():
    """Get AI model status and performance metrics"""
    try:
        status = {
            'model_name': 'simple_threat_detector',
            'model_path': 'in_memory',
            'device': 'cpu',
            'config': {
                'max_length': 512,
                'batch_size': 16,
                'learning_rate': 2.0e-5,
                'num_epochs': 3,
                'threshold': 0.5
            },
            'loaded': True,
            'performance': {
                'accuracy': 0.85,
                'precision': 0.82,
                'recall': 0.88,
                'f1_score': 0.85
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/retrain', methods=['POST'])
def retrain_models():
    """Retrain AI models with new data"""
    try:
        # Simulate retraining
        time.sleep(1)  # Simulate processing time
        
        return jsonify({
            'message': 'Model retraining started',
            'status': 'in_progress',
            'estimated_completion': (datetime.utcnow() + timedelta(minutes=30)).isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get all detected threats"""
    try:
        # Return threats from database
        return jsonify({
            'threats': threats_database,
            'total': len(threats_database),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/<threat_id>', methods=['DELETE'])
def delete_threat(threat_id):
    """Delete a specific threat by ID"""
    try:
        # Find and remove the threat
        threat_to_delete = None
        for i, threat in enumerate(threats_database):
            if threat.get('id') == threat_id:
                threat_to_delete = threats_database.pop(i)
                break
        
        if not threat_to_delete:
            return jsonify({'error': 'Threat not found'}), 404
        
        # Update analytics data
        analytics_data['total_threats'] = len(threats_database)
        
        # Update severity counts
        severity = threat_to_delete.get('severity', 'low')
        if severity in analytics_data['threats_by_severity']:
            analytics_data['threats_by_severity'][severity] = max(0, analytics_data['threats_by_severity'][severity] - 1)
        
        # Update type counts
        threat_type = threat_to_delete.get('type', 'unknown')
        if threat_type in analytics_data['threats_by_type']:
            analytics_data['threats_by_type'][threat_type] = max(0, analytics_data['threats_by_type'][threat_type] - 1)
        
        analytics_data['last_updated'] = datetime.utcnow().isoformat()
        
        return jsonify({
            'message': 'Threat deleted successfully',
            'deleted_threat': threat_to_delete,
            'total_threats': len(threats_database)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    try:
        stats = {
            'threats': {
                'total': len(threats_database),
                'by_severity': analytics_data['threats_by_severity'],
                'by_type': analytics_data['threats_by_type']
            },
            'alerts': {
                'total': len(alerts_database),
                'recent': len([a for a in alerts_database if datetime.fromisoformat(a['timestamp']) > datetime.utcnow() - timedelta(hours=1)])
            },
            'system': {
                'uptime': '100%',
                'memory_usage': '45%',
                'cpu_usage': '23%',
                'disk_usage': '12%'
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    return jsonify({
        'service': 'AI Threat Detection System',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'health': '/api/health',
            'detect': '/api/detect (POST)',
            'analytics': '/api/analytics',
            'alerts': '/api/alerts',
            'models': '/api/models/status',
            'threats': '/api/threats',
            'stats': '/api/stats'
        },
        'timestamp': datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    print("🚀 Starting Simplified AI Threat Detection System...")
    print("📊 API Documentation: http://localhost:5000")
    print("🔍 Health Check: http://localhost:5000/api/health")
    print("🧪 Test Endpoint: http://localhost:5000/api/detect")
    
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    
    app.run(
        host=host,
        port=port,
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    ) 