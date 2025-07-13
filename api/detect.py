from http.server import BaseHTTPRequestHandler
import json
import time
import random
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
import os

# Global storage (in production, use a database)
threats_database = []
analytics_data = {
    'total_threats': 0,
    'threats_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
    'threats_by_type': {},
    'last_updated': datetime.utcnow().isoformat()
}

class SimpleThreatDetector:
    def __init__(self):
        self.suspicious_patterns = [
            'sql injection', 'sqlmap', 'xss', 'command injection', 'path traversal',
            'buffer overflow', 'privilege escalation', 'brute force', 'ddos',
            'script', 'alert', 'union select', 'drop table', 'insert into',
            ';', '&&', '|', 'wget', 'curl', 'python', 'bash', 'sh',
            '../', '/etc/passwd', 'boot.ini',
            'http://169.254.169.254', 'file://', 'gopher://'
        ]
        self.suspicious_ports = [22, 23, 3389, 445, 1433, 3306, 5432]

    def detect_threats(self, data):
        threats = []
        
        # Pattern Matching
        for field in ['user_agent', 'request_method', 'message', 'url']:
            if field in data:
                field_value = str(data[field]).lower()
                for pattern in self.suspicious_patterns:
                    if pattern in field_value:
                        threat = {
                            'id': f"threat_{int(time.time() * 1000)}",
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
        
        # Port Analysis
        if 'port' in data and data['port'] in self.suspicious_ports:
            threat = {
                'id': f"threat_{int(time.time() * 1000)}",
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
        
        # AI simulation
        if random.random() < 0.3:
            threat = {
                'id': f"threat_{int(time.time() * 1000)}",
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

threat_detector = SimpleThreatDetector()

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        response = {
            'message': 'Use POST method to detect threats',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.wfile.write(json.dumps(response).encode())
        return

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            
            if not data:
                self.send_error_response('No data provided', 400)
                return
            
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
            
            response = {
                'threats_detected': len(threats),
                'threats': threats,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.send_success_response(response)
            
        except json.JSONDecodeError:
            self.send_error_response('Invalid JSON data', 400)
        except Exception as e:
            self.send_error_response(str(e), 500)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        return

    def send_success_response(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_error_response(self, message, status_code):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        response = {'error': message}
        self.wfile.write(json.dumps(response).encode()) 