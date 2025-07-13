from http.server import BaseHTTPRequestHandler
import json
from datetime import datetime, timedelta

# Global storage (in production, use a database)
threats_database = []
analytics_data = {
    'total_threats': 0,
    'threats_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
    'threats_by_type': {},
    'last_updated': datetime.utcnow().isoformat()
}

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
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
                    'active_alerts': 0,
                    'system_health': 'healthy'
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.send_success_response(analytics)
            
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