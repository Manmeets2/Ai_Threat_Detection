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
            stats = {
                'threats': {
                    'total': len(threats_database),
                    'by_severity': analytics_data['threats_by_severity'],
                    'by_type': analytics_data['threats_by_type']
                },
                'alerts': {
                    'total': 0,
                    'recent': 0
                },
                'system': {
                    'uptime': '100%',
                    'memory_usage': '45%',
                    'cpu_usage': '23%',
                    'disk_usage': '12%'
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.send_success_response(stats)
            
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