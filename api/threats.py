from http.server import BaseHTTPRequestHandler
import json
import time
from datetime import datetime, timedelta
import re

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
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        response = {
            'threats': threats_database,
            'total': len(threats_database),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.wfile.write(json.dumps(response).encode())
        return

    def do_DELETE(self):
        # Extract threat ID from URL path
        path = self.path
        threat_id_match = re.search(r'/api/threats/(.+)', path)
        
        if not threat_id_match:
            self.send_error_response('Invalid threat ID', 400)
            return
        
        threat_id = threat_id_match.group(1)
        
        # Find and remove the threat
        threat_to_delete = None
        for i, threat in enumerate(threats_database):
            if threat.get('id') == threat_id:
                threat_to_delete = threats_database.pop(i)
                break
        
        if not threat_to_delete:
            self.send_error_response('Threat not found', 404)
            return
        
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
        
        response = {
            'message': 'Threat deleted successfully',
            'deleted_threat': threat_to_delete,
            'total_threats': len(threats_database)
        }
        
        self.send_success_response(response)

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