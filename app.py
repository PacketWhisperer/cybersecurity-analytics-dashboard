from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from collections import defaultdict
import re
import json
import os
import requests
from datetime import datetime
import tempfile

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Allowed file extensions
ALLOWED_EXTENSIONS = {'log', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_ip_geolocation(ip):
    """Get geolocation data for an IP address"""
    try:
        # Using a free IP geolocation service
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
    except:
        pass
    return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

def analyze_log_content(content):
    """Analyze log content and return structured data"""
    failed_ips = defaultdict(int)
    failed_users = defaultdict(int)
    attack_timeline = []
    
    lines = content.split('\n')
    
    for line in lines:
        if "Failed password" in line:
            # Extract IP address
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            # Extract username
            user_match = re.search(r'Failed password for (\w+)', line)
            # Extract timestamp
            time_match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            
            if ip_match:
                ip = ip_match.group(1)
                failed_ips[ip] += 1
                
                if user_match and time_match:
                    user = user_match.group(1)
                    timestamp = time_match.group(1)
                    failed_users[user] += 1
                    
                    attack_timeline.append({
                        'timestamp': timestamp,
                        'ip': ip,
                        'user': user
                    })
    
    # Analyze threat levels and get geolocation
    threat_analysis = []
    for ip, count in failed_ips.items():
        threat_level = "🔴 High Risk" if count >= 10 else "🟡 Medium Risk" if count >= 5 else "🟢 Low Risk" if count >= 3 else "✅ Normal"
        geo_data = get_ip_geolocation(ip)
        
        threat_analysis.append({
            'ip': ip,
            'count': count,
            'threat_level': threat_level,
            'country': geo_data['country'],
            'city': geo_data['city'],
            'isp': geo_data['isp']
        })
    
    # Sort by count (most attempts first)
    threat_analysis.sort(key=lambda x: x['count'], reverse=True)
    
    return {
        'ip_analysis': threat_analysis,
        'user_analysis': [{'user': user, 'count': count} for user, count in failed_users.items()],
        'timeline': attack_timeline[-20:],  # Last 20 events
        'total_failed_attempts': sum(failed_ips.values()),
        'unique_ips': len(failed_ips),
        'unique_users': len(failed_users)
    }

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # Read file content directly from memory
            content = file.read().decode('utf-8')
            analysis_result = analyze_log_content(content)
            return jsonify(analysis_result)
        except Exception as e:
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file type. Please upload .log or .txt files'}), 400

@app.route('/sample-data')
def sample_data():
    """Return sample data for demo purposes"""
    sample_content = """Jul  3 06:42:21 server sshd[12345]: Failed password for root from 192.168.1.10 port 22 ssh2
Jul  3 06:42:22 server sshd[12346]: Failed password for root from 192.168.1.10 port 22 ssh2
Jul  3 06:42:23 server sshd[12347]: Failed password for root from 192.168.1.10 port 22 ssh2
Jul  3 06:43:11 server sshd[12348]: Failed password for admin from 10.0.0.2 port 2222 ssh2
Jul  3 06:45:19 server sshd[12350]: Failed password for root from 8.8.8.8 port 22 ssh2
Jul  3 06:46:02 server sshd[12351]: Failed password for root from 8.8.8.8 port 22 ssh2
Jul  3 06:46:50 server sshd[12352]: Failed password for root from 8.8.8.8 port 22 ssh2
Jul  3 06:47:30 server sshd[12353]: Failed password for root from 8.8.8.8 port 22 ssh2
Jul  3 07:15:45 server sshd[12355]: Failed password for user1 from 203.0.113.5 port 22 ssh2
Jul  3 07:16:10 server sshd[12356]: Failed password for user1 from 203.0.113.5 port 22 ssh2
Jul  3 07:16:35 server sshd[12357]: Failed password for admin from 203.0.113.5 port 22 ssh2
Jul  3 07:17:00 server sshd[12358]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul  3 07:17:25 server sshd[12359]: Failed password for root from 203.0.113.5 port 22 ssh2"""
    
    return jsonify(analyze_log_content(sample_content))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))