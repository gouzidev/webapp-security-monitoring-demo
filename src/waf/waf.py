from flask import Flask, request, Response, jsonify
import requests
import re

app = Flask(__name__)

# patterns that indicate attacks
ATTACK_PATTERNS = [
    (r'rm\s+-rf', 'dangerous rm command'),
    (r'/etc/passwd', 'system file access'),
    (r'(?<!#!)/bin/(bash|sh)', 'shell execution'),  # exclude shebangs
    (r'wget\s+http', 'remote download attempt'),
    (r'curl\s+http', 'remote download attempt'),
    (r'nc\s+-[el]', 'netcat reverse shell'),
    (r'mkfifo', 'named pipe creation'),
    (r'eval\s*\(', 'eval injection'),
    (r'exec\s*\(', 'exec injection'),
    (r';.*rm\s', 'command chaining'),
    (r'\|.*rm\s', 'pipe to rm'),
    (r'>\s*/dev/', 'device redirection'),
]

def check_for_attacks(content):
    for pattern, description in ATTACK_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True, description
    return False, None

def log_request(filename, blocked, reason):
    with open('/var/log/waf.log', 'a') as f:
        status = 'BLOCKED' if blocked else 'ALLOWED'
        f.write(f'{status}: {filename} - {reason}\n')

@app.route('/')
def index():
    return requests.get('http://app:5000/').text

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return requests.get('http://app:5000/login').text
    else:
        resp = requests.post('http://app:5000/login', 
                           data=request.form)
        return Response(resp.content, status=resp.status_code,
                       headers=dict(resp.headers))

@app.route('/logout')
def logout():
    resp = requests.get('http://app:5000/logout')
    return Response(resp.content, status=resp.status_code,
                   headers=dict(resp.headers))

@app.route('/toggle_scan')
def toggle_scan():
    return requests.get('http://app:5000/toggle_scan').text

@app.route('/logs')
def logs():
    return requests.get('http://app:5000/logs').text

@app.route('/execute', methods=['POST'])
def execute():
    if 'script' not in request.files:
        return jsonify({'error': 'no file'}), 400
    
    f = request.files['script']
    content = f.read().decode('utf-8', errors='ignore')
    
    # check for malicious content
    is_attack, description = check_for_attacks(content)
    
    if is_attack:
        log_request(f.filename, True, f'attack detected: {description}')
        return jsonify({
            'error': 'security violation detected',
            'reason': description,
            'blocked': True
        }), 403
    
    # forward to backend if safe
    log_request(f.filename, False, 'clean request')
    files = {'script': (f.filename, content)}
    resp = requests.post('http://app:5000/execute', files=files)
    return Response(resp.content, status=resp.status_code, 
                   content_type=resp.headers.get('content-type'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
