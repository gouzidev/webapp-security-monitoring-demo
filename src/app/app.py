from flask import Flask, request, jsonify, session, redirect, render_template_string
import subprocess
import os
import re
from PIL import Image
import io

app = Flask(__name__)
app.secret_key = 'demo_key'

USERS = {'admin': 'admin', 'demo': 'demo'}

# persistent state file for scan toggle
SCAN_STATE_FILE = '/tmp/scan_state.txt'

def get_scan_enabled():
    try:
        with open(SCAN_STATE_FILE, 'r') as f:
            return f.read().strip() == 'enabled'
    except:
        return True  # default enabled

def set_scan_enabled(enabled):
    with open(SCAN_STATE_FILE, 'w') as f:
        f.write('enabled' if enabled else 'disabled')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        if user in USERS and USERS[user] == pwd:
            session['user'] = user
            return redirect('/')
        return 'invalid credentials', 401
    
    return '''
    <html>
    <head><title>login</title></head>
    <body style="font-family: Arial; max-width: 400px; margin: 100px auto; padding: 20px;">
        <h2>login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="username" required 
                   style="width: 100%; padding: 10px; margin: 5px 0; box-sizing: border-box;"><br>
            <input type="password" name="password" placeholder="password" required
                   style="width: 100%; padding: 10px; margin: 5px 0; box-sizing: border-box;"><br>
            <button type="submit" style="width: 100%; padding: 10px; margin: 10px 0; 
                    background: #007bff; color: white; border: none; cursor: pointer;">login</button>
        </form>
        <p style="color: #666; font-size: 0.9em;">try: admin/admin or demo/demo</p>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/toggle_scan')
def toggle_scan():
    current = get_scan_enabled()
    new_state = not current
    set_scan_enabled(new_state)
    return jsonify({'enabled': new_state, 'status': 'enabled' if new_state else 'disabled'})

@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/login')
    
    scan_enabled = get_scan_enabled()
    scan_status = 'enabled' if scan_enabled else 'disabled'
    scan_color = '#28a745' if scan_enabled else '#dc3545'
    
    # using triple quotes with escape for braces
    html = '''
    <html>
    <head>
        <title>container security monitor</title>
        <style>
            body {{ font-family: Arial; max-width: 900px; margin: 40px auto; padding: 20px; background: #f8f9fa; }}
            .header {{ background: white; padding: 25px; border-radius: 8px; margin-bottom: 20px; }}
            .upload-section {{ background: white; padding: 25px; border-radius: 8px; margin-bottom: 20px; }}
            .logs-section {{ background: white; padding: 25px; border-radius: 8px; }}
            button {{ padding: 10px 20px; background: #007bff; color: white; border: none; 
                      border-radius: 4px; cursor: pointer; }}
            .toggle {{ background: #6c757d; margin-left: 10px; }}
            .scan-status {{ padding: 10px; margin: 10px 0; background: {color}; color: white; 
                            border-radius: 4px; text-align: center; }}
            .log-entry {{ padding: 12px; margin: 8px 0; border-radius: 4px; border-left: 4px solid; 
                          font-family: monospace; }}
            .log-blocked {{ background: #ffe6e6; border-left-color: #dc3545; }}
            .log-allowed {{ background: #e6f7e6; border-left-color: #28a745; }}
            .logout {{ float: right; background: #dc3545; font-size: 0.9em; padding: 5px 10px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <a href="/logout" class="logout" style="text-decoration: none; color: white;">logout</a>
            <h1>runtime attack detection</h1>
            <p style="color: #666;">logged in as: {user}</p>
        </div>
        
        <div class="scan-status">image scanning: {status}</div>
        
        <div class="upload-section">
            <h3>upload script or image</h3>
            <form id="uploadForm" action="/execute" method="post" enctype="multipart/form-data">
                <input type="file" name="script" accept=".sh,.png,.jpg,.jpeg" required>
                <button type="submit">execute/scan</button>
                <button type="button" class="toggle" onclick="toggleScan()">toggle image scan</button>
            </form>
        </div>
        
        <div class="logs-section">
            <h3>activity log</h3>
            <div id="logs"></div>
        </div>
        
        <div id="result" style="display: none; margin-top: 20px; padding: 15px; border-radius: 4px;"></div>
        
        <script>
            function escapeHtml(text) {{
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }}
            
            function refreshLogs() {{
                fetch('/logs').then(r => r.json()).then(data => {{
                    document.getElementById('logs').innerHTML = data.logs.map(l => {{
                        const cls = l.blocked ? 'log-blocked' : 'log-allowed';
                        const label = l.blocked ? '[blocked]' : '[allowed]';
                        return '<div class="log-entry ' + cls + '"><b>' + label + '</b> ' + escapeHtml(l.msg) + '</div>';
                    }}).join('') || '<p style="color: #999;">no activity yet</p>';
                }});
            }}
            
            function showResult(data, isError) {{
                const result = document.getElementById('result');
                result.style.display = 'block';
                
                if (isError) {{
                    result.style.background = '#ffe6e6';
                    result.style.borderLeft = '4px solid #dc3545';
                    result.innerHTML = '<strong>🛡️ blocked by security scan:</strong><br>' + 
                                      (data.reason || data.error);
                }} else if (data.html) {{
                    // vulnerable - renders html directly (xss)
                    result.style.background = '#fff3cd';
                    result.style.borderLeft = '4px solid #ff6b6b';
                    result.innerHTML = '<strong>⚠️ security disabled - rendering unfiltered content</strong><br>' + 
                                      '<em style="color: #d63031;">xss vulnerability active!</em>' +
                                      data.html;
                }} else if (data.vulnerable) {{
                    result.style.background = '#fff3cd';
                    result.style.borderLeft = '4px solid #ff6b6b';
                    result.innerHTML = '<strong>vulnerability demonstrated:</strong><br>' + 
                                      data.output.replace(/\\n/g, '<br>');
                }} else if (data.output) {{
                    result.style.background = '#e6f7e6';
                    result.style.borderLeft = '4px solid #28a745';
                    result.innerHTML = '<strong>✓ ' + data.output + '</strong>';
                }}
                
                setTimeout(() => {{ result.style.display = 'none'; }}, 15000);
            }}
            
            function toggleScan() {{
                const btn = event.target;
                btn.disabled = true;
                btn.textContent = 'toggling...';
                
                fetch('/toggle_scan')
                    .then(r => r.json())
                    .then(data => {{
                        // update ui based on actual server state
                        const statusDiv = document.querySelector('.scan-status');
                        if (data.enabled) {{
                            statusDiv.textContent = 'image scanning: enabled';
                            statusDiv.style.background = '#28a745';
                        }} else {{
                            statusDiv.textContent = 'image scanning: disabled';
                            statusDiv.style.background = '#dc3545';
                        }}
                        btn.textContent = 'toggle image scan';
                        btn.disabled = false;
                    }})
                    .catch(err => {{
                        btn.textContent = 'toggle image scan';
                        btn.disabled = false;
                    }});
            }}
            
            refreshLogs();
            
            document.getElementById('uploadForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                const formData = new FormData(this);
                
                fetch('/execute', {{
                    method: 'POST',
                    body: formData
                }})
                .then(r => r.json().then(data => ({{status: r.status, data: data}})))
                .then(result => {{
                    showResult(result.data, result.status >= 400);
                    setTimeout(refreshLogs, 500);
                }})
                .catch(err => {{
                    showResult({{error: 'request failed'}}, true);
                }});
            }});
        </script>
    </body>
    </html>
    '''.format(user=session['user'], status=scan_status, color=scan_color)
    
    return html

def check_image_metadata(file_data):
    # check for embedded php/js/shell code in image metadata
    try:
        img = Image.open(io.BytesIO(file_data))
        metadata = img.info
        
        dangerous_patterns = [
            (r'<\?php', 'php code'),
            (r'<script', 'javascript'),
            (r'onerror\s*=', 'xss event handler'),
            (r'onload\s*=', 'xss event handler'),
            (r'onclick\s*=', 'xss event handler'),
            (r'eval\s*\(', 'eval function'),
            (r'system\s*\(', 'system call'),
            (r'/bin/(ba)?sh', 'shell reference'),
            (r'fetch\s*\(', 'fetch api call'),
        ]
        
        for key, value in metadata.items():
            if isinstance(value, str):
                for pattern, desc in dangerous_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return True, f'{desc} found in {key}: "{value[:50]}..."'
        
        return False, None
    except:
        return False, None

def check_script_attacks(content):
    # waf logic for scripts
    patterns = [
        (r'rm\s+-rf', 'dangerous rm command'),
        (r'/etc/passwd', 'system file access'),
        (r'(?<!#!)/bin/(bash|sh)', 'shell execution'),
        (r'wget\s+http', 'remote download attempt'),
        (r'curl\s+http', 'remote download attempt'),
        (r'nc\s+-[el]', 'netcat reverse shell'),
        (r'mkfifo', 'named pipe creation'),
        (r';.*rm\s', 'command chaining'),
        (r'\|.*rm\s', 'pipe to rm'),
    ]
    
    for pattern, description in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True, description
    return False, None

@app.route('/execute', methods=['POST'])
def execute():
    if 'user' not in session:
        return jsonify({'error': 'not logged in'}), 401
    
    if 'script' not in request.files:
        return jsonify({'error': 'no file'}), 400
    
    f = request.files['script']
    filename = f.filename.lower()
    
    # check if it's an image
    if filename.endswith(('.png', '.jpg', '.jpeg', '.gif')):
        content = f.read()
        
        if get_scan_enabled():
            is_malicious, reason = check_image_metadata(content)
            
            if is_malicious:
                log_activity(f.filename, True, f'image scan: {reason}')
                return jsonify({'error': 'malicious image detected', 'reason': reason, 'blocked': True}), 403
            
            log_activity(f.filename, False, 'image scan: clean')
            return jsonify({'output': 'image scanned - safe to use'})
        else:
            # vulnerable path - display without scanning
            # save the uploaded file to serve it
            import base64
            img_b64 = base64.b64encode(content).decode()
            
            # extract metadata to display (this is the vulnerability!)
            try:
                img = Image.open(io.BytesIO(content))
                metadata_html = ""
                for key, value in img.info.items():
                    # intentionally not sanitizing - vulnerable!
                    metadata_html += f"<div><b>{key}:</b> {value}</div>"
            except:
                metadata_html = "<div>could not read metadata</div>"
            
            log_activity(f.filename, False, 'uploaded without scan - xss possible')
            
            # return html that will render the image and its metadata (xss vulnerability!)
            return jsonify({
                'output': 'image uploaded',
                'html': f'''
                    <div style="margin-top: 10px;">
                        <img src="data:image/png;base64,{img_b64}" style="max-width: 200px; border: 1px solid #ddd;">
                        <div style="margin-top: 10px; font-size: 0.9em;">
                            <strong>image metadata:</strong>
                            {metadata_html}
                        </div>
                    </div>
                '''
            })
    
    # handle scripts - run through waf first
    content = f.read().decode('utf-8', errors='ignore')
    
    # waf check
    is_attack, reason = check_script_attacks(content)
    if is_attack:
        log_activity(f.filename, True, f'waf blocked: {reason}')
        return jsonify({'error': 'security violation detected', 'reason': reason, 'blocked': True}), 403
    
    # execute if safe
    try:
        result = subprocess.run(['sh', '-c', content], 
                              capture_output=True, 
                              timeout=2, 
                              text=True)
        log_activity(f.filename, False, 'executed successfully')
        return jsonify({'output': result.stdout, 'error': result.stderr})
    except Exception as e:
        log_activity(f.filename, False, f'execution failed: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/logs')
def get_logs():
    logs = []
    
    # waf logs
    try:
        with open('/var/log/waf.log', 'r') as f:
            lines = f.readlines()[-20:]
            for line in lines:
                if 'BLOCKED' in line:
                    logs.append({'blocked': True, 'msg': line.strip()})
                else:
                    logs.append({'blocked': False, 'msg': line.strip()})
    except FileNotFoundError:
        pass
    
    # app logs
    try:
        with open('/tmp/security_logs.txt', 'r') as f:
            lines = f.readlines()[-20:]
            for line in lines:
                if 'BLOCKED' in line:
                    logs.append({'blocked': True, 'msg': line.strip()})
                elif 'contains:' in line or 'waf blocked' in line:
                    logs.append({'blocked': True, 'msg': line.strip()})
                else:
                    logs.append({'blocked': False, 'msg': line.strip()})
    except FileNotFoundError:
        pass
    
    return jsonify({'logs': logs})

def log_activity(filename, blocked, msg):
    with open('/tmp/security_logs.txt', 'a') as f:
        status = 'BLOCKED' if blocked else 'ALLOWED'
        f.write(f'{status}: {filename} - {msg}\n')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
