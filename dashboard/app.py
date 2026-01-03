from flask import Flask, render_template, jsonify
import json
import os
from collections import defaultdict, Counter
from datetime import datetime

app = Flask(__name__)
JSON_LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'alerts.json')

def read_alerts():
    alerts = []
    if not os.path.exists(JSON_LOG_PATH):
        return alerts
    
    try:
        with open(JSON_LOG_PATH, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except:
                        pass
    except Exception as e:
        print(f"Error reading logs: {e}")
        
    return alerts

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    try:
        all_alerts = read_alerts()
        
        total = len(all_alerts)
        high_risk = sum(1 for row in all_alerts if row['severity'] == 'HIGH')
        medium_risk = sum(1 for row in all_alerts if row['severity'] == 'MEDIUM')
        low_risk = sum(1 for row in all_alerts if row['severity'] == 'LOW')
        
        # 1. Attack Types (Bar Chart)
        types_counter = Counter(row['type'] for row in all_alerts)
        
        # 2. Top IPs
        ips_counter = Counter(row['source_ip'] for row in all_alerts)
        top_ips = [{'ip': ip, 'count': count} for ip, count in ips_counter.most_common(5)]
        
        # 3. Protocol / Service Inference (Pie Chart)
        protocols = Counter()
        for row in all_alerts:
            msg = row['message'].lower()
            atype = row['type']
            
            if 'port 22' in msg: protocols['SSH'] += 1
            elif 'port 21' in msg: protocols['FTP'] += 1
            elif 'port 80' in msg or 'port 443' in msg or 'xss' in msg or 'sql' in msg: protocols['HTTP'] += 1
            elif atype == 'port_scan': protocols['TCP'] += 1
            elif atype == 'anomaly': protocols['Traffic'] += 1
            else: protocols['Other'] += 1

        # 4. Time Series (Line Chart)
        timeline = defaultdict(int)
        for row in all_alerts:
            try:
                ts_str = row['timestamp']
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                key = dt.strftime("%H:%M") # Group by HH:MM
                timeline[key] += 1
            except:
                pass
        
        timeline_sorted = dict(sorted(timeline.items()))

        # Full History (Reverse Order)
        # Using reversed list for "Newest First" display
        history = list(reversed(all_alerts))

        return jsonify({
            'summary': {
                'total': total,
                'high': high_risk,
                'medium': medium_risk,
                'low': low_risk,
                'unique_ips': len(ips_counter)
            },
            'charts': {
                'types': dict(types_counter),
                'protocols': dict(protocols),
                'timeline': timeline_sorted
            },
            'top_ips': top_ips,
            'recent': history 
        })
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
