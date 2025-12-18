"""
ReconHunter Web Interface
Flask-based web UI for viewing and running reconnaissance scans.
"""

import os
import json
import asyncio
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_from_directory, redirect, url_for

from src.core.config import get_default_config
from src.core.normalizer import URLNormalizer
from src.recon_engine import ReconEngine

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'reconhunter-dev-key')

OUTPUT_DIR = 'recon_output'
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconHunter - Bug Bounty Reconnaissance</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #a371f7;
            --border-color: #30363d;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 40px 20px;
            text-align: center;
            border-bottom: 1px solid var(--border-color);
        }
        
        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }
        
        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        .scan-form {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 40px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-primary);
            font-weight: 500;
        }
        
        .form-group input[type="text"] {
            width: 100%;
            padding: 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 1rem;
        }
        
        .form-group input[type="text"]:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        
        .form-group input[type="text"]::placeholder {
            color: var(--text-secondary);
        }
        
        .options-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .option-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px;
            background: var(--bg-tertiary);
            border-radius: 6px;
        }
        
        .option-item input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--accent-blue);
        }
        
        .btn {
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: var(--accent-blue);
            color: #fff;
        }
        
        .btn-primary:hover {
            background: #4493e5;
            transform: translateY(-2px);
        }
        
        .btn-primary:disabled {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: not-allowed;
            transform: none;
        }
        
        .reports-section h2 {
            margin-bottom: 20px;
            color: var(--text-primary);
        }
        
        .reports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .report-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            transition: all 0.2s;
        }
        
        .report-card:hover {
            border-color: var(--accent-blue);
            transform: translateY(-2px);
        }
        
        .report-card h3 {
            color: var(--accent-blue);
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        .report-card .meta {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 15px;
        }
        
        .report-card .actions {
            display: flex;
            gap: 10px;
        }
        
        .report-card .actions a {
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            text-decoration: none;
            font-size: 0.85rem;
            transition: all 0.2s;
        }
        
        .report-card .actions a:hover {
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: #fff;
        }
        
        .status-message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        .status-message.error {
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            display: block;
        }
        
        .status-message.success {
            background: rgba(63, 185, 80, 0.1);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            display: block;
        }
        
        .status-message.loading {
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid var(--accent-blue);
            color: var(--accent-blue);
            display: block;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid var(--accent-blue);
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ReconHunter</h1>
        <p>Professional Bug Bounty Reconnaissance Tool</p>
    </div>
    
    <div class="container">
        <div class="scan-form">
            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target Domain or URL</label>
                    <input type="text" id="target" name="target" 
                           placeholder="Enter domain (e.g., example.com) or URL" required>
                </div>
                
                <div class="options-grid">
                    <div class="option-item">
                        <input type="checkbox" id="wayback" name="wayback" checked>
                        <label for="wayback">Wayback Machine</label>
                    </div>
                    <div class="option-item">
                        <input type="checkbox" id="urlscan" name="urlscan" checked>
                        <label for="urlscan">URLScan.io</label>
                    </div>
                    <div class="option-item">
                        <input type="checkbox" id="alienvault" name="alienvault" checked>
                        <label for="alienvault">AlienVault OTX</label>
                    </div>
                    <div class="option-item">
                        <input type="checkbox" id="analyze_js" name="analyze_js" checked>
                        <label for="analyze_js">JavaScript Analysis</label>
                    </div>
                </div>
                
                <div id="statusMessage" class="status-message"></div>
                
                <button type="submit" class="btn btn-primary" id="submitBtn">
                    Start Reconnaissance
                </button>
            </form>
        </div>
        
        <div class="reports-section">
            <h2>Previous Reports</h2>
            <div class="reports-grid" id="reportsGrid">
                {% if reports %}
                    {% for report in reports %}
                    <div class="report-card">
                        <h3>{{ report.domain }}</h3>
                        <div class="meta">{{ report.date }}</div>
                        <div class="actions">
                            <a href="/report/{{ report.folder }}/report.html">View HTML</a>
                            <a href="/report/{{ report.folder }}/full_report.json">View JSON</a>
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <div class="empty-state">
                        No reports yet. Start a scan to generate your first report.
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <footer>
        ReconHunter v1.0.0 | For authorized security testing only
    </footer>
    
    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const submitBtn = document.getElementById('submitBtn');
            const statusDiv = document.getElementById('statusMessage');
            
            submitBtn.disabled = true;
            statusDiv.className = 'status-message loading';
            statusDiv.innerHTML = '<span class="loading-spinner"></span>Running reconnaissance... This may take a few minutes.';
            
            try {
                const formData = new FormData(e.target);
                
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        target: target,
                        wayback: document.getElementById('wayback').checked,
                        urlscan: document.getElementById('urlscan').checked,
                        alienvault: document.getElementById('alienvault').checked,
                        analyze_js: document.getElementById('analyze_js').checked
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    statusDiv.className = 'status-message success';
                    statusDiv.innerHTML = 'Scan complete! <a href="/report/' + result.report_folder + '/report.html">View Report</a>';
                    setTimeout(() => location.reload(), 2000);
                } else {
                    statusDiv.className = 'status-message error';
                    statusDiv.textContent = 'Error: ' + result.error;
                }
            } catch (error) {
                statusDiv.className = 'status-message error';
                statusDiv.textContent = 'Error: ' + error.message;
            } finally {
                submitBtn.disabled = false;
            }
        });
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    reports = get_existing_reports()
    return render_template_string(MAIN_TEMPLATE, reports=reports)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        config = get_default_config()
        config.output_dir = OUTPUT_DIR
        config.wayback.enabled = data.get('wayback', True)
        config.urlscan.enabled = data.get('urlscan', True)
        config.alienvault.enabled = data.get('alienvault', True)
        config.js_analysis = data.get('analyze_js', True)
        
        engine = ReconEngine(config)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(engine.run(target, analyze_js=config.js_analysis))
        finally:
            loop.close()
        
        html_path = engine.export_html(target, OUTPUT_DIR)
        json_dir = engine.export_json(target, OUTPUT_DIR)
        
        report_folder = os.path.basename(os.path.dirname(html_path))
        
        return jsonify({
            'success': True,
            'report_folder': report_folder,
            'html_path': html_path,
            'json_dir': json_dir
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/report/<path:folder>/<path:filename>')
def serve_report(folder, filename):
    report_path = os.path.join(OUTPUT_DIR, folder)
    return send_from_directory(report_path, filename)


def get_existing_reports():
    reports = []
    
    if not os.path.exists(OUTPUT_DIR):
        return reports
    
    for folder in os.listdir(OUTPUT_DIR):
        folder_path = os.path.join(OUTPUT_DIR, folder)
        
        if not os.path.isdir(folder_path):
            continue
        
        html_report = os.path.join(folder_path, 'report.html')
        if not os.path.exists(html_report):
            continue
        
        parts = folder.rsplit('_', 2)
        if len(parts) >= 3:
            domain = parts[0]
            date_str = f"{parts[1]}_{parts[2]}"
            try:
                date = datetime.strptime(date_str, '%Y%m%d_%H%M%S')
                date_formatted = date.strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_formatted = date_str
        else:
            domain = folder
            date_formatted = 'Unknown'
        
        reports.append({
            'folder': folder,
            'domain': domain,
            'date': date_formatted
        })
    
    reports.sort(key=lambda x: x['date'], reverse=True)
    
    return reports


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6789, debug=True)
