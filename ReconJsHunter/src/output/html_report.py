"""
HTML report generator.
Creates interactive HTML reports for visualizing reconnaissance results.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader, BaseLoader

from src.collectors.base import CollectedData
from src.analyzers.js_analyzer import JSAnalysisResult
from src.core.logger import logger


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconHunter Report - {{ domain }}</title>
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
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 0;
            margin-bottom: 30px;
        }
        
        header h1 {
            color: var(--accent-blue);
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        header .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-card .number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-blue);
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-card.warning .number { color: var(--accent-yellow); }
        .stat-card.danger .number { color: var(--accent-red); }
        .stat-card.success .number { color: var(--accent-green); }
        
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-tertiary);
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        
        .section-header h2 {
            font-size: 1.1rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-header .count {
            background: var(--accent-blue);
            color: #fff;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
        }
        
        .section-content {
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
        }
        
        .section-content.collapsed {
            display: none;
        }
        
        .url-list {
            list-style: none;
        }
        
        .url-list li {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85rem;
            word-break: break-all;
        }
        
        .url-list li:last-child {
            border-bottom: none;
        }
        
        .url-list li:hover {
            background: var(--bg-tertiary);
        }
        
        .url-list a {
            color: var(--accent-blue);
            text-decoration: none;
        }
        
        .url-list a:hover {
            text-decoration: underline;
        }
        
        .finding-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 10px;
        }
        
        .finding-card .type {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        
        .finding-card .type.high { background: var(--accent-red); color: #fff; }
        .finding-card .type.medium { background: var(--accent-yellow); color: #000; }
        .finding-card .type.low { background: var(--accent-green); color: #fff; }
        
        .finding-card .value {
            font-family: monospace;
            background: var(--bg-primary);
            padding: 8px;
            border-radius: 4px;
            margin: 8px 0;
            word-break: break-all;
            font-size: 0.85rem;
        }
        
        .finding-card .source {
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        
        .subdomain-block {
            margin-bottom: 15px;
        }
        
        .subdomain-block h3 {
            color: var(--accent-purple);
            font-size: 1rem;
            margin-bottom: 10px;
            padding: 10px;
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
        
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .tab {
            padding: 10px 20px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            cursor: pointer;
            color: var(--text-secondary);
            transition: all 0.2s;
        }
        
        .tab:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        .tab.active {
            background: var(--accent-blue);
            color: #fff;
            border-color: var(--accent-blue);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .search-box {
            width: 100%;
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 1rem;
            margin-bottom: 20px;
        }
        
        .search-box::placeholder {
            color: var(--text-secondary);
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        
        .js-file-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 10px;
            overflow: hidden;
        }
        
        .js-file-header {
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .js-file-header:hover {
            background: var(--bg-secondary);
        }
        
        .js-file-url {
            font-family: monospace;
            font-size: 0.85rem;
            word-break: break-all;
            color: var(--accent-blue);
        }
        
        .js-file-stats {
            display: flex;
            gap: 10px;
        }
        
        .js-file-stats span {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }
        
        .js-file-content {
            padding: 15px;
            border-top: 1px solid var(--border-color);
            display: none;
        }
        
        .js-file-content.expanded {
            display: block;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .container {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>ReconHunter Report</h1>
            <div class="meta">
                Target: <strong>{{ domain }}</strong> | 
                Scan Time: {{ scan_time }} | 
                Sources: {{ sources|join(', ') }}
            </div>
        </div>
    </header>
    
    <div class="container">
        <input type="text" class="search-box" id="globalSearch" placeholder="Search URLs, findings, endpoints...">
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{{ summary.total_urls }}</div>
                <div class="label">Total URLs</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ summary.total_subdomains }}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ summary.total_js_files }}</div>
                <div class="label">JS Files</div>
            </div>
            <div class="stat-card success">
                <div class="number">{{ summary.total_endpoints }}</div>
                <div class="label">Endpoints</div>
            </div>
            <div class="stat-card danger">
                <div class="number">{{ summary.total_secrets_found }}</div>
                <div class="label">Secrets Found</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{{ summary.high_confidence_secrets }}</div>
                <div class="label">High Confidence</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-tab="main-domain">Main Domain</div>
            <div class="tab" data-tab="subdomains">Subdomains</div>
            <div class="tab" data-tab="javascript">JavaScript</div>
            <div class="tab" data-tab="findings">Findings</div>
            <div class="tab" data-tab="endpoints">Endpoints</div>
        </div>
        
        <div id="main-domain" class="tab-content active">
            <div class="section">
                <div class="section-header">
                    <h2>Main Domain URLs <span class="count">{{ main_domain.urls|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if main_domain.urls %}
                    <ul class="url-list">
                        {% for url in main_domain.urls[:200] %}
                        <li><a href="{{ url }}" target="_blank" rel="noopener">{{ url }}</a></li>
                        {% endfor %}
                    </ul>
                    {% if main_domain.urls|length > 200 %}
                    <div class="empty-state">Showing first 200 of {{ main_domain.urls|length }} URLs</div>
                    {% endif %}
                    {% else %}
                    <div class="empty-state">No main domain URLs found</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="subdomains" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>Discovered Subdomains <span class="count">{{ subdomains|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if subdomains %}
                    {% for subdomain, data in subdomains.items() %}
                    <div class="subdomain-block">
                        <h3>{{ subdomain }} ({{ data.url_count }} URLs)</h3>
                        <ul class="url-list">
                            {% for url in data.urls[:20] %}
                            <li><a href="{{ url }}" target="_blank" rel="noopener">{{ url }}</a></li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No subdomains discovered</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="javascript" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>JavaScript Files <span class="count">{{ javascript.files|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if javascript.analysis %}
                    {% for js in javascript.analysis %}
                    <div class="js-file-card">
                        <div class="js-file-header" onclick="toggleJsFile(this)">
                            <span class="js-file-url">{{ js.url }}</span>
                            <div class="js-file-stats">
                                {% if js.secrets %}
                                <span style="background: var(--accent-red); color: #fff;">{{ js.secrets|length }} secrets</span>
                                {% endif %}
                                {% if js.urls %}
                                <span style="background: var(--accent-blue); color: #fff;">{{ js.urls|length }} URLs</span>
                                {% endif %}
                            </div>
                        </div>
                        <div class="js-file-content">
                            {% if js.secrets %}
                            <h4 style="margin-bottom: 10px; color: var(--accent-red);">Secrets Found:</h4>
                            {% for secret in js.secrets %}
                            <div class="finding-card">
                                <span class="type {{ secret.confidence }}">{{ secret.confidence }}</span>
                                <span style="margin-left: 10px; color: var(--text-secondary);">{{ secret.type }}</span>
                                <div class="value">{{ secret.value }}</div>
                                <div class="source">Line {{ secret.line_number }}</div>
                            </div>
                            {% endfor %}
                            {% endif %}
                            
                            {% if js.api_endpoints %}
                            <h4 style="margin: 15px 0 10px; color: var(--accent-green);">API Endpoints:</h4>
                            <ul class="url-list">
                                {% for endpoint in js.api_endpoints[:20] %}
                                <li>{{ endpoint }}</li>
                                {% endfor %}
                            </ul>
                            {% endif %}
                            
                            {% if js.internal_refs %}
                            <h4 style="margin: 15px 0 10px; color: var(--accent-yellow);">Internal References:</h4>
                            {% for ref in js.internal_refs[:10] %}
                            <div class="finding-card">
                                <span class="type medium">{{ ref.type }}</span>
                                <div class="value">{{ ref.value }}</div>
                            </div>
                            {% endfor %}
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No JavaScript files analyzed</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="findings" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>High Confidence Secrets <span class="count">{{ findings.secrets.high|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.secrets.high %}
                    {% for finding in findings.secrets.high %}
                    <div class="finding-card">
                        <span class="type high">HIGH</span>
                        <span style="margin-left: 10px; font-weight: 600;">{{ finding.type }}</span>
                        <div class="value">{{ finding.value }}</div>
                        <div class="source">Source: {{ finding.source_file }}</div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No high confidence secrets found</div>
                    {% endif %}
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>Medium Confidence Secrets <span class="count">{{ findings.secrets.medium|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.secrets.medium %}
                    {% for finding in findings.secrets.medium %}
                    <div class="finding-card">
                        <span class="type medium">MEDIUM</span>
                        <span style="margin-left: 10px; font-weight: 600;">{{ finding.type }}</span>
                        <div class="value">{{ finding.value }}</div>
                        <div class="source">Source: {{ finding.source_file }}</div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No medium confidence secrets found</div>
                    {% endif %}
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>Internal References <span class="count">{{ findings.internal_references|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.internal_references %}
                    {% for ref in findings.internal_references[:50] %}
                    <div class="finding-card">
                        <span class="type medium">{{ ref.type }}</span>
                        <div class="value">{{ ref.value }}</div>
                        <div class="source">Source: {{ ref.source_file }}</div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No internal references found</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="endpoints" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>Discovered API Endpoints <span class="count">{{ findings.api_endpoints|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.api_endpoints %}
                    <ul class="url-list">
                        {% for ep in findings.api_endpoints[:200] %}
                        <li>
                            <span style="color: var(--accent-green);">{{ ep.endpoint }}</span>
                            <br><small style="color: var(--text-secondary);">from: {{ ep.source_file }}</small>
                        </li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <div class="empty-state">No API endpoints discovered</div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        Generated by ReconHunter v1.0.0 | For authorized security testing only
    </footer>
    
    <script>
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });
        
        document.querySelectorAll('.section-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = header.nextElementSibling;
                content.classList.toggle('collapsed');
            });
        });
        
        function toggleJsFile(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('expanded');
        }
        
        document.getElementById('globalSearch').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            
            document.querySelectorAll('.url-list li, .finding-card, .js-file-card, .subdomain-block').forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? '' : 'none';
            });
        });
    </script>
</body>
</html>
'''


class HTMLReportGenerator:
    
    def __init__(self):
        self.env = Environment(loader=BaseLoader())
        self.template = self.env.from_string(HTML_TEMPLATE)
    
    def generate(self, domain: str, collected_data: Dict[str, CollectedData],
                 js_results: List[JSAnalysisResult],
                 categorized_urls: Dict[str, List[str]],
                 output_dir: str) -> str:
        
        summary = self._generate_summary(collected_data, js_results, categorized_urls)
        subdomains = self._organize_subdomains(collected_data, categorized_urls)
        findings = self._aggregate_findings(js_results)
        
        html_content = self.template.render(
            domain=domain,
            scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            sources=[name for name in collected_data.keys()],
            summary=summary,
            main_domain={
                'urls': categorized_urls.get('main_domain', []),
                'endpoints': categorized_urls.get('endpoints', [])
            },
            subdomains=subdomains,
            javascript={
                'files': categorized_urls.get('javascript', []),
                'analysis': [r.to_dict() for r in js_results]
            },
            findings=findings
        )
        
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, 'report.html')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path}")
        
        return report_path
    
    def _generate_summary(self, collected_data, js_results, categorized_urls):
        total_urls = sum(len(data.urls) for data in collected_data.values())
        total_subdomains = set()
        for data in collected_data.values():
            total_subdomains.update(data.subdomains)
        
        total_secrets = sum(len(r.secrets) for r in js_results)
        high_confidence = sum(1 for r in js_results for s in r.secrets if s.confidence == 'high')
        
        return {
            'total_urls': total_urls,
            'unique_urls': len(categorized_urls.get('all', [])),
            'total_subdomains': len(total_subdomains),
            'total_js_files': len(categorized_urls.get('javascript', [])),
            'js_files_analyzed': len(js_results),
            'total_endpoints': len(categorized_urls.get('endpoints', [])),
            'total_secrets_found': total_secrets,
            'high_confidence_secrets': high_confidence,
            'sources_used': list(collected_data.keys())
        }
    
    def _organize_subdomains(self, collected_data, categorized_urls):
        subdomains = {}
        all_subdomains = set()
        
        for data in collected_data.values():
            all_subdomains.update(data.subdomains)
        
        subdomain_urls = categorized_urls.get('subdomain_urls', {})
        
        for subdomain in sorted(all_subdomains):
            subdomains[subdomain] = {
                'urls': subdomain_urls.get(subdomain, []),
                'url_count': len(subdomain_urls.get(subdomain, []))
            }
        
        return subdomains
    
    def _aggregate_findings(self, js_results):
        findings = {
            'secrets': {'high': [], 'medium': [], 'low': []},
            'internal_references': [],
            'sensitive_data': [],
            'api_endpoints': []
        }
        
        for result in js_results:
            for secret in result.secrets:
                finding = secret.to_dict()
                finding['source_file'] = result.url
                findings['secrets'][secret.confidence].append(finding)
            
            for ref in result.internal_refs:
                finding = ref.to_dict()
                finding['source_file'] = result.url
                findings['internal_references'].append(finding)
            
            for endpoint in result.api_endpoints:
                findings['api_endpoints'].append({
                    'endpoint': endpoint,
                    'source_file': result.url
                })
        
        return findings
