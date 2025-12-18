"""HTML Report Output Handler for WebRecon."""

import os
import base64
from typing import Dict, Any, List
from datetime import datetime


class HTMLOutputHandler:
    """Handler for HTML report generation with modern UI."""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
    
    def generate_report(
        self,
        all_results: List[Dict[str, Any]],
        scan_info: Dict[str, Any]
    ) -> str:
        """Generate an HTML report for all scan results."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        html_content = self._generate_html(all_results, scan_info)
        
        output_path = os.path.join(self.output_dir, "report.html")
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path
    
    def _encode_image_base64(self, image_path: str) -> str:
        """Encode an image file to base64."""
        try:
            if os.path.exists(image_path):
                with open(image_path, 'rb') as f:
                    return base64.b64encode(f.read()).decode('utf-8')
        except Exception:
            pass
        return ""
    
    def _generate_html(
        self,
        all_results: List[Dict[str, Any]],
        scan_info: Dict[str, Any]
    ) -> str:
        """Generate HTML content."""
        successful = sum(1 for r in all_results if r.get("success"))
        failed = len(all_results) - successful
        
        targets_html = ""
        nav_html = ""
        for idx, result in enumerate(all_results):
            target = result.get("target", "Unknown")
            hostname = result.get("hostname", target)
            targets_html += self._generate_target_section(result, idx)
            nav_html += f'<a href="#target-{idx}" class="nav-item">{hostname}</a>'
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRecon Scan Report</title>
    <style>
        :root {{
            --bg-primary: #0a0f1a;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --bg-hover: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --accent-purple: #8b5cf6;
            --border-color: #374151;
            --gradient-start: #1e3a5f;
            --gradient-end: #0a0f1a;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .app-container {{
            display: flex;
            min-height: 100vh;
        }}
        
        .sidebar {{
            width: 280px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            padding: 1.5rem;
        }}
        
        .sidebar-header {{
            margin-bottom: 2rem;
        }}
        
        .logo {{
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .sidebar-nav {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        
        .nav-item {{
            color: var(--text-secondary);
            text-decoration: none;
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            transition: all 0.2s;
            font-size: 0.875rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .nav-item:hover {{
            background: var(--bg-hover);
            color: var(--text-primary);
        }}
        
        .main-content {{
            margin-left: 280px;
            flex: 1;
            padding: 2rem;
        }}
        
        .header {{
            background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%);
            padding: 2.5rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        
        .header h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-top: 2rem;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            padding: 1.25rem;
            border-radius: 0.75rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }}
        
        .target-card {{
            background: var(--bg-card);
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }}
        
        .target-header {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .target-url {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--accent-cyan);
            word-break: break-all;
        }}
        
        .badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        
        .badge {{
            padding: 0.375rem 0.875rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }}
        .badge-error {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }}
        .badge-grade-a {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }}
        .badge-grade-b {{ background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); }}
        .badge-grade-c {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); }}
        .badge-grade-d {{ background: rgba(249, 115, 22, 0.2); color: #f97316; }}
        .badge-grade-f {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }}
        
        .target-body {{
            padding: 1.5rem;
        }}
        
        .section {{
            margin-bottom: 2rem;
        }}
        
        .section:last-child {{
            margin-bottom: 0;
        }}
        
        .section-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .section-icon {{
            width: 40px;
            height: 40px;
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
        }}
        
        .section-icon.screenshot {{ background: rgba(139, 92, 246, 0.2); }}
        .section-icon.headers {{ background: rgba(59, 130, 246, 0.2); }}
        .section-icon.tech {{ background: rgba(16, 185, 129, 0.2); }}
        .section-icon.dns {{ background: rgba(6, 182, 212, 0.2); }}
        .section-icon.ssl {{ background: rgba(245, 158, 11, 0.2); }}
        .section-icon.whois {{ background: rgba(236, 72, 153, 0.2); }}
        .section-icon.extra {{ background: rgba(99, 102, 241, 0.2); }}
        
        .section-title {{
            font-size: 1.125rem;
            font-weight: 600;
        }}
        
        .section-content {{
            background: var(--bg-secondary);
            border-radius: 0.75rem;
            padding: 1.25rem;
        }}
        
        .screenshot-gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }}
        
        .screenshot-item {{
            background: var(--bg-primary);
            border-radius: 0.5rem;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        
        .screenshot-item img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        
        .screenshot-label {{
            padding: 0.75rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-align: center;
            border-top: 1px solid var(--border-color);
        }}
        
        .data-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }}
        
        .data-item {{
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 0.5rem;
            border: 1px solid var(--border-color);
        }}
        
        .data-label {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }}
        
        .data-value {{
            font-size: 0.9375rem;
            color: var(--text-primary);
            word-break: break-all;
        }}
        
        .tech-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }}
        
        .tech-category {{
            margin-bottom: 1rem;
        }}
        
        .tech-category-title {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        
        .tech-tag {{
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.375rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.8125rem;
            font-weight: 500;
        }}
        
        .tech-tag.server {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; }}
        .tech-tag.language {{ background: rgba(139, 92, 246, 0.2); color: #a78bfa; }}
        .tech-tag.framework {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
        .tech-tag.cms {{ background: rgba(236, 72, 153, 0.2); color: #f472b6; }}
        .tech-tag.analytics {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
        .tech-tag.cdn {{ background: rgba(6, 182, 212, 0.2); color: #22d3ee; }}
        .tech-tag.js {{ background: rgba(251, 191, 36, 0.2); color: #fcd34d; }}
        .tech-tag.service {{ background: rgba(99, 102, 241, 0.2); color: #818cf8; }}
        .tech-tag.payment {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; }}
        
        .header-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .header-table th,
        .header-table td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .header-table th {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: var(--bg-primary);
        }}
        
        .header-table td {{
            font-size: 0.875rem;
        }}
        
        .header-name {{
            color: var(--accent-cyan);
            font-weight: 500;
        }}
        
        .header-value {{
            color: var(--text-secondary);
            word-break: break-all;
            max-width: 500px;
        }}
        
        .status-present {{ color: var(--accent-green); }}
        .status-missing {{ color: var(--accent-red); }}
        
        .severity-high {{ color: var(--accent-red); }}
        .severity-medium {{ color: var(--accent-yellow); }}
        .severity-low {{ color: var(--accent-cyan); }}
        
        .ssl-status {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }}
        
        .ssl-valid {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        
        .ssl-warning {{
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}
        
        .ssl-error {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        
        .issues-list {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}
        
        .issue-item {{
            display: flex;
            gap: 0.75rem;
            padding: 1rem;
            background: var(--bg-primary);
            border-radius: 0.5rem;
            border-left: 3px solid;
        }}
        
        .issue-critical {{ border-color: var(--accent-red); }}
        .issue-high {{ border-color: #f97316; }}
        .issue-warning {{ border-color: var(--accent-yellow); }}
        .issue-medium {{ border-color: var(--accent-yellow); }}
        
        .issue-content {{
            flex: 1;
        }}
        
        .issue-title {{
            font-weight: 500;
            margin-bottom: 0.25rem;
        }}
        
        .issue-desc {{
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        
        .collapsible-content {{
            display: none;
            margin-top: 1rem;
        }}
        
        .collapsible.active .collapsible-content {{
            display: block;
        }}
        
        .collapsible-toggle {{
            font-size: 0.75rem;
            color: var(--accent-blue);
            margin-left: auto;
        }}
        
        .raw-headers {{
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.8125rem;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}
        
        @media (max-width: 1024px) {{
            .sidebar {{
                display: none;
            }}
            .main-content {{
                margin-left: 0;
            }}
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="app-container">
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="logo">WebRecon</div>
            </div>
            <nav class="sidebar-nav">
                {nav_html}
            </nav>
        </aside>
        
        <main class="main-content">
            <header class="header">
                <h1>Reconnaissance Report</h1>
                <p class="subtitle">Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{len(all_results)}</div>
                        <div class="stat-label">Total Targets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{successful}</div>
                        <div class="stat-label">Successful</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{failed}</div>
                        <div class="stat-label">Failed</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{scan_info.get("duration", "N/A")}s</div>
                        <div class="stat-label">Duration</div>
                    </div>
                </div>
            </header>
            
            {targets_html}
            
            <footer class="footer">
                <p>Generated by WebRecon v1.0.0 - Professional Web Reconnaissance Tool</p>
            </footer>
        </main>
    </div>
    
    <script>
        document.querySelectorAll('.collapsible').forEach(el => {{
            el.querySelector('.section-header').addEventListener('click', () => {{
                el.classList.toggle('active');
            }});
        }});
    </script>
</body>
</html>'''
        
        return html
    
    def _generate_target_section(self, result: Dict[str, Any], idx: int) -> str:
        """Generate HTML section for a single target."""
        target = result.get("target", "Unknown")
        success = result.get("success", False)
        results = result.get("results", {})
        output_folder = result.get("output_folder", "")
        
        status_badge = '<span class="badge badge-success">Success</span>' if success else '<span class="badge badge-error">Failed</span>'
        
        grade = ""
        grade_class = ""
        if "headers" in results:
            headers_data = results["headers"].get("data", {})
            security = headers_data.get("security_headers", {})
            if security.get("grade"):
                g = security.get("grade")
                grade_class = f"badge-grade-{g.lower()}"
                grade = f'<span class="badge {grade_class}">Grade {g}</span>'
        
        sections_html = ""
        
        sections_html += self._generate_screenshot_section(results, output_folder)
        sections_html += self._generate_headers_section(results)
        sections_html += self._generate_tech_section(results)
        sections_html += self._generate_ssl_section(results)
        sections_html += self._generate_whois_section(results)
        sections_html += self._generate_dns_section(results)
        sections_html += self._generate_extra_section(results)
        
        return f'''
        <div class="target-card" id="target-{idx}">
            <div class="target-header">
                <span class="target-url">{target}</span>
                <div class="badges">{status_badge} {grade}</div>
            </div>
            <div class="target-body">
                {sections_html}
            </div>
        </div>'''
    
    def _generate_screenshot_section(self, results: Dict[str, Any], output_folder: str) -> str:
        """Generate screenshot gallery section."""
        if "screenshot" not in results or not results["screenshot"].get("success"):
            return ""
        
        screenshot_data = results["screenshot"].get("data", {})
        desktop = screenshot_data.get("desktop", {})
        mobile = screenshot_data.get("mobile", {})
        page_title = screenshot_data.get("page_title", "")
        final_url = screenshot_data.get("final_url", "")
        
        screenshots_html = ""
        
        if desktop.get("path"):
            img_base64 = self._encode_image_base64(desktop["path"])
            if img_base64:
                screenshots_html += f'''
                <div class="screenshot-item">
                    <img src="data:image/png;base64,{img_base64}" alt="Desktop Screenshot">
                    <div class="screenshot-label">Desktop ({desktop.get("width", "?")}x{desktop.get("height", "?")})</div>
                </div>'''
        
        if mobile.get("path"):
            img_base64 = self._encode_image_base64(mobile["path"])
            if img_base64:
                screenshots_html += f'''
                <div class="screenshot-item">
                    <img src="data:image/png;base64,{img_base64}" alt="Mobile Screenshot">
                    <div class="screenshot-label">Mobile (375x812)</div>
                </div>'''
        
        if not screenshots_html:
            return ""
        
        title_html = f'<p style="margin-bottom: 1rem; color: var(--text-secondary);"><strong>Page Title:</strong> {page_title}</p>' if page_title else ""
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon screenshot">📸</div>
                <h3 class="section-title">Screenshots</h3>
            </div>
            <div class="section-content">
                {title_html}
                <div class="screenshot-gallery">
                    {screenshots_html}
                </div>
            </div>
        </div>'''
    
    def _generate_headers_section(self, results: Dict[str, Any]) -> str:
        """Generate headers analysis section."""
        if "headers" not in results or not results["headers"].get("success"):
            return ""
        
        headers_data = results["headers"].get("data", {})
        security = headers_data.get("security_headers", {})
        all_headers = headers_data.get("headers", {})
        server_info = headers_data.get("server", {})
        cdn_waf = headers_data.get("cdn_waf", {})
        cookies = headers_data.get("cookies", [])
        status_code = headers_data.get("status_code", "")
        
        score = security.get("score", 0)
        present = security.get("present", [])
        missing = security.get("missing", [])
        
        security_rows = ""
        for h in present:
            severity_class = f"severity-{h.get('severity', 'low')}"
            val = h.get("value", "")[:100] + ("..." if len(h.get("value", "")) > 100 else "")
            security_rows += f'''
            <tr>
                <td class="header-name">{h["header"]}</td>
                <td class="status-present">Present</td>
                <td class="{severity_class}">{h.get("severity", "").title()}</td>
                <td class="header-value">{val}</td>
            </tr>'''
        
        for h in missing:
            severity_class = f"severity-{h.get('severity', 'low')}"
            security_rows += f'''
            <tr>
                <td class="header-name">{h["header"]}</td>
                <td class="status-missing">Missing</td>
                <td class="{severity_class}">{h.get("severity", "").title()}</td>
                <td class="header-value">{h.get("description", "")}</td>
            </tr>'''
        
        raw_headers = "\n".join([f"{k}: {v}" for k, v in all_headers.items()])
        
        server_html = ""
        if server_info.get("server") or server_info.get("powered_by"):
            server_items = []
            if server_info.get("server"):
                server_items.append(f"<strong>Server:</strong> {server_info['server']}")
            if server_info.get("powered_by"):
                server_items.append(f"<strong>Powered By:</strong> {server_info['powered_by']}")
            server_html = f'<p style="margin-bottom: 1rem; color: var(--text-secondary);">{" | ".join(server_items)}</p>'
        
        cdn_html = ""
        if cdn_waf.get("detected"):
            cdn_tags = " ".join([f'<span class="tech-tag cdn">{c}</span>' for c in cdn_waf["detected"]])
            cdn_html = f'<div style="margin-bottom: 1rem;"><strong style="color: var(--text-muted);">CDN/WAF:</strong> {cdn_tags}</div>'
        
        return f'''
        <div class="section collapsible active">
            <div class="section-header">
                <div class="section-icon headers">🔒</div>
                <h3 class="section-title">HTTP Headers & Security (Score: {score}%)</h3>
                <span class="collapsible-toggle">Click to toggle</span>
            </div>
            <div class="collapsible-content">
                <div class="section-content">
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);"><strong>Status Code:</strong> {status_code}</p>
                    {server_html}
                    {cdn_html}
                    
                    <h4 style="margin: 1.5rem 0 1rem; color: var(--text-primary);">Security Headers Analysis</h4>
                    <table class="header-table">
                        <thead>
                            <tr>
                                <th>Header</th>
                                <th>Status</th>
                                <th>Severity</th>
                                <th>Value/Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {security_rows}
                        </tbody>
                    </table>
                    
                    <h4 style="margin: 1.5rem 0 1rem; color: var(--text-primary);">All Response Headers</h4>
                    <div class="raw-headers">{raw_headers}</div>
                </div>
            </div>
        </div>'''
    
    def _generate_tech_section(self, results: Dict[str, Any]) -> str:
        """Generate technology detection section."""
        if "tech_detect" not in results or not results["tech_detect"].get("success"):
            return ""
        
        tech_data = results["tech_detect"].get("data", {})
        
        category_map = {
            "web_servers": ("Server", "server"),
            "languages": ("Languages", "language"),
            "frameworks": ("Frameworks", "framework"),
            "cms": ("CMS", "cms"),
            "analytics": ("Analytics", "analytics"),
            "payment": ("Payment", "payment"),
            "cdn_waf": ("CDN/WAF", "cdn"),
            "js_libraries": ("JavaScript", "js"),
            "services": ("Services", "service")
        }
        
        categories_html = ""
        total_count = 0
        
        for key, (label, css_class) in category_map.items():
            techs = tech_data.get(key, [])
            if techs:
                total_count += len(techs)
                tags = " ".join([f'<span class="tech-tag {css_class}">{t}</span>' for t in techs])
                categories_html += f'''
                <div class="tech-category">
                    <div class="tech-category-title">{label}</div>
                    <div class="tech-grid">{tags}</div>
                </div>'''
        
        if not categories_html:
            return ""
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon tech">🔧</div>
                <h3 class="section-title">Technologies Detected ({total_count})</h3>
            </div>
            <div class="section-content">
                {categories_html}
            </div>
        </div>'''
    
    def _generate_ssl_section(self, results: Dict[str, Any]) -> str:
        """Generate SSL certificate section."""
        if "ssl" not in results or not results["ssl"].get("success"):
            return ""
        
        ssl_data = results["ssl"].get("data", {})
        subject = ssl_data.get("subject", {})
        issuer = ssl_data.get("issuer", {})
        validity = ssl_data.get("validity", {})
        connection = ssl_data.get("connection", {})
        san_list = ssl_data.get("subject_alternative_names", [])
        fingerprints = ssl_data.get("fingerprints", {})
        security_issues = ssl_data.get("security_issues", [])
        
        is_valid = validity.get("is_valid", False)
        is_expired = validity.get("is_expired", False)
        days_until_expiry = validity.get("days_until_expiry", 0)
        
        if is_expired:
            status_class = "ssl-error"
            status_text = "EXPIRED"
            status_icon = "❌"
        elif days_until_expiry <= 30:
            status_class = "ssl-warning"
            status_text = f"Expires in {days_until_expiry} days"
            status_icon = "⚠️"
        elif is_valid:
            status_class = "ssl-valid"
            status_text = f"Valid ({days_until_expiry} days remaining)"
            status_icon = "✅"
        else:
            status_class = "ssl-error"
            status_text = "Invalid"
            status_icon = "❌"
        
        issues_html = ""
        if security_issues:
            issue_items = ""
            for issue in security_issues:
                severity = issue.get("severity", "warning")
                issue_items += f'''
                <div class="issue-item issue-{severity}">
                    <div class="issue-content">
                        <div class="issue-title">{issue.get("type", "").replace("_", " ").title()}</div>
                        <div class="issue-desc">{issue.get("description", "")}</div>
                        <div class="issue-desc" style="margin-top: 0.25rem; color: var(--accent-cyan);">Recommendation: {issue.get("recommendation", "")}</div>
                    </div>
                </div>'''
            issues_html = f'''
            <h4 style="margin: 1.5rem 0 1rem; color: var(--accent-red);">Security Issues</h4>
            <div class="issues-list">{issue_items}</div>'''
        
        san_html = ""
        if san_list:
            san_display = san_list[:10]
            more = len(san_list) - 10 if len(san_list) > 10 else 0
            san_tags = " ".join([f'<span class="tech-tag cdn">{s}</span>' for s in san_display])
            if more > 0:
                san_tags += f' <span class="tech-tag service">+{more} more</span>'
            san_html = f'''
            <div style="margin-top: 1rem;">
                <div class="data-label">Subject Alternative Names ({len(san_list)})</div>
                <div style="margin-top: 0.5rem;">{san_tags}</div>
            </div>'''
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon ssl">🔐</div>
                <h3 class="section-title">SSL/TLS Certificate</h3>
            </div>
            <div class="section-content">
                <div class="ssl-status {status_class}">
                    <span style="font-size: 1.25rem;">{status_icon}</span>
                    <span style="font-weight: 600;">{status_text}</span>
                </div>
                
                <div class="data-grid">
                    <div class="data-item">
                        <div class="data-label">Common Name</div>
                        <div class="data-value">{subject.get("common_name", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Organization</div>
                        <div class="data-value">{subject.get("organization") or issuer.get("organization") or "N/A"}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Issuer</div>
                        <div class="data-value">{issuer.get("common_name", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Issuer Organization</div>
                        <div class="data-value">{issuer.get("organization", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Valid From</div>
                        <div class="data-value">{validity.get("not_before", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Valid Until</div>
                        <div class="data-value">{validity.get("not_after", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Protocol</div>
                        <div class="data-value">{connection.get("protocol", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Cipher Suite</div>
                        <div class="data-value">{connection.get("cipher_suite", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Signature Algorithm</div>
                        <div class="data-value">{ssl_data.get("signature_algorithm", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Serial Number</div>
                        <div class="data-value">{ssl_data.get("serial_number", "N/A")[:32]}...</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">SHA-256 Fingerprint</div>
                        <div class="data-value" style="font-size: 0.75rem;">{fingerprints.get("sha256", "N/A")[:48]}...</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Self-Signed</div>
                        <div class="data-value">{"Yes" if ssl_data.get("is_self_signed") else "No"}</div>
                    </div>
                </div>
                
                {san_html}
                {issues_html}
            </div>
        </div>'''
    
    def _generate_whois_section(self, results: Dict[str, Any]) -> str:
        """Generate WHOIS section."""
        if "whois" not in results or not results["whois"].get("success"):
            return ""
        
        whois_data = results["whois"].get("data", {})
        registrant = whois_data.get("registrant", {})
        domain_age = whois_data.get("domain_age", {})
        name_servers = whois_data.get("name_servers", [])
        status = whois_data.get("status", [])
        
        ns_tags = " ".join([f'<span class="tech-tag cdn">{ns}</span>' for ns in name_servers[:5]])
        if len(name_servers) > 5:
            ns_tags += f' <span class="tech-tag service">+{len(name_servers) - 5} more</span>'
        
        status_tags = " ".join([f'<span class="tech-tag service">{s[:30]}</span>' for s in status[:3]])
        
        registrant_info = []
        if registrant.get("name"):
            registrant_info.append(registrant["name"])
        if registrant.get("organization"):
            registrant_info.append(registrant["organization"])
        if registrant.get("country"):
            registrant_info.append(registrant["country"])
        registrant_str = ", ".join(registrant_info) if registrant_info else "N/A (Privacy Protected)"
        
        age_str = "N/A"
        if domain_age:
            age_str = f"{domain_age.get('years', 0)} years ({domain_age.get('days', 0)} days)"
        
        days_until_expiry = whois_data.get("days_until_expiry")
        expiry_class = ""
        if days_until_expiry is not None:
            if days_until_expiry < 30:
                expiry_class = "status-missing"
            elif days_until_expiry < 90:
                expiry_class = "style='color: var(--accent-yellow);'"
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon whois">📋</div>
                <h3 class="section-title">WHOIS Information</h3>
            </div>
            <div class="section-content">
                <div class="data-grid">
                    <div class="data-item">
                        <div class="data-label">Domain</div>
                        <div class="data-value">{whois_data.get("domain", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Registrar</div>
                        <div class="data-value">{whois_data.get("registrar", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Registrant</div>
                        <div class="data-value">{registrant_str}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Domain Age</div>
                        <div class="data-value">{age_str}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Created</div>
                        <div class="data-value">{whois_data.get("creation_date", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Expires</div>
                        <div class="data-value {expiry_class}">{whois_data.get("expiration_date", "N/A")} ({days_until_expiry} days)</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Last Updated</div>
                        <div class="data-value">{whois_data.get("updated_date", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">DNSSEC</div>
                        <div class="data-value">{whois_data.get("dnssec", "N/A")}</div>
                    </div>
                </div>
                
                <div style="margin-top: 1rem;">
                    <div class="data-label" style="margin-bottom: 0.5rem;">Name Servers</div>
                    <div>{ns_tags or "N/A"}</div>
                </div>
                
                <div style="margin-top: 1rem;">
                    <div class="data-label" style="margin-bottom: 0.5rem;">Domain Status</div>
                    <div>{status_tags or "N/A"}</div>
                </div>
            </div>
        </div>'''
    
    def _generate_dns_section(self, results: Dict[str, Any]) -> str:
        """Generate DNS section."""
        if "dns" not in results or not results["dns"].get("success"):
            return ""
        
        dns_data = results["dns"].get("data", {})
        ip_addresses = dns_data.get("ip_addresses", {})
        dns_records = dns_data.get("dns_records", {})
        asn_info = dns_data.get("asn_info", {})
        reverse_dns = dns_data.get("reverse_dns", [])
        
        records_html = ""
        for record_type, records in dns_records.items():
            if records:
                tags = " ".join([f'<span class="tech-tag cdn">{r[:50]}</span>' for r in records[:5]])
                records_html += f'''
                <div style="margin-bottom: 0.75rem;">
                    <div class="data-label">{record_type.upper()} Records</div>
                    <div style="margin-top: 0.25rem;">{tags}</div>
                </div>'''
        
        asn_html = ""
        if asn_info:
            asn_html = f'''
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                <h4 style="margin-bottom: 1rem; color: var(--text-primary);">ASN Information</h4>
                <div class="data-grid">
                    <div class="data-item">
                        <div class="data-label">ASN</div>
                        <div class="data-value">{asn_info.get("asn", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Organization</div>
                        <div class="data-value">{asn_info.get("name", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Network</div>
                        <div class="data-value">{asn_info.get("network", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Country</div>
                        <div class="data-value">{asn_info.get("country", "N/A")}</div>
                    </div>
                </div>
            </div>'''
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon dns">🌐</div>
                <h3 class="section-title">DNS & Network Intelligence</h3>
            </div>
            <div class="section-content">
                <div class="data-grid">
                    <div class="data-item">
                        <div class="data-label">IPv4 Addresses</div>
                        <div class="data-value">{", ".join(ip_addresses.get("ipv4", [])) or "N/A"}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">IPv6 Addresses</div>
                        <div class="data-value">{", ".join(ip_addresses.get("ipv6", [])[:2]) or "N/A"}</div>
                    </div>
                </div>
                
                <div style="margin-top: 1rem;">
                    {records_html}
                </div>
                
                {asn_html}
            </div>
        </div>'''
    
    def _generate_extra_section(self, results: Dict[str, Any]) -> str:
        """Generate extra intelligence section."""
        if "extra_intel" not in results or not results["extra_intel"].get("success"):
            return ""
        
        extra_data = results["extra_intel"].get("data", {})
        robots = extra_data.get("robots_txt", {})
        sitemap = extra_data.get("sitemap", {})
        favicon = extra_data.get("favicon", {})
        methods = extra_data.get("http_methods", {})
        
        items_html = ""
        
        if robots.get("exists"):
            items_html += f'''
            <div class="data-item">
                <div class="data-label">robots.txt</div>
                <div class="data-value status-present">Found ({robots.get("size", 0)} bytes)</div>
            </div>'''
        
        if sitemap.get("exists"):
            items_html += f'''
            <div class="data-item">
                <div class="data-label">sitemap.xml</div>
                <div class="data-value status-present">Found</div>
            </div>'''
        
        if favicon.get("exists"):
            items_html += f'''
            <div class="data-item">
                <div class="data-label">Favicon Hash (mmh3)</div>
                <div class="data-value">{favicon.get("mmh3_hash", "N/A")}</div>
            </div>'''
        
        if methods.get("allowed"):
            items_html += f'''
            <div class="data-item">
                <div class="data-label">HTTP Methods</div>
                <div class="data-value">{", ".join(methods.get("allowed", []))}</div>
            </div>'''
        
        if not items_html:
            return ""
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon extra">🔍</div>
                <h3 class="section-title">Additional Intelligence</h3>
            </div>
            <div class="section-content">
                <div class="data-grid">
                    {items_html}
                </div>
            </div>
        </div>'''
