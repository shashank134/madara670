"""HTML Report Output Handler for WebRecon."""

import os
from typing import Dict, Any, List
from datetime import datetime


class HTMLOutputHandler:
    """Handler for HTML report generation."""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
    
    def generate_report(
        self,
        all_results: List[Dict[str, Any]],
        scan_info: Dict[str, Any]
    ) -> str:
        """
        Generate an HTML report for all scan results.
        
        Args:
            all_results: List of all scan results
            scan_info: General scan information
        
        Returns:
            Path to the generated HTML report
        """
        os.makedirs(self.output_dir, exist_ok=True)
        
        html_content = self._generate_html(all_results, scan_info)
        
        output_path = os.path.join(self.output_dir, "report.html")
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_html(
        self,
        all_results: List[Dict[str, Any]],
        scan_info: Dict[str, Any]
    ) -> str:
        """Generate HTML content."""
        successful = sum(1 for r in all_results if r.get("success"))
        failed = len(all_results) - successful
        
        targets_html = ""
        for result in all_results:
            targets_html += self._generate_target_section(result)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRecon Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 2rem; border-radius: 1rem; margin-bottom: 2rem; }}
        h1 {{ color: #60a5fa; font-size: 2rem; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #94a3b8; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1.5rem; }}
        .stat-card {{ background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 0.5rem; text-align: center; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #60a5fa; }}
        .stat-label {{ color: #94a3b8; font-size: 0.875rem; }}
        .target-card {{ background: #1e293b; border-radius: 1rem; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .target-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 1rem; }}
        .target-url {{ color: #60a5fa; font-size: 1.25rem; word-break: break-all; }}
        .badge {{ padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
        .badge-success {{ background: #166534; color: #86efac; }}
        .badge-error {{ background: #991b1b; color: #fca5a5; }}
        .badge-grade {{ background: #1e40af; color: #93c5fd; }}
        .module-section {{ margin-top: 1rem; }}
        .module-title {{ color: #f8fafc; font-size: 1rem; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem; }}
        .module-content {{ background: #0f172a; padding: 1rem; border-radius: 0.5rem; font-size: 0.875rem; }}
        .security-headers {{ display: grid; gap: 0.5rem; }}
        .header-item {{ display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(255,255,255,0.02); border-radius: 0.25rem; }}
        .header-present {{ color: #86efac; }}
        .header-missing {{ color: #fca5a5; }}
        .tech-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        .tech-tag {{ background: #334155; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; }}
        pre {{ background: #0f172a; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; font-size: 0.75rem; }}
        .footer {{ text-align: center; margin-top: 2rem; color: #64748b; font-size: 0.875rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>WebRecon Scan Report</h1>
            <p class="subtitle">Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
            <div class="stats">
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
        
        <main>
            {targets_html}
        </main>
        
        <footer class="footer">
            <p>Generated by WebRecon v1.0.0</p>
        </footer>
    </div>
</body>
</html>'''
        
        return html
    
    def _generate_target_section(self, result: Dict[str, Any]) -> str:
        """Generate HTML section for a single target."""
        target = result.get("target", "Unknown")
        success = result.get("success", False)
        results = result.get("results", {})
        
        status_badge = '<span class="badge badge-success">Success</span>' if success else '<span class="badge badge-error">Failed</span>'
        
        grade = ""
        if "headers" in results:
            headers_data = results["headers"].get("data", {})
            security = headers_data.get("security_headers", {})
            if security.get("grade"):
                grade = f'<span class="badge badge-grade">Grade: {security.get("grade")}</span>'
        
        modules_html = ""
        
        if "headers" in results and results["headers"].get("success"):
            headers_data = results["headers"].get("data", {})
            security = headers_data.get("security_headers", {})
            
            present_html = "".join([
                f'<div class="header-item"><span>{h["header"]}</span><span class="header-present">Present</span></div>'
                for h in security.get("present", [])
            ])
            missing_html = "".join([
                f'<div class="header-item"><span>{h["header"]}</span><span class="header-missing">Missing</span></div>'
                for h in security.get("missing", [])
            ])
            
            modules_html += f'''
            <div class="module-section">
                <h4 class="module-title">Security Headers (Score: {security.get("score", "N/A")}%)</h4>
                <div class="module-content security-headers">
                    {present_html}{missing_html}
                </div>
            </div>'''
        
        if "tech_detect" in results and results["tech_detect"].get("success"):
            tech_data = results["tech_detect"].get("data", {})
            tech_tags = ""
            for category in ["web_servers", "frameworks", "cms", "languages", "analytics"]:
                for tech in tech_data.get(category, []):
                    tech_tags += f'<span class="tech-tag">{tech}</span>'
            
            if tech_tags:
                modules_html += f'''
                <div class="module-section">
                    <h4 class="module-title">Technologies Detected</h4>
                    <div class="module-content">
                        <div class="tech-list">{tech_tags}</div>
                    </div>
                </div>'''
        
        if "dns" in results and results["dns"].get("success"):
            dns_data = results["dns"].get("data", {})
            ip_info = dns_data.get("ip_addresses", {})
            ipv4 = ", ".join(ip_info.get("ipv4", [])) or "N/A"
            ipv6 = ", ".join(ip_info.get("ipv6", [])) or "N/A"
            
            modules_html += f'''
            <div class="module-section">
                <h4 class="module-title">Network Information</h4>
                <div class="module-content">
                    <p><strong>IPv4:</strong> {ipv4}</p>
                    <p><strong>IPv6:</strong> {ipv6}</p>
                </div>
            </div>'''
        
        if "ssl" in results and results["ssl"].get("success"):
            ssl_data = results["ssl"].get("data", {})
            validity = ssl_data.get("validity", {})
            issuer = ssl_data.get("issuer", {})
            
            modules_html += f'''
            <div class="module-section">
                <h4 class="module-title">SSL Certificate</h4>
                <div class="module-content">
                    <p><strong>Issuer:</strong> {issuer.get("organization", "N/A")}</p>
                    <p><strong>Valid Until:</strong> {validity.get("not_after", "N/A")}</p>
                    <p><strong>Days Until Expiry:</strong> {validity.get("days_until_expiry", "N/A")}</p>
                </div>
            </div>'''
        
        return f'''
        <div class="target-card">
            <div class="target-header">
                <span class="target-url">{target}</span>
                <div>{status_badge} {grade}</div>
            </div>
            {modules_html}
        </div>'''
