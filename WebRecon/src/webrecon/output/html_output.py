"""HTML Report Output Handler for WebRecon - Optimized for Large Scans."""

import os
import base64
from typing import Dict, Any, List
from datetime import datetime
import json


class HTMLOutputHandler:
    """Handler for HTML report generation with modern UI optimized for large datasets."""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        self.targets_per_page = 50
    
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
    
    def _encode_image_base64(self, image_path: str, max_size_kb: int = 200) -> str:
        """Encode an image file to base64, with optional size limit for thumbnails."""
        try:
            if os.path.exists(image_path):
                file_size = os.path.getsize(image_path)
                if file_size > max_size_kb * 1024 * 10:
                    thumb_path = image_path.replace(".png", "_thumb.png").replace("desktop", "thumb")
                    if os.path.exists(thumb_path):
                        with open(thumb_path, 'rb') as f:
                            return base64.b64encode(f.read()).decode('utf-8')
                
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
        """Generate HTML content with pagination and search."""
        successful = sum(1 for r in all_results if r.get("success"))
        failed = len(all_results) - successful
        
        # Calculate total technologies detected
        total_tech = 0
        for result in all_results:
            if "tech_detect" in result.get("results", {}):
                tech_data = result["results"]["tech_detect"].get("data", {})
                summary = tech_data.get("summary", {})
                total_tech += summary.get("total_detected", 0)
        
        targets_data = []
        for idx, result in enumerate(all_results):
            target = result.get("target", "Unknown")
            hostname = result.get("hostname", target)
            success = result.get("success", False)
            results = result.get("results", {})
            output_folder = result.get("output_folder", "")
            
            grade = ""
            if "headers" in results:
                headers_data = results["headers"].get("data", {})
                security = headers_data.get("security_headers", {})
                grade = security.get("grade", "")
            
            tech_count = 0
            tech_list = []
            if "tech_detect" in results and results["tech_detect"].get("success"):
                tech_data = results["tech_detect"].get("data", {})
                summary = tech_data.get("summary", {})
                tech_count = summary.get("total_detected", 0)
                for cat, techs in tech_data.items():
                    if cat != "summary" and isinstance(techs, list):
                        tech_list.extend(techs[:5])
            
            screenshot_thumb = ""
            if "screenshot" in results and results["screenshot"].get("success"):
                ss_data = results["screenshot"].get("data", {})
                thumb_info = ss_data.get("thumbnail", {})
                if thumb_info.get("path"):
                    screenshot_thumb = self._encode_image_base64(thumb_info["path"])
                elif ss_data.get("desktop", {}).get("path"):
                    screenshot_thumb = self._encode_image_base64(ss_data["desktop"]["path"])
            
            targets_data.append({
                "idx": idx,
                "target": target,
                "hostname": hostname,
                "success": success,
                "grade": grade,
                "tech_count": tech_count,
                "tech_list": tech_list[:8],
                "screenshot_thumb": screenshot_thumb,
                "has_screenshot": bool(screenshot_thumb)
            })
        
        targets_json = json.dumps(targets_data)
        
        full_results_sections = ""
        for idx, result in enumerate(all_results):
            full_results_sections += self._generate_target_section(result, idx)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRecon Scan Report - {len(all_results)} Targets</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
            --accent-pink: #ec4899;
            --border-color: #374151;
            --gradient-start: #1e3a5f;
            --gradient-end: #0a0f1a;
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.4);
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
            width: 320px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }}
        
        .sidebar-header {{
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .logo {{
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .search-container {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .search-input {{
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            color: var(--text-primary);
            font-size: 0.875rem;
        }}
        
        .search-input:focus {{
            outline: none;
            border-color: var(--accent-cyan);
        }}
        
        .filter-controls {{
            padding: 0.75rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            padding: 0.375rem 0.75rem;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.375rem;
            color: var(--text-secondary);
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
            border-color: var(--accent-cyan);
        }}
        
        .sidebar-stats {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 1rem;
        }}
        
        .stat-mini {{
            flex: 1;
            text-align: center;
        }}
        
        .stat-mini-value {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--accent-cyan);
        }}
        
        .stat-mini-label {{
            font-size: 0.625rem;
            text-transform: uppercase;
            color: var(--text-muted);
        }}
        
        .sidebar-nav {{
            flex: 1;
            overflow-y: auto;
            padding: 0.5rem;
        }}
        
        .nav-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            color: var(--text-secondary);
            text-decoration: none;
            padding: 0.625rem 0.75rem;
            border-radius: 0.5rem;
            transition: all 0.2s;
            font-size: 0.8125rem;
            cursor: pointer;
            margin-bottom: 0.25rem;
        }}
        
        .nav-item:hover {{
            background: var(--bg-hover);
            color: var(--text-primary);
        }}
        
        .nav-item.active {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
        }}
        
        .nav-item-thumb {{
            width: 40px;
            height: 24px;
            border-radius: 0.25rem;
            object-fit: cover;
            background: var(--bg-card);
        }}
        
        .nav-item-info {{
            flex: 1;
            min-width: 0;
        }}
        
        .nav-item-host {{
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .nav-item-badges {{
            display: flex;
            gap: 0.25rem;
            margin-top: 0.125rem;
        }}
        
        .nav-badge {{
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.625rem;
            font-weight: 600;
        }}
        
        .nav-badge.success {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }}
        .nav-badge.error {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }}
        .nav-badge.grade-a {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }}
        .nav-badge.grade-b {{ background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); }}
        .nav-badge.grade-c {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); }}
        .nav-badge.grade-d {{ background: rgba(249, 115, 22, 0.2); color: #f97316; }}
        .nav-badge.grade-f {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }}
        .nav-badge.tech {{ background: rgba(139, 92, 246, 0.2); color: var(--accent-purple); }}
        
        .pagination-controls {{
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .page-btn {{
            padding: 0.5rem 0.75rem;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.375rem;
            color: var(--text-secondary);
            font-size: 0.75rem;
            cursor: pointer;
        }}
        
        .page-btn:hover:not(:disabled) {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
        }}
        
        .page-btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        
        .page-info {{
            font-size: 0.75rem;
            color: var(--text-muted);
        }}
        
        .main-content {{
            margin-left: 320px;
            flex: 1;
            padding: 2rem;
        }}
        
        .header {{
            background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%);
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        
        .header h1 {{
            font-size: 1.75rem;
            margin-bottom: 0.5rem;
        }}
        
        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-top: 1.5rem;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            padding: 1rem;
            border-radius: 0.75rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.2s, border-color 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-cyan);
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.6875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .view-controls {{
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }}
        
        .view-btn {{
            padding: 0.625rem 1.25rem;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .view-btn:hover, .view-btn.active {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
            border-color: var(--accent-cyan);
        }}
        
        .grid-view {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
        }}
        
        .grid-card {{
            background: var(--bg-card);
            border-radius: 0.75rem;
            overflow: hidden;
            border: 1px solid var(--border-color);
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
        }}
        
        .grid-card:hover {{
            border-color: var(--accent-cyan);
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl);
        }}
        
        .grid-card-thumb {{
            width: 100%;
            height: 160px;
            object-fit: cover;
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
        }}
        
        .grid-card-placeholder {{
            width: 100%;
            height: 160px;
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-muted);
            font-size: 2.5rem;
        }}
        
        .grid-card-body {{
            padding: 1.25rem;
            flex: 1;
            display: flex;
            flex-direction: column;
        }}
        
        .grid-card-host {{
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--accent-cyan);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 0.75rem;
        }}
        
        .grid-card-badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 0.75rem;
        }}
        
        .badge {{
            padding: 0.375rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.6875rem;
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
        .badge-tech {{ background: rgba(139, 92, 246, 0.2); color: var(--accent-purple); }}
        
        .grid-card-techs {{
            display: flex;
            gap: 0.375rem;
            flex-wrap: wrap;
            margin-top: auto;
        }}
        
        .tech-chip {{
            padding: 0.25rem 0.5rem;
            background: rgba(59, 130, 246, 0.15);
            border-radius: 0.25rem;
            font-size: 0.6875rem;
            color: var(--accent-blue);
        }}
        
        .list-view {{
            display: none;
        }}
        
        .list-view.active {{
            display: block;
        }}
        
        .grid-view.active {{
            display: grid;
        }}
        
        .target-card {{
            background: var(--bg-card);
            border-radius: 1rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-color);
            overflow: hidden;
            display: none;
        }}
        
        .target-card.visible {{
            display: block;
        }}
        
        .target-header {{
            background: var(--bg-secondary);
            padding: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            cursor: pointer;
        }}
        
        .target-url {{
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--accent-cyan);
            word-break: break-all;
        }}
        
        .badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .expand-indicator {{
            color: var(--text-muted);
            font-size: 0.75rem;
            transition: transform 0.2s;
        }}
        
        .target-card.expanded .expand-indicator {{
            transform: rotate(180deg);
        }}
        
        .target-body {{
            padding: 1.25rem;
            display: none;
        }}
        
        .target-card.expanded .target-body {{
            display: block;
        }}
        
        .section {{
            margin-bottom: 1.5rem;
        }}
        
        .section:last-child {{
            margin-bottom: 0;
        }}
        
        .section-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .section-icon {{
            width: 32px;
            height: 32px;
            border-radius: 0.375rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }}
        
        .section-icon.screenshot {{ background: rgba(139, 92, 246, 0.2); }}
        .section-icon.headers {{ background: rgba(59, 130, 246, 0.2); }}
        .section-icon.tech {{ background: rgba(16, 185, 129, 0.2); }}
        .section-icon.dns {{ background: rgba(6, 182, 212, 0.2); }}
        .section-icon.ssl {{ background: rgba(245, 158, 11, 0.2); }}
        .section-icon.whois {{ background: rgba(236, 72, 153, 0.2); }}
        .section-icon.extra {{ background: rgba(99, 102, 241, 0.2); }}
        
        .section-title {{
            font-size: 1rem;
            font-weight: 600;
        }}
        
        .section-content {{
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
        }}
        
        .screenshot-gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }}
        
        .screenshot-item {{
            background: var(--bg-primary);
            border-radius: 0.375rem;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        
        .screenshot-item img {{
            width: 100%;
            height: auto;
            display: block;
            cursor: pointer;
        }}
        
        .screenshot-item img:hover {{
            opacity: 0.9;
        }}
        
        .screenshot-label {{
            padding: 0.5rem;
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-align: center;
            border-top: 1px solid var(--border-color);
        }}
        
        .data-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.75rem;
        }}
        
        .data-item {{
            background: var(--bg-primary);
            padding: 0.75rem;
            border-radius: 0.375rem;
            border: 1px solid var(--border-color);
        }}
        
        .data-label {{
            font-size: 0.6875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.125rem;
        }}
        
        .data-value {{
            font-size: 0.8125rem;
            color: var(--text-primary);
            word-break: break-all;
        }}
        
        .tech-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.375rem;
        }}
        
        .tech-category {{
            margin-bottom: 0.75rem;
        }}
        
        .tech-category:last-child {{
            margin-bottom: 0;
        }}
        
        .tech-category-title {{
            font-size: 0.6875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.375rem;
        }}
        
        .tech-tag {{
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.6875rem;
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
        .tech-tag.css {{ background: rgba(99, 102, 241, 0.2); color: #818cf8; }}
        .tech-tag.security {{ background: rgba(239, 68, 68, 0.2); color: #f87171; }}
        .tech-tag.marketing {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; }}
        .tech-tag.ai {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; }}
        .tech-tag.database {{ background: rgba(6, 182, 212, 0.2); color: #22d3ee; }}
        
        .header-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }}
        
        .header-table th,
        .header-table td {{
            padding: 0.5rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .header-table th {{
            font-size: 0.6875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: var(--bg-primary);
        }}
        
        .header-name {{
            color: var(--accent-cyan);
            font-weight: 500;
        }}
        
        .header-value {{
            color: var(--text-secondary);
            word-break: break-all;
            max-width: 400px;
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
            padding: 0.75rem;
            border-radius: 0.375rem;
            margin-bottom: 0.75rem;
            font-size: 0.875rem;
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
            gap: 0.5rem;
        }}
        
        .issue-item {{
            display: flex;
            gap: 0.5rem;
            padding: 0.75rem;
            background: var(--bg-primary);
            border-radius: 0.375rem;
            border-left: 3px solid;
            font-size: 0.8125rem;
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
            margin-bottom: 0.125rem;
        }}
        
        .issue-desc {{
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}
        
        .raw-headers {{
            background: var(--bg-primary);
            padding: 0.75rem;
            border-radius: 0.375rem;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.6875rem;
            overflow-x: auto;
            max-height: 250px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .collapsible-section {{
            cursor: pointer;
        }}
        
        .collapsible-section .section-content {{
            display: none;
        }}
        
        .collapsible-section.active .section-content {{
            display: block;
        }}
        
        .collapsible-toggle {{
            font-size: 0.6875rem;
            color: var(--accent-blue);
            margin-left: auto;
        }}
        
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        
        .modal.active {{
            display: flex;
        }}
        
        .modal img {{
            max-width: 95%;
            max-height: 95%;
            object-fit: contain;
        }}
        
        .modal-close {{
            position: fixed;
            top: 1rem;
            right: 1rem;
            font-size: 2rem;
            color: white;
            cursor: pointer;
            z-index: 1001;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.75rem;
        }}
        
        .no-results {{
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
        }}
        
        @media (max-width: 1024px) {{
            .sidebar {{
                width: 280px;
            }}
            .main-content {{
                margin-left: 280px;
            }}
            .stats-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
        }}
        
        @media (max-width: 768px) {{
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
            <div class="search-container">
                <input type="text" class="search-input" id="searchInput" placeholder="Search domains...">
            </div>
            <div class="filter-controls">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="success">Success</button>
                <button class="filter-btn" data-filter="failed">Failed</button>
                <button class="filter-btn" data-filter="screenshot">Screenshots</button>
            </div>
            <div class="sidebar-stats">
                <div class="stat-mini">
                    <div class="stat-mini-value">{len(all_results)}</div>
                    <div class="stat-mini-label">Total</div>
                </div>
                <div class="stat-mini">
                    <div class="stat-mini-value">{successful}</div>
                    <div class="stat-mini-label">Success</div>
                </div>
                <div class="stat-mini">
                    <div class="stat-mini-value">{failed}</div>
                    <div class="stat-mini-label">Failed</div>
                </div>
            </div>
            <nav class="sidebar-nav" id="sidebarNav">
            </nav>
            <div class="pagination-controls" id="paginationControls">
                <button class="page-btn" id="prevPage">Prev</button>
                <span class="page-info" id="pageInfo">1 / 1</span>
                <button class="page-btn" id="nextPage">Next</button>
            </div>
        </aside>
        
        <main class="main-content">
            <header class="header">
                <h1>Reconnaissance Report</h1>
                <p class="subtitle">Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC | {len(all_results)} targets scanned</p>
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
                    <div class="stat-card">
                        <div class="stat-value">{total_tech}</div>
                        <div class="stat-label">Technologies</div>
                    </div>
                </div>
            </header>
            
            <div class="view-controls">
                <button class="view-btn active" id="listViewBtn">List View</button>
                <button class="view-btn" id="gridViewBtn">Grid View</button>
                <button class="view-btn" id="expandAllBtn">Expand All</button>
                <button class="view-btn" id="collapseAllBtn">Collapse All</button>
            </div>
            
            <div class="grid-view" id="gridView" style="display: none;">
            </div>
            
            <div class="list-view active" id="listView">
                {full_results_sections}
            </div>
            
            <div class="no-results" id="noResults" style="display: none;">
                <p>No results match your search criteria.</p>
            </div>
            
            <footer class="footer">
                <p>Generated by WebRecon v1.0.0 - Professional Web Reconnaissance Tool</p>
            </footer>
        </main>
    </div>
    
    <div class="modal" id="imageModal">
        <span class="modal-close" onclick="closeModal()">&times;</span>
        <img id="modalImage" src="" alt="Full Screenshot">
    </div>
    
    <script>
        const targetsData = {targets_json};
        let currentFilter = 'all';
        let searchQuery = '';
        let currentPage = 1;
        const itemsPerPage = 25;
        
        function getFilteredTargets() {{
            return targetsData.filter(t => {{
                const matchesSearch = t.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
                                     t.target.toLowerCase().includes(searchQuery.toLowerCase());
                
                let matchesFilter = true;
                if (currentFilter === 'success') matchesFilter = t.success;
                else if (currentFilter === 'failed') matchesFilter = !t.success;
                else if (currentFilter === 'screenshot') matchesFilter = t.has_screenshot;
                
                return matchesSearch && matchesFilter;
            }});
        }}
        
        function updateSidebar() {{
            const filtered = getFilteredTargets();
            const totalPages = Math.ceil(filtered.length / itemsPerPage);
            currentPage = Math.min(currentPage, Math.max(1, totalPages));
            
            const start = (currentPage - 1) * itemsPerPage;
            const pageTargets = filtered.slice(start, start + itemsPerPage);
            
            const nav = document.getElementById('sidebarNav');
            nav.innerHTML = pageTargets.map(t => `
                <div class="nav-item" onclick="showTarget(${{t.idx}})">
                    ${{t.screenshot_thumb ? 
                        `<img class="nav-item-thumb" src="data:image/png;base64,${{t.screenshot_thumb}}" alt="">` : 
                        `<div class="nav-item-thumb"></div>`}}
                    <div class="nav-item-info">
                        <div class="nav-item-host">${{t.hostname}}</div>
                        <div class="nav-item-badges">
                            <span class="nav-badge ${{t.success ? 'success' : 'error'}}">${{t.success ? 'OK' : 'FAIL'}}</span>
                            ${{t.grade ? `<span class="nav-badge grade-${{t.grade.toLowerCase()}}">Grade ${{t.grade}}</span>` : ''}}
                            ${{t.tech_count ? `<span class="nav-badge tech">${{t.tech_count}} tech</span>` : ''}}
                        </div>
                    </div>
                </div>
            `).join('');
            
            document.getElementById('pageInfo').textContent = `${{currentPage}} / ${{totalPages || 1}}`;
            document.getElementById('prevPage').disabled = currentPage <= 1;
            document.getElementById('nextPage').disabled = currentPage >= totalPages;
            
            updateMainView(filtered);
        }}
        
        function updateMainView(filtered) {{
            const targetCards = document.querySelectorAll('.target-card');
            const filteredIds = new Set(filtered.map(t => t.idx));
            
            let visibleCount = 0;
            targetCards.forEach((card, idx) => {{
                if (filteredIds.has(idx)) {{
                    card.classList.add('visible');
                    visibleCount++;
                }} else {{
                    card.classList.remove('visible');
                }}
            }});
            
            document.getElementById('noResults').style.display = visibleCount === 0 ? 'block' : 'none';
            
            const gridView = document.getElementById('gridView');
            gridView.innerHTML = filtered.slice(0, 50).map(t => `
                <div class="grid-card" onclick="showTarget(${{t.idx}})">
                    ${{t.screenshot_thumb ? 
                        `<img class="grid-card-thumb" src="data:image/png;base64,${{t.screenshot_thumb}}" alt="">` : 
                        `<div class="grid-card-placeholder">🌐</div>`}}
                    <div class="grid-card-body">
                        <div class="grid-card-host">${{t.hostname}}</div>
                        <div class="grid-card-badges">
                            <span class="badge badge-${{t.success ? 'success' : 'error'}}">${{t.success ? 'OK' : 'FAIL'}}</span>
                            ${{t.grade ? `<span class="badge badge-grade-${{t.grade.toLowerCase()}}">Grade ${{t.grade}}</span>` : ''}}
                            ${{t.tech_count ? `<span class="badge badge-tech">${{t.tech_count}} tech</span>` : ''}}
                        </div>
                        ${{t.tech_list && t.tech_list.length > 0 ? `
                            <div class="grid-card-techs">
                                ${{t.tech_list.slice(0, 5).map(tech => `<span class="tech-chip">${{tech}}</span>`).join('')}}
                                ${{t.tech_list.length > 5 ? `<span class="tech-chip">+${{t.tech_list.length - 5}}</span>` : ''}}
                            </div>
                        ` : ''}}
                    </div>
                </div>
            `).join('');
        }}
        
        function showTarget(idx) {{
            const targetCards = document.querySelectorAll('.target-card');
            targetCards.forEach((card, i) => {{
                if (i === idx) {{
                    card.classList.add('expanded', 'visible');
                    card.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                }}
            }});
            
            document.getElementById('listView').classList.add('active');
            document.getElementById('gridView').style.display = 'none';
            document.getElementById('listViewBtn').classList.add('active');
            document.getElementById('gridViewBtn').classList.remove('active');
        }}
        
        document.getElementById('searchInput').addEventListener('input', (e) => {{
            searchQuery = e.target.value;
            currentPage = 1;
            updateSidebar();
        }});
        
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.dataset.filter;
                currentPage = 1;
                updateSidebar();
            }});
        }});
        
        document.getElementById('prevPage').addEventListener('click', () => {{
            if (currentPage > 1) {{
                currentPage--;
                updateSidebar();
            }}
        }});
        
        document.getElementById('nextPage').addEventListener('click', () => {{
            const totalPages = Math.ceil(getFilteredTargets().length / itemsPerPage);
            if (currentPage < totalPages) {{
                currentPage++;
                updateSidebar();
            }}
        }});
        
        document.getElementById('listViewBtn').addEventListener('click', () => {{
            document.getElementById('listView').classList.add('active');
            document.getElementById('gridView').style.display = 'none';
            document.getElementById('listViewBtn').classList.add('active');
            document.getElementById('gridViewBtn').classList.remove('active');
        }});
        
        document.getElementById('gridViewBtn').addEventListener('click', () => {{
            document.getElementById('listView').classList.remove('active');
            document.getElementById('gridView').style.display = 'grid';
            document.getElementById('listViewBtn').classList.remove('active');
            document.getElementById('gridViewBtn').classList.add('active');
        }});
        
        document.getElementById('expandAllBtn').addEventListener('click', () => {{
            document.querySelectorAll('.target-card.visible').forEach(card => {{
                card.classList.add('expanded');
            }});
        }});
        
        document.getElementById('collapseAllBtn').addEventListener('click', () => {{
            document.querySelectorAll('.target-card').forEach(card => {{
                card.classList.remove('expanded');
            }});
        }});
        
        document.querySelectorAll('.target-header').forEach(header => {{
            header.addEventListener('click', () => {{
                header.closest('.target-card').classList.toggle('expanded');
            }});
        }});
        
        document.querySelectorAll('.collapsible-section .section-header').forEach(header => {{
            header.addEventListener('click', (e) => {{
                e.stopPropagation();
                header.closest('.collapsible-section').classList.toggle('active');
            }});
        }});
        
        function openModal(imgSrc) {{
            document.getElementById('modalImage').src = imgSrc;
            document.getElementById('imageModal').classList.add('active');
        }}
        
        function closeModal() {{
            document.getElementById('imageModal').classList.remove('active');
        }}
        
        document.getElementById('imageModal').addEventListener('click', (e) => {{
            if (e.target === document.getElementById('imageModal')) {{
                closeModal();
            }}
        }});
        
        document.addEventListener('keydown', (e) => {{
            if (e.key === 'Escape') closeModal();
        }});
        
        updateSidebar();
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
                <div>
                    <span class="target-url">{target}</span>
                </div>
                <div class="badges">
                    {status_badge} {grade}
                    <span class="expand-indicator">▼</span>
                </div>
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
        
        screenshots_html = ""
        
        if desktop.get("path"):
            img_base64 = self._encode_image_base64(desktop["path"])
            if img_base64:
                screenshots_html += f'''
                <div class="screenshot-item">
                    <img src="data:image/png;base64,{img_base64}" alt="Desktop Screenshot" onclick="openModal(this.src)">
                    <div class="screenshot-label">Desktop ({desktop.get("width", "?")}x{desktop.get("height", "?")})</div>
                </div>'''
        
        if mobile.get("path"):
            img_base64 = self._encode_image_base64(mobile["path"])
            if img_base64:
                screenshots_html += f'''
                <div class="screenshot-item">
                    <img src="data:image/png;base64,{img_base64}" alt="Mobile Screenshot" onclick="openModal(this.src)">
                    <div class="screenshot-label">Mobile (375x812)</div>
                </div>'''
        
        if not screenshots_html:
            return ""
        
        title_html = f'<p style="margin-bottom: 0.75rem; color: var(--text-secondary); font-size: 0.8125rem;"><strong>Page Title:</strong> {page_title}</p>' if page_title else ""
        
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
        status_code = headers_data.get("status_code", "")
        
        score = security.get("score", 0)
        present = security.get("present", [])
        missing = security.get("missing", [])
        
        security_rows = ""
        for h in present[:10]:
            severity_class = f"severity-{h.get('severity', 'low')}"
            val = h.get("value", "")[:80] + ("..." if len(h.get("value", "")) > 80 else "")
            security_rows += f'''
            <tr>
                <td class="header-name">{h["header"]}</td>
                <td class="status-present">Present</td>
                <td class="{severity_class}">{h.get("severity", "").title()}</td>
                <td class="header-value">{val}</td>
            </tr>'''
        
        for h in missing[:10]:
            severity_class = f"severity-{h.get('severity', 'low')}"
            security_rows += f'''
            <tr>
                <td class="header-name">{h["header"]}</td>
                <td class="status-missing">Missing</td>
                <td class="{severity_class}">{h.get("severity", "").title()}</td>
                <td class="header-value">{h.get("description", "")[:80]}</td>
            </tr>'''
        
        raw_headers = "\n".join([f"{k}: {v[:200]}" for k, v in list(all_headers.items())[:30]])
        
        server_html = ""
        if server_info.get("server") or server_info.get("powered_by"):
            server_items = []
            if server_info.get("server"):
                server_items.append(f"<strong>Server:</strong> {server_info['server']}")
            if server_info.get("powered_by"):
                server_items.append(f"<strong>Powered By:</strong> {server_info['powered_by']}")
            server_html = f'<p style="margin-bottom: 0.75rem; color: var(--text-secondary); font-size: 0.8125rem;">{" | ".join(server_items)}</p>'
        
        cdn_html = ""
        if cdn_waf.get("detected"):
            cdn_tags = " ".join([f'<span class="tech-tag cdn">{c}</span>' for c in cdn_waf["detected"][:5]])
            cdn_html = f'<div style="margin-bottom: 0.75rem;"><span style="color: var(--text-muted); font-size: 0.75rem;">CDN/WAF:</span> {cdn_tags}</div>'
        
        return f'''
        <div class="section collapsible-section active">
            <div class="section-header">
                <div class="section-icon headers">🔒</div>
                <h3 class="section-title">HTTP Headers & Security (Score: {score}%)</h3>
                <span class="collapsible-toggle">Click to toggle</span>
            </div>
            <div class="section-content">
                <p style="margin-bottom: 0.75rem; color: var(--text-secondary); font-size: 0.8125rem;"><strong>Status Code:</strong> {status_code}</p>
                {server_html}
                {cdn_html}
                
                <h4 style="margin: 1rem 0 0.5rem; color: var(--text-primary); font-size: 0.875rem;">Security Headers Analysis</h4>
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
                
                <h4 style="margin: 1rem 0 0.5rem; color: var(--text-primary); font-size: 0.875rem;">All Response Headers</h4>
                <div class="raw-headers">{raw_headers}</div>
            </div>
        </div>'''
    
    def _generate_tech_section(self, results: Dict[str, Any]) -> str:
        """Generate technology detection section."""
        if "tech_detect" not in results or not results["tech_detect"].get("success"):
            return ""
        
        tech_data = results["tech_detect"].get("data", {})
        
        category_map = {
            "web_servers": ("Web Servers", "server"),
            "languages": ("Languages", "language"),
            "frameworks": ("Frameworks", "framework"),
            "cms": ("CMS", "cms"),
            "analytics": ("Analytics", "analytics"),
            "payment": ("Payment", "payment"),
            "cdn_waf": ("CDN/WAF", "cdn"),
            "js_libraries": ("JavaScript", "js"),
            "css_frameworks": ("CSS Frameworks", "css"),
            "services": ("Services", "service"),
            "hosting": ("Hosting", "service"),
            "ecommerce": ("E-commerce", "payment"),
            "security": ("Security", "security"),
            "marketing": ("Marketing", "marketing"),
            "ai_ml": ("AI/ML", "ai"),
            "communication": ("Communication", "service"),
            "database": ("Database", "database"),
        }
        
        categories_html = ""
        total_count = 0
        
        for key, (label, css_class) in category_map.items():
            techs = tech_data.get(key, [])
            if techs:
                total_count += len(techs)
                tags = " ".join([f'<span class="tech-tag {css_class}">{t}</span>' for t in techs[:20]])
                if len(techs) > 20:
                    tags += f' <span class="tech-tag service">+{len(techs) - 20} more</span>'
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
            for issue in security_issues[:5]:
                severity = issue.get("severity", "warning")
                issue_items += f'''
                <div class="issue-item issue-{severity}">
                    <div class="issue-content">
                        <div class="issue-title">{issue.get("type", "").replace("_", " ").title()}</div>
                        <div class="issue-desc">{issue.get("description", "")}</div>
                    </div>
                </div>'''
            issues_html = f'''
            <h4 style="margin: 1rem 0 0.5rem; color: var(--accent-red); font-size: 0.875rem;">Security Issues</h4>
            <div class="issues-list">{issue_items}</div>'''
        
        san_html = ""
        if san_list:
            san_display = san_list[:8]
            more = len(san_list) - 8 if len(san_list) > 8 else 0
            san_tags = " ".join([f'<span class="tech-tag cdn">{s}</span>' for s in san_display])
            if more > 0:
                san_tags += f' <span class="tech-tag service">+{more} more</span>'
            san_html = f'''
            <div style="margin-top: 0.75rem;">
                <div class="data-label">Subject Alternative Names ({len(san_list)})</div>
                <div style="margin-top: 0.375rem;">{san_tags}</div>
            </div>'''
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon ssl">🔐</div>
                <h3 class="section-title">SSL/TLS Certificate</h3>
            </div>
            <div class="section-content">
                <div class="ssl-status {status_class}">
                    <span style="font-size: 1rem;">{status_icon}</span>
                    <span style="font-weight: 600; font-size: 0.875rem;">{status_text}</span>
                </div>
                
                <div class="data-grid">
                    <div class="data-item">
                        <div class="data-label">Common Name</div>
                        <div class="data-value">{subject.get("common_name", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Issuer</div>
                        <div class="data-value">{issuer.get("common_name", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Valid Until</div>
                        <div class="data-value">{validity.get("not_after", "N/A")}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Protocol</div>
                        <div class="data-value">{connection.get("protocol", "N/A")}</div>
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
        
        ns_tags = " ".join([f'<span class="tech-tag cdn">{ns}</span>' for ns in name_servers[:4]])
        if len(name_servers) > 4:
            ns_tags += f' <span class="tech-tag service">+{len(name_servers) - 4} more</span>'
        
        registrant_str = registrant.get("organization") or registrant.get("name") or "N/A (Privacy Protected)"
        
        age_str = "N/A"
        if domain_age:
            age_str = f"{domain_age.get('years', 0)} years"
        
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
                        <div class="data-value">{whois_data.get("expiration_date", "N/A")}</div>
                    </div>
                </div>
                
                <div style="margin-top: 0.75rem;">
                    <div class="data-label" style="margin-bottom: 0.375rem;">Name Servers</div>
                    <div>{ns_tags or "N/A"}</div>
                </div>
            </div>
        </div>'''
    
    def _generate_dns_section(self, results: Dict[str, Any]) -> str:
        """Generate DNS section."""
        if "dns" not in results or not results["dns"].get("success"):
            return ""
        
        dns_data = results["dns"].get("data", {})
        
        # Check different possible data structures
        dns_records = {}
        
        # Try different possible keys for DNS records
        if "dns_records" in dns_data:
            dns_records = dns_data.get("dns_records", {})
        elif "records" in dns_data:
            dns_records = dns_data.get("records", {})
        elif "dns" in dns_data:
            dns_records = dns_data.get("dns", {})
        
        ip_addresses = dns_data.get("ip_addresses", {})
        asn_info = dns_data.get("asn_info", {})
        
        # If no DNS records found, return empty
        if not dns_records and not ip_addresses:
            return ""
        
        # Build IP addresses section
        ip_html = ""
        if ip_addresses:
            ipv4_list = ip_addresses.get("ipv4", []) or ip_addresses.get("IPv4", [])
            ipv6_list = ip_addresses.get("ipv6", []) or ip_addresses.get("IPv6", [])
            
            if ipv4_list or ipv6_list:
                ip_html = '''
                <div class="data-grid">'''
                
                if ipv4_list:
                    ipv4_str = ", ".join([str(ip) for ip in ipv4_list[:3]])
                    if len(ipv4_list) > 3:
                        ipv4_str += f" (+{len(ipv4_list)-3} more)"
                    ip_html += f'''
                    <div class="data-item">
                        <div class="data-label">IPv4 Addresses</div>
                        <div class="data-value">{ipv4_str or "N/A"}</div>
                    </div>'''
                
                if ipv6_list:
                    ipv6_str = ", ".join([str(ip) for ip in ipv6_list[:2]])
                    if len(ipv6_list) > 2:
                        ipv6_str += f" (+{len(ipv6_list)-2} more)"
                    ip_html += f'''
                    <div class="data-item">
                        <div class="data-label">IPv6 Addresses</div>
                        <div class="data-value">{ipv6_str or "N/A"}</div>
                    </div>'''
                
                ip_html += '''
                </div>'''
        
        # Build DNS records section
        dns_items_html = ""
        if dns_records:
            # Common DNS record types to display
            record_types_to_show = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR']
            
            for record_type in record_types_to_show:
                # Try different case variations
                records = None
                if record_type in dns_records:
                    records = dns_records[record_type]
                elif record_type.lower() in dns_records:
                    records = dns_records[record_type.lower()]
                elif record_type.upper() in dns_records:
                    records = dns_records[record_type.upper()]
                
                if records and isinstance(records, (list, tuple)):
                    # For TXT records, they might be long, so truncate
                    if record_type == 'TXT':
                        display_records = []
                        for r in records[:3]:  # Show only first 3 TXT records
                            if isinstance(r, str):
                                if len(r) > 100:
                                    display_records.append(r[:97] + "...")
                                else:
                                    display_records.append(r)
                            else:
                                display_records.append(str(r))
                        value_str = ", ".join(display_records)
                    else:
                        value_str = ", ".join([str(r) for r in records[:3]])  # Show first 3 records
                    
                    if len(records) > 3:
                        value_str += f" (+{len(records)-3} more)"
                    
                    if not dns_items_html:
                        dns_items_html = '<div style="margin-top: 1rem;"><h4 style="margin-bottom: 0.5rem; color: var(--text-primary); font-size: 0.875rem;">DNS Records</h4><div class="data-grid">'
                    
                    dns_items_html += f'''
                    <div class="data-item">
                        <div class="data-label">{record_type} Records</div>
                        <div class="data-value">{value_str}</div>
                    </div>'''
            
            if dns_items_html:
                dns_items_html += '</div></div>'
        
        # Build ASN information section
        asn_html = ""
        if asn_info:
            asn_html = f'''
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                <h4 style="margin-bottom: 0.5rem; color: var(--text-primary); font-size: 0.875rem;">ASN Information</h4>
                <div class="data-grid">
                    <div class="data-item">
                        <div class="data-label">ASN</div>
                        <div class="data-value">{asn_info.get("asn", asn_info.get("ASN", "N/A"))}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Organization</div>
                        <div class="data-value">{asn_info.get("name", asn_info.get("organization", asn_info.get("org", "N/A")))}</div>
                    </div>
                    <div class="data-item">
                        <div class="data-label">Country</div>
                        <div class="data-value">{asn_info.get("country", asn_info.get("country_code", "N/A"))}</div>
                    </div>
                </div>
            </div>'''
        
        # If there's no content at all, return empty
        if not ip_html and not dns_items_html and not asn_html:
            return ""
        
        return f'''
        <div class="section">
            <div class="section-header">
                <div class="section-icon dns">🌐</div>
                <h3 class="section-title">DNS & Network Intelligence</h3>
            </div>
            <div class="section-content">
                {ip_html}
                {dns_items_html}
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