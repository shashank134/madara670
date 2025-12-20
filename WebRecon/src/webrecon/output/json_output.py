"""JSON Output Handler for WebRecon - Optimized folder structure."""

import json
import os
from typing import Dict, Any, List
from datetime import datetime


class JSONOutputHandler:
    """Handler for JSON output format with consolidated folder structure."""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        self.results_dir = os.path.join(output_dir, "results")
    
    def save_target_result(
        self,
        target: str,
        results: Dict[str, Any],
        folder_name: str
    ) -> str:
        """
        Save scan results for a single target to consolidated results folder.
        
        Args:
            target: Target URL
            results: Scan results dictionary
            folder_name: Safe hostname for filename
        
        Returns:
            Path to the saved JSON file
        """
        os.makedirs(self.results_dir, exist_ok=True)
        
        output_data = {
            "target": target,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "results": results
        }
        
        output_path = os.path.join(self.results_dir, f"{folder_name}.json")
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        return output_path
    
    def save_summary(
        self,
        all_results: List[Dict[str, Any]],
        scan_info: Dict[str, Any]
    ) -> str:
        """
        Save master summary of all scanned targets.
        
        Args:
            all_results: List of all scan results
            scan_info: General scan information
        
        Returns:
            Path to the saved summary file
        """
        os.makedirs(self.output_dir, exist_ok=True)
        
        summary = {
            "scan_info": {
                "start_time": scan_info.get("start_time"),
                "end_time": scan_info.get("end_time"),
                "duration_seconds": scan_info.get("duration"),
                "total_targets": len(all_results),
                "successful_scans": sum(1 for r in all_results if r.get("success")),
                "failed_scans": sum(1 for r in all_results if not r.get("success"))
            },
            "targets": []
        }
        
        for result in all_results:
            target_summary = {
                "target": result.get("target"),
                "success": result.get("success"),
                "result_file": result.get("output_folder"),
                "modules_run": list(result.get("results", {}).keys()),
                "errors": [
                    {
                        "module": mod,
                        "error": data.get("error")
                    }
                    for mod, data in result.get("results", {}).items()
                    if not data.get("success") and data.get("error")
                ]
            }
            
            if "headers" in result.get("results", {}):
                headers_data = result["results"]["headers"].get("data", {})
                security = headers_data.get("security_headers", {})
                target_summary["security_score"] = security.get("score")
                target_summary["security_grade"] = security.get("grade")
            
            if "tech_detect" in result.get("results", {}):
                tech_data = result["results"]["tech_detect"].get("data", {})
                summary_data = tech_data.get("summary", {})
                target_summary["technologies_count"] = summary_data.get("total_detected", 0)
            
            summary["targets"].append(target_summary)
        
        output_path = os.path.join(self.output_dir, "scan_summary.json")
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        return output_path
