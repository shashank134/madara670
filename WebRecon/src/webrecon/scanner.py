"""Main Scanner Orchestrator for WebRecon."""

import asyncio
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import aiohttp
import os

from .config import Config
from .utils.logger import get_logger, setup_logging
from .utils.url_utils import normalize_url, parse_targets, deduplicate_targets, extract_hostname
from .modules import (
    HeadersModule,
    DNSModule,
    SSLModule,
    WhoisModule,
    TechDetectModule,
    ScreenshotModule,
    ExtraIntelModule
)
from .output import JSONOutputHandler, HTMLOutputHandler


class WebReconScanner:
    """
    Main scanner orchestrator for WebRecon.
    
    Coordinates all reconnaissance modules and manages
    concurrent scanning with rate limiting.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: WebRecon configuration object (uses defaults if None)
        """
        self.config = config or Config()
        self.logger = get_logger("scanner")
        
        self.modules = {
            "headers": HeadersModule(self.config),
            "dns": DNSModule(self.config),
            "ssl": SSLModule(self.config),
            "whois": WhoisModule(self.config),
            "tech_detect": TechDetectModule(self.config),
            "screenshot": ScreenshotModule(self.config),
            "extra_intel": ExtraIntelModule(self.config),
        }
        
        self.json_handler = JSONOutputHandler(self.config.output_dir)
        self.html_handler = HTMLOutputHandler(self.config.output_dir)
        
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._rate_limit_lock = asyncio.Lock()
        self._last_request_time = 0.0
    
    async def scan(
        self,
        targets: List[str],
        modules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of URLs/domains to scan
            modules: Specific modules to run (runs all enabled if None)
        
        Returns:
            Dictionary containing all scan results
        """
        start_time = datetime.utcnow()
        start_ts = time.time()
        
        self.logger.info(f"Starting scan of {len(targets)} targets")
        
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        self._semaphore = asyncio.Semaphore(self.config.concurrency)
        
        tasks = [
            self._scan_target(target, modules)
            for target in targets
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_results = []
        for target, result in zip(targets, results):
            if isinstance(result, Exception):
                all_results.append({
                    "target": target,
                    "success": False,
                    "error": str(result),
                    "results": {}
                })
            else:
                all_results.append(result)
        
        end_time = datetime.utcnow()
        duration = round(time.time() - start_ts, 2)
        
        scan_info = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration": duration,
            "total_targets": len(targets),
            "config": self.config.to_dict()
        }
        
        summary_path = self.json_handler.save_summary(all_results, scan_info)
        self.logger.info(f"Summary saved to: {summary_path}")
        
        if self.config.generate_html:
            html_path = self.html_handler.generate_report(all_results, scan_info)
            self.logger.info(f"HTML report saved to: {html_path}")
        
        self.logger.info(f"Scan completed in {duration}s")
        
        return {
            "scan_info": scan_info,
            "results": all_results,
            "summary_path": summary_path
        }
    
    async def _scan_target(
        self,
        target: str,
        modules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Scan a single target with all enabled modules."""
        async with self._semaphore:
            await self._rate_limit()
            
            hostname = extract_hostname(target)
            safe_hostname = hostname.replace(".", "_").replace(":", "_")
            
            self.logger.info(f"Scanning target: {target}")
            
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            async with aiohttp.ClientSession(connector=connector) as session:
                module_results = {}
                
                modules_to_run = self._get_modules_to_run(modules)
                
                tasks = {}
                for module_name in modules_to_run:
                    module = self.modules.get(module_name)
                    if module:
                        if module_name == "screenshot":
                            tasks[module_name] = module.scan(
                                target,
                                session,
                                output_dir=os.path.join(self.config.output_dir, safe_hostname)
                            )
                        else:
                            tasks[module_name] = module.scan(target, session)
                
                if tasks:
                    results = await asyncio.gather(
                        *tasks.values(),
                        return_exceptions=True
                    )
                    
                    for module_name, result in zip(tasks.keys(), results):
                        if isinstance(result, Exception):
                            module_results[module_name] = {
                                "module": module_name,
                                "success": False,
                                "error": str(result),
                                "data": {}
                            }
                        else:
                            module_results[module_name] = result
            
            result = {
                "target": target,
                "hostname": hostname,
                "success": True,
                "output_folder": safe_hostname,
                "results": module_results
            }
            
            self.json_handler.save_target_result(target, module_results, safe_hostname)
            
            self.logger.info(f"Completed scan for: {target}")
            
            return result
    
    def _get_modules_to_run(self, requested: Optional[List[str]] = None) -> List[str]:
        """Get list of modules to run based on config and request."""
        all_modules = []
        
        if self.config.enable_headers:
            all_modules.append("headers")
        if self.config.enable_dns:
            all_modules.append("dns")
        if self.config.enable_ssl:
            all_modules.append("ssl")
        if self.config.enable_whois:
            all_modules.append("whois")
        if self.config.enable_tech_detect:
            all_modules.append("tech_detect")
        if self.config.enable_screenshot:
            all_modules.append("screenshot")
        if self.config.enable_extra_intel:
            all_modules.append("extra_intel")
        
        if requested:
            return [m for m in requested if m in all_modules]
        
        return all_modules
    
    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        async with self._rate_limit_lock:
            elapsed = time.time() - self._last_request_time
            wait_time = self.config.rate_limit - elapsed
            
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            
            self._last_request_time = time.time()
    
    def scan_sync(
        self,
        targets: List[str],
        modules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper for the scan method.
        
        Args:
            targets: List of URLs/domains to scan
            modules: Specific modules to run
        
        Returns:
            Dictionary containing all scan results
        """
        return asyncio.run(self.scan(targets, modules))
