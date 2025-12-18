"""
Main reconnaissance engine.
Orchestrates all collectors and analyzers.
"""

import asyncio
from typing import Dict, List, Set
import aiohttp

from src.core.config import Config, get_default_config
from src.core.normalizer import URLNormalizer, normalize_input
from src.core.logger import logger, set_verbose
from src.collectors.base import CollectedData
from src.collectors.wayback import WaybackCollector
from src.collectors.urlscan import URLScanCollector
from src.collectors.alienvault import AlienVaultCollector
from src.analyzers.js_analyzer import JSAnalyzer, JSAnalysisResult
from src.output.json_exporter import JSONExporter
from src.output.html_report import HTMLReportGenerator


class ReconEngine:
    
    def __init__(self, config: Config = None):
        self.config = config or get_default_config()
        self.normalizer = URLNormalizer()
        
        self.collectors = []
        self.collected_data: Dict[str, CollectedData] = {}
        self.js_results: List[JSAnalysisResult] = []
        self.categorized_urls: Dict[str, List[str]] = {}
    
    async def run(self, target: str, analyze_js: bool = True) -> Dict:
        domain = self.normalizer.normalize_domain(target)
        
        logger.info(f"Starting reconnaissance for: {domain}")
        
        await self._collect_osint(domain)
        
        self._categorize_urls(domain)
        
        if analyze_js and self.config.js_analysis:
            await self._analyze_javascript()
        
        return self._get_results(domain)
    
    async def _collect_osint(self, domain: str):
        logger.info("Starting OSINT collection from all sources...")
        
        collector_classes = [
            (WaybackCollector, self.config.wayback),
            (URLScanCollector, self.config.urlscan),
            (AlienVaultCollector, self.config.alienvault),
        ]
        
        tasks = []
        collectors = []
        
        async with aiohttp.ClientSession() as session:
            for CollectorClass, config in collector_classes:
                if config.enabled:
                    collector = CollectorClass(config)
                    collector.session = session
                    collectors.append(collector)
                    tasks.append(collector.collect(domain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for collector, result in zip(collectors, results):
                if isinstance(result, Exception):
                    logger.error(f"Collector {collector.name} failed: {result}")
                    self.collected_data[collector.name] = CollectedData(
                        source=collector.name,
                        errors=[str(result)]
                    )
                else:
                    self.collected_data[collector.name] = result
        
        total_urls = sum(len(d.urls) for d in self.collected_data.values())
        total_subdomains = set()
        for d in self.collected_data.values():
            total_subdomains.update(d.subdomains)
        
        logger.info(f"OSINT collection complete: {total_urls} URLs, {len(total_subdomains)} subdomains")
    
    def _categorize_urls(self, domain: str):
        logger.info("Categorizing collected URLs...")
        
        all_urls = set()
        main_domain_urls = []
        subdomain_urls = {}
        js_files = set()
        endpoints = []
        external_urls = []
        
        for data in self.collected_data.values():
            for url in data.urls:
                normalized = self.normalizer.normalize_url(url)
                if not normalized:
                    continue
                
                all_urls.add(normalized)
                
                category = self.normalizer.categorize_url(normalized, domain)
                
                if category == 'javascript':
                    js_files.add(normalized)
                elif category == 'main_domain':
                    main_domain_urls.append(normalized)
                elif category == 'subdomain':
                    subdomain, _, full = self.normalizer.extract_domain_parts(normalized)
                    if full not in subdomain_urls:
                        subdomain_urls[full] = []
                    subdomain_urls[full].append(normalized)
                elif category == 'external':
                    external_urls.append(normalized)
                
                if self.normalizer.is_interesting_endpoint(normalized):
                    endpoints.append(normalized)
            
            js_files.update(data.js_files)
            endpoints.extend(data.endpoints)
        
        self.categorized_urls = {
            'all': list(all_urls),
            'main_domain': list(set(main_domain_urls)),
            'subdomain_urls': {k: list(set(v)) for k, v in subdomain_urls.items()},
            'javascript': list(js_files),
            'endpoints': list(set(endpoints)),
            'external': list(set(external_urls))
        }
        
        logger.info(f"Categorized: {len(main_domain_urls)} main domain, "
                   f"{len(subdomain_urls)} subdomains, {len(js_files)} JS files")
    
    async def _analyze_javascript(self):
        js_files = self.categorized_urls.get('javascript', [])
        
        if not js_files:
            logger.info("No JavaScript files to analyze")
            return
        
        logger.info(f"Analyzing {len(js_files)} JavaScript files...")
        
        analyzer = JSAnalyzer(max_size=self.config.max_js_size)
        
        async with aiohttp.ClientSession() as session:
            self.js_results = await analyzer.analyze_urls(js_files[:50], session)
        
        successful = sum(1 for r in self.js_results if r.success)
        total_secrets = sum(len(r.secrets) for r in self.js_results)
        
        logger.info(f"JavaScript analysis complete: {successful}/{len(js_files)} files, "
                   f"{total_secrets} potential secrets found")
    
    def _get_results(self, domain: str) -> Dict:
        return {
            'domain': domain,
            'collected_data': self.collected_data,
            'js_results': self.js_results,
            'categorized_urls': self.categorized_urls
        }
    
    def export_json(self, domain: str, output_dir: str = None) -> str:
        exporter = JSONExporter(output_dir or self.config.output_dir)
        return exporter.export_full_report(
            domain,
            self.collected_data,
            self.js_results,
            self.categorized_urls
        )
    
    def export_html(self, domain: str, output_dir: str = None) -> str:
        generator = HTMLReportGenerator()
        return generator.generate(
            domain,
            self.collected_data,
            self.js_results,
            self.categorized_urls,
            output_dir or self.config.output_dir
        )


async def run_recon(target: str, config: Config = None, 
                    analyze_js: bool = True) -> ReconEngine:
    engine = ReconEngine(config)
    await engine.run(target, analyze_js)
    return engine
