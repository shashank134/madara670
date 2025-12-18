"""
URLScan.io collector.
Uses the URLScan API to retrieve scan results and discovered URLs.
"""

from typing import List, Dict
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class URLScanCollector(BaseCollector):
    
    name = "urlscan"
    
    SEARCH_API = "https://urlscan.io/api/v1/search/"
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            logger.info(f"[{self.name}] Collector disabled, skipping")
            return data
        
        logger.info(f"[{self.name}] Collecting URLs for {domain}")
        
        try:
            headers = {}
            if self.config.api_key:
                headers['API-Key'] = self.config.api_key
            
            query = f"domain:{domain}"
            url = f"{self.SEARCH_API}?q={quote(query)}&size=1000"
            
            response = await self.rate_limiter.request(
                self.session, url, headers=headers, timeout=60
            )
            
            if not response:
                data.errors.append("Failed to fetch from URLScan API")
                return data
            
            if response.status == 429:
                data.errors.append("Rate limited by URLScan API")
                return data
            
            if response.status != 200:
                data.errors.append(f"URLScan API returned status {response.status}")
                return data
            
            results = await response.json()
            
            if not results or 'results' not in results:
                logger.info(f"[{self.name}] No results found for {domain}")
                return data
            
            for result in results.get('results', []):
                try:
                    page = result.get('page', {})
                    task = result.get('task', {})
                    
                    page_url = page.get('url', '')
                    if page_url:
                        normalized = normalizer.normalize_url(page_url)
                        if normalized:
                            data.urls.append(normalized)
                            
                            subdomain, root, full = normalizer.extract_domain_parts(normalized)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                    
                    page_domain = page.get('domain', '')
                    if page_domain and domain in page_domain:
                        subdomain, root, full = normalizer.extract_domain_parts(page_domain)
                        if subdomain:
                            data.subdomains.add(full)
                    
                    result_id = result.get('_id')
                    if result_id:
                        await self._fetch_scan_details(result_id, data, normalizer, domain)
                
                except Exception as e:
                    logger.debug(f"[{self.name}] Error processing result: {e}")
                    continue
            
            data.deduplicate()
            
            logger.info(f"[{self.name}] Found {len(data.urls)} URLs, "
                       f"{len(data.subdomains)} subdomains, "
                       f"{len(data.js_files)} JS files")
            
        except Exception as e:
            error_msg = f"Error collecting from URLScan: {e}"
            logger.error(f"[{self.name}] {error_msg}")
            data.errors.append(error_msg)
        
        return data
    
    async def _fetch_scan_details(self, scan_id: str, data: CollectedData, 
                                   normalizer: URLNormalizer, domain: str):
        try:
            url = f"https://urlscan.io/api/v1/result/{scan_id}/"
            
            response = await self.rate_limiter.request(
                self.session, url, timeout=30
            )
            
            if not response or response.status != 200:
                return
            
            result = await response.json()
            
            for request in result.get('data', {}).get('requests', []):
                req_url = request.get('request', {}).get('url', '')
                if req_url:
                    normalized = normalizer.normalize_url(req_url)
                    if normalized:
                        data.urls.append(normalized)
                        
                        if normalized.endswith('.js'):
                            data.js_files.append(normalized)
                        
                        if normalizer.is_interesting_endpoint(normalized):
                            data.endpoints.append(normalized)
            
            for link in result.get('data', {}).get('links', []):
                href = link.get('href', '')
                if href:
                    normalized = normalizer.normalize_url(href)
                    if normalized:
                        data.urls.append(normalized)
        
        except Exception as e:
            logger.debug(f"[{self.name}] Error fetching scan details: {e}")
