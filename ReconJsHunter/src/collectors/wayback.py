"""
Wayback Machine (Web Archive) collector.
Uses the CDX API to retrieve historical URLs.
"""

import re
from typing import List
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class WaybackCollector(BaseCollector):
    
    name = "wayback"
    
    CDX_API = "https://web.archive.org/cdx/search/cdx"
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            logger.info(f"[{self.name}] Collector disabled, skipping")
            return data
        
        logger.info(f"[{self.name}] Collecting URLs for {domain}")
        
        try:
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'original,mimetype,statuscode,timestamp',
                'collapse': 'urlkey',
                'filter': 'statuscode:200'
            }
            
            query_string = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
            url = f"{self.CDX_API}?{query_string}"
            
            response = await self.rate_limiter.request(
                self.session, url, timeout=60
            )
            
            if not response or response.status != 200:
                data.errors.append(f"Failed to fetch from Wayback CDX API")
                return data
            
            try:
                results = await response.json()
            except Exception:
                text = await response.text()
                lines = text.strip().split('\n')
                results = []
                for line in lines:
                    if line:
                        parts = line.split()
                        if len(parts) >= 4:
                            results.append(parts)
            
            if not results:
                logger.info(f"[{self.name}] No results found for {domain}")
                return data
            
            if isinstance(results[0], list) and results[0] == ['original', 'mimetype', 'statuscode', 'timestamp']:
                results = results[1:]
            
            for entry in results:
                try:
                    if isinstance(entry, list) and len(entry) >= 2:
                        original_url = entry[0]
                        mimetype = entry[1] if len(entry) > 1 else ''
                    elif isinstance(entry, dict):
                        original_url = entry.get('original', '')
                        mimetype = entry.get('mimetype', '')
                    else:
                        continue
                    
                    normalized = normalizer.normalize_url(original_url)
                    if not normalized:
                        continue
                    
                    data.urls.append(normalized)
                    
                    if 'javascript' in mimetype.lower() or normalized.endswith('.js'):
                        data.js_files.append(normalized)
                    
                    subdomain, root, full = normalizer.extract_domain_parts(normalized)
                    if subdomain and root.lower() == domain.lower():
                        data.subdomains.add(full)
                    
                    if normalizer.is_interesting_endpoint(normalized):
                        data.endpoints.append(normalized)
                
                except Exception as e:
                    logger.debug(f"[{self.name}] Error processing entry: {e}")
                    continue
            
            data.deduplicate()
            
            logger.info(f"[{self.name}] Found {len(data.urls)} URLs, "
                       f"{len(data.subdomains)} subdomains, "
                       f"{len(data.js_files)} JS files")
            
        except Exception as e:
            error_msg = f"Error collecting from Wayback: {e}"
            logger.error(f"[{self.name}] {error_msg}")
            data.errors.append(error_msg)
        
        return data
