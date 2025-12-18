"""
AlienVault OTX collector.
Uses the OTX API to retrieve threat intelligence and URL data.
"""

from typing import List
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class AlienVaultCollector(BaseCollector):
    
    name = "alienvault"
    
    OTX_API = "https://otx.alienvault.com/api/v1"
    
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
                headers['X-OTX-API-KEY'] = self.config.api_key
            
            endpoints_to_check = [
                f"/indicators/domain/{domain}/url_list",
                f"/indicators/domain/{domain}/passive_dns",
                f"/indicators/hostname/{domain}/url_list",
            ]
            
            for endpoint in endpoints_to_check:
                await self._fetch_endpoint(endpoint, data, normalizer, domain, headers)
            
            data.deduplicate()
            
            logger.info(f"[{self.name}] Found {len(data.urls)} URLs, "
                       f"{len(data.subdomains)} subdomains, "
                       f"{len(data.js_files)} JS files")
            
        except Exception as e:
            error_msg = f"Error collecting from AlienVault: {e}"
            logger.error(f"[{self.name}] {error_msg}")
            data.errors.append(error_msg)
        
        return data
    
    async def _fetch_endpoint(self, endpoint: str, data: CollectedData,
                               normalizer: URLNormalizer, domain: str,
                               headers: dict):
        try:
            url = f"{self.OTX_API}{endpoint}"
            
            response = await self.rate_limiter.request(
                self.session, url, headers=headers, timeout=60
            )
            
            if not response or response.status != 200:
                return
            
            result = await response.json()
            
            if 'url_list' in result:
                for entry in result['url_list']:
                    url_value = entry.get('url', '')
                    if url_value:
                        normalized = normalizer.normalize_url(url_value)
                        if normalized:
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
                            
                            if normalizer.is_interesting_endpoint(normalized):
                                data.endpoints.append(normalized)
            
            if 'passive_dns' in result:
                for entry in result['passive_dns']:
                    hostname = entry.get('hostname', '')
                    if hostname and domain in hostname:
                        subdomain, root, full = normalizer.extract_domain_parts(hostname)
                        if subdomain:
                            data.subdomains.add(full)
            
            if 'dns_records' in result:
                for record in result.get('dns_records', []):
                    value = record.get('value', '')
                    if value and domain in value:
                        subdomain, root, full = normalizer.extract_domain_parts(value)
                        if subdomain:
                            data.subdomains.add(full)
        
        except Exception as e:
            logger.debug(f"[{self.name}] Error fetching endpoint {endpoint}: {e}")
