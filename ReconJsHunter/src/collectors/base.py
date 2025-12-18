"""
Base collector class for OSINT sources.
All collectors inherit from this base class.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
import aiohttp

from src.core.rate_limiter import RateLimiter
from src.core.config import CollectorConfig


@dataclass
class CollectedData:
    source: str
    urls: List[str] = field(default_factory=list)
    subdomains: Set[str] = field(default_factory=set)
    js_files: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def merge(self, other: 'CollectedData'):
        self.urls.extend(other.urls)
        self.subdomains.update(other.subdomains)
        self.js_files.extend(other.js_files)
        self.endpoints.extend(other.endpoints)
        self.metadata.update(other.metadata)
        self.errors.extend(other.errors)
    
    def deduplicate(self):
        self.urls = list(set(self.urls))
        self.js_files = list(set(self.js_files))
        self.endpoints = list(set(self.endpoints))
    
    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'urls': self.urls,
            'subdomains': list(self.subdomains),
            'js_files': self.js_files,
            'endpoints': self.endpoints,
            'metadata': self.metadata,
            'errors': self.errors,
            'stats': {
                'total_urls': len(self.urls),
                'total_subdomains': len(self.subdomains),
                'total_js_files': len(self.js_files),
                'total_endpoints': len(self.endpoints)
            }
        }


class BaseCollector(ABC):
    
    name: str = "base"
    
    def __init__(self, config: CollectorConfig):
        self.config = config
        self.rate_limiter = RateLimiter(
            requests_per_second=config.rate_limit.requests_per_second,
            max_concurrent=config.rate_limit.max_concurrent,
            retry_attempts=config.rate_limit.retry_attempts,
            retry_delay=config.rate_limit.retry_delay
        )
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        headers = {
            'User-Agent': 'ReconHunter/1.0 (Security Research Tool)',
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        self.session = aiohttp.ClientSession(headers=headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def collect(self, domain: str) -> CollectedData:
        pass
    
    def is_enabled(self) -> bool:
        return self.config.enabled
    
    def get_stats(self) -> Dict:
        return self.rate_limiter.get_stats()
