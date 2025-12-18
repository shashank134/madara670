"""
Rate limiting and request management.
Provides async-safe rate limiting with configurable delays.
"""

import asyncio
import time
from collections import deque
from typing import Optional
from dataclasses import dataclass
import aiohttp
from src.core.logger import logger


@dataclass
class RateLimitState:
    requests: deque
    lock: asyncio.Lock
    

class RateLimiter:
    
    def __init__(self, requests_per_second: float = 2.0, 
                 max_concurrent: int = 5,
                 retry_attempts: int = 3,
                 retry_delay: float = 2.0):
        self.requests_per_second = requests_per_second
        self.max_concurrent = max_concurrent
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        
        self.request_times: deque = deque(maxlen=100)
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        self.total_requests = 0
        self.blocked_requests = 0
        self.failed_requests = 0
    
    async def acquire(self):
        async with self.lock:
            now = time.time()
            
            while self.request_times and now - self.request_times[0] > 1.0:
                self.request_times.popleft()
            
            if len(self.request_times) >= self.requests_per_second:
                oldest = self.request_times[0]
                sleep_time = 1.0 - (now - oldest)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            
            self.request_times.append(time.time())
            self.total_requests += 1
    
    async def request(self, session: aiohttp.ClientSession, url: str,
                      headers: dict = None, timeout: int = 30,
                      method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        async with self.semaphore:
            for attempt in range(self.retry_attempts):
                try:
                    await self.acquire()
                    
                    async with session.request(
                        method, url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        **kwargs
                    ) as response:
                        
                        if response.status == 429:
                            self.blocked_requests += 1
                            retry_after = int(response.headers.get('Retry-After', self.retry_delay * (attempt + 1)))
                            logger.warning(f"Rate limited on {url}, waiting {retry_after}s")
                            await asyncio.sleep(retry_after)
                            continue
                        
                        if response.status == 403:
                            self.blocked_requests += 1
                            logger.warning(f"Blocked (403) on {url}")
                            return None
                        
                        if response.status >= 500:
                            logger.warning(f"Server error ({response.status}) on {url}, retrying...")
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                            continue
                        
                        content = await response.read()
                        
                        class ResponseWrapper:
                            def __init__(self, status, headers, content, url):
                                self.status = status
                                self.headers = headers
                                self.content = content
                                self.url = url
                            
                            async def text(self):
                                return self.content.decode('utf-8', errors='replace')
                            
                            async def json(self):
                                import json
                                return json.loads(self.content)
                        
                        return ResponseWrapper(response.status, response.headers, content, str(response.url))
                
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout on {url} (attempt {attempt + 1}/{self.retry_attempts})")
                    await asyncio.sleep(self.retry_delay)
                
                except aiohttp.ClientError as e:
                    logger.warning(f"Client error on {url}: {e}")
                    await asyncio.sleep(self.retry_delay)
                
                except Exception as e:
                    logger.error(f"Unexpected error on {url}: {e}")
                    self.failed_requests += 1
                    return None
            
            self.failed_requests += 1
            logger.error(f"Failed to fetch {url} after {self.retry_attempts} attempts")
            return None
    
    def get_stats(self) -> dict:
        return {
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
            'failed_requests': self.failed_requests,
            'success_rate': (self.total_requests - self.failed_requests) / max(1, self.total_requests) * 100
        }
