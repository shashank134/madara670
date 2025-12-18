"""Extra Intelligence Gathering Module."""

import asyncio
import hashlib
import time
from typing import Dict, Any, List, Optional, Tuple
import aiohttp
import mmh3
from urllib.parse import urljoin, urlparse

from .base import BaseModule


class ExtraIntelModule(BaseModule):
    """
    Module for gathering additional intelligence.
    
    Collects:
    - robots.txt content
    - sitemap.xml discovery
    - Favicon hash (for Shodan/Censys searches)
    - HTTP methods allowed
    - Redirect chain analysis
    - Response time metrics
    - Login/admin panel detection
    """
    
    name = "extra_intel"
    description = "Additional intelligence gathering"
    is_active = False
    
    ADMIN_PATHS = [
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/login", "/login/", "/signin", "/signin/",
        "/wp-admin", "/wp-login.php",
        "/admin/login", "/user/login", "/auth/login",
        "/backend", "/backend/", "/manage", "/manage/",
        "/dashboard", "/dashboard/", "/panel", "/panel/",
        "/cpanel", "/phpmyadmin", "/adminer",
    ]
    
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Gather extra intelligence from the target."""
        self.logger.info(f"Gathering extra intel for {url}")
        
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            should_close = True
        else:
            should_close = False
        
        try:
            base_url = self._get_base_url(url)
            
            results = await asyncio.gather(
                self._fetch_robots_txt(session, base_url),
                self._fetch_sitemap(session, base_url),
                self._get_favicon_hash(session, base_url),
                self._check_http_methods(session, url),
                self._analyze_redirects(session, url),
                self._measure_response_time(session, url),
                self._detect_admin_panels(session, base_url),
                return_exceptions=True
            )
            
            robots_txt = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
            sitemap = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}
            favicon = results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])}
            methods = results[3] if not isinstance(results[3], Exception) else {"error": str(results[3])}
            redirects = results[4] if not isinstance(results[4], Exception) else {"error": str(results[4])}
            timing = results[5] if not isinstance(results[5], Exception) else {"error": str(results[5])}
            admin_panels = results[6] if not isinstance(results[6], Exception) else {"error": str(results[6])}
            
            return self._create_result(
                success=True,
                data={
                    "robots_txt": robots_txt,
                    "sitemap": sitemap,
                    "favicon": favicon,
                    "http_methods": methods,
                    "redirects": redirects,
                    "response_time": timing,
                    "admin_panels": admin_panels
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error in extra intel gathering: {e}")
            return self._create_result(success=False, error=str(e))
        finally:
            if should_close:
                await session.close()
    
    def _get_base_url(self, url: str) -> str:
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _fetch_robots_txt(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> Dict[str, Any]:
        """Fetch and parse robots.txt."""
        robots_url = urljoin(base_url, "/robots.txt")
        
        try:
            response = await self._make_request(session, robots_url)
            
            if response is None or response.status != 200:
                return {"found": False, "url": robots_url}
            
            content = ""
            try:
                content = await response.text() if hasattr(response, 'text') else ""
            except:
                try:
                    content = response._body.decode('utf-8', errors='ignore') if hasattr(response, '_body') else ""
                except:
                    pass
            
            disallowed = []
            allowed = []
            sitemaps = []
            
            for line in content.split("\n"):
                line = line.strip().lower()
                if line.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif line.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        allowed.append(path)
                elif line.startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    if sitemap_url.startswith("http"):
                        sitemaps.append(sitemap_url)
                    else:
                        sitemaps.append(line.split("Sitemap:", 1)[1].strip() if "Sitemap:" in content else sitemap_url)
            
            return {
                "found": True,
                "url": robots_url,
                "disallowed_paths": disallowed[:50],
                "allowed_paths": allowed[:50],
                "sitemaps": sitemaps,
                "raw_content": content[:2000]
            }
            
        except Exception as e:
            return {"found": False, "url": robots_url, "error": str(e)}
    
    async def _fetch_sitemap(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> Dict[str, Any]:
        """Check for sitemap.xml."""
        sitemap_urls = [
            urljoin(base_url, "/sitemap.xml"),
            urljoin(base_url, "/sitemap_index.xml"),
            urljoin(base_url, "/sitemap/sitemap.xml"),
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                response = await self._make_request(session, sitemap_url)
                
                if response and response.status == 200:
                    content_type = response.headers.get("content-type", "")
                    if "xml" in content_type.lower() or "text" in content_type.lower():
                        return {
                            "found": True,
                            "url": sitemap_url,
                            "content_type": content_type
                        }
            except:
                continue
        
        return {"found": False, "checked_urls": sitemap_urls}
    
    async def _get_favicon_hash(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> Dict[str, Any]:
        """Get favicon and compute hashes for Shodan/Censys searches."""
        favicon_urls = [
            urljoin(base_url, "/favicon.ico"),
            urljoin(base_url, "/favicon.png"),
        ]
        
        for favicon_url in favicon_urls:
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with session.get(
                    favicon_url,
                    timeout=timeout,
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    if response.status == 200:
                        content = await response.read()
                        
                        if len(content) < 100:
                            continue
                        
                        import base64
                        favicon_b64 = base64.b64encode(content).decode()
                        mmh3_hash = mmh3.hash(favicon_b64)
                        
                        md5_hash = hashlib.md5(content).hexdigest()
                        sha256_hash = hashlib.sha256(content).hexdigest()
                        
                        return {
                            "found": True,
                            "url": favicon_url,
                            "size_bytes": len(content),
                            "hashes": {
                                "mmh3": mmh3_hash,
                                "md5": md5_hash,
                                "sha256": sha256_hash
                            },
                            "shodan_query": f"http.favicon.hash:{mmh3_hash}"
                        }
            except:
                continue
        
        return {"found": False, "checked_urls": favicon_urls}
    
    async def _check_http_methods(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Dict[str, Any]:
        """Check which HTTP methods are allowed."""
        allowed_methods = []
        
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.options(
                url,
                timeout=timeout,
                ssl=False
            ) as response:
                allow_header = response.headers.get("Allow", "")
                if allow_header:
                    allowed_methods = [m.strip().upper() for m in allow_header.split(",")]
        except:
            pass
        
        if not allowed_methods:
            for method in ["GET", "HEAD", "POST", "OPTIONS"]:
                try:
                    timeout = aiohttp.ClientTimeout(total=5)
                    async with session.request(
                        method,
                        url,
                        timeout=timeout,
                        ssl=False
                    ) as response:
                        if response.status < 500:
                            allowed_methods.append(method)
                except:
                    pass
        
        dangerous_methods = [m for m in allowed_methods if m in ["PUT", "DELETE", "TRACE"]]
        
        return {
            "allowed": allowed_methods,
            "dangerous_enabled": dangerous_methods,
            "has_security_concern": len(dangerous_methods) > 0
        }
    
    async def _analyze_redirects(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Dict[str, Any]:
        """Analyze redirect chain for the URL."""
        chain = []
        current_url = url
        max_redirects = 10
        
        for i in range(max_redirects):
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with session.get(
                    current_url,
                    timeout=timeout,
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    chain.append({
                        "url": current_url,
                        "status_code": response.status,
                        "location": response.headers.get("Location")
                    })
                    
                    if response.status in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location")
                        if location:
                            if not location.startswith("http"):
                                location = urljoin(current_url, location)
                            current_url = location
                        else:
                            break
                    else:
                        break
            except Exception as e:
                chain.append({
                    "url": current_url,
                    "error": str(e)
                })
                break
        
        return {
            "chain": chain,
            "total_redirects": len(chain) - 1,
            "final_url": chain[-1]["url"] if chain else url,
            "has_https_upgrade": any(
                "http://" in c.get("url", "") and
                "https://" in c.get("location", "")
                for c in chain
            )
        }
    
    async def _measure_response_time(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Dict[str, Any]:
        """Measure response time metrics."""
        times = []
        
        for _ in range(3):
            try:
                start = time.time()
                timeout = aiohttp.ClientTimeout(total=10)
                async with session.get(
                    url,
                    timeout=timeout,
                    ssl=False
                ) as response:
                    await response.read()
                    elapsed = (time.time() - start) * 1000
                    times.append(elapsed)
            except:
                pass
            
            await asyncio.sleep(0.5)
        
        if not times:
            return {"error": "Could not measure response time"}
        
        return {
            "samples": len(times),
            "min_ms": round(min(times), 2),
            "max_ms": round(max(times), 2),
            "avg_ms": round(sum(times) / len(times), 2),
            "performance": self._rate_performance(sum(times) / len(times))
        }
    
    def _rate_performance(self, avg_ms: float) -> str:
        """Rate performance based on average response time."""
        if avg_ms < 200:
            return "Excellent"
        elif avg_ms < 500:
            return "Good"
        elif avg_ms < 1000:
            return "Fair"
        elif avg_ms < 3000:
            return "Slow"
        else:
            return "Very Slow"
    
    async def _detect_admin_panels(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> Dict[str, Any]:
        """Detect common admin/login panels."""
        found_panels = []
        
        async def check_path(path: str) -> Optional[Dict]:
            url = urljoin(base_url, path)
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                async with session.get(
                    url,
                    timeout=timeout,
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    if response.status == 200:
                        content_type = response.headers.get("content-type", "")
                        if "text/html" in content_type.lower():
                            return {
                                "path": path,
                                "url": url,
                                "status": response.status
                            }
            except:
                pass
            return None
        
        tasks = [check_path(path) for path in self.ADMIN_PATHS[:10]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                found_panels.append(result)
        
        return {
            "panels_found": found_panels,
            "count": len(found_panels),
            "paths_checked": len(self.ADMIN_PATHS[:10])
        }
