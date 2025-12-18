"""HTTP Headers and Security Analysis Module."""

from typing import Dict, Any, List, Optional
import aiohttp
from urllib.parse import urlparse

from .base import BaseModule


class HeadersModule(BaseModule):
    """
    Module for analyzing HTTP response headers and security configurations.
    
    Detects:
    - All response headers
    - Missing/misconfigured security headers
    - CDN/WAF indicators
    - Server information
    """
    
    name = "headers"
    description = "HTTP headers and security header analysis"
    is_active = False
    
    SECURITY_HEADERS = {
        "content-security-policy": {
            "name": "Content-Security-Policy",
            "description": "Helps prevent XSS and data injection attacks",
            "severity": "high"
        },
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "description": "Forces HTTPS connections",
            "severity": "high"
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "description": "Prevents clickjacking attacks",
            "severity": "medium"
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "description": "Prevents MIME type sniffing",
            "severity": "medium"
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "description": "Controls referrer information leakage",
            "severity": "low"
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "description": "Controls browser features and APIs",
            "severity": "low"
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "description": "Legacy XSS filter (deprecated but still checked)",
            "severity": "low"
        }
    }
    
    CDN_WAF_INDICATORS = {
        "cf-ray": "Cloudflare",
        "cf-cache-status": "Cloudflare",
        "x-amz-cf-id": "Amazon CloudFront",
        "x-amz-cf-pop": "Amazon CloudFront",
        "x-cache": "CDN (Generic)",
        "x-served-by": "Fastly/Varnish",
        "x-akamai-transformed": "Akamai",
        "x-sucuri-id": "Sucuri WAF",
        "x-sucuri-cache": "Sucuri WAF",
        "server: cloudflare": "Cloudflare",
        "x-cdn": "CDN (Generic)",
        "x-azure-ref": "Azure CDN",
        "x-ms-ref": "Azure CDN",
        "x-vercel-id": "Vercel",
        "x-vercel-cache": "Vercel",
        "x-netlify-request-id": "Netlify",
    }
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Scan target for HTTP headers and security configuration."""
        self.logger.info(f"Scanning headers for {url}")
        
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            should_close = True
        else:
            should_close = False
        
        try:
            response = await self._make_request(session, url)
            
            if response is None:
                return self._create_result(
                    success=False,
                    error="Failed to fetch URL"
                )
            
            headers_dict = dict(response.headers)
            
            security_analysis = self._analyze_security_headers(headers_dict)
            cdn_waf = self._detect_cdn_waf(headers_dict)
            server_info = self._extract_server_info(headers_dict)
            
            return self._create_result(
                success=True,
                data={
                    "status_code": response.status,
                    "headers": headers_dict,
                    "security_headers": security_analysis,
                    "cdn_waf": cdn_waf,
                    "server": server_info,
                    "cookies": self._parse_cookies(response.headers)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error scanning headers: {e}")
            return self._create_result(success=False, error=str(e))
        finally:
            if should_close:
                await session.close()
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers presence and configuration."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        present = []
        missing = []
        
        for header_key, header_info in self.SECURITY_HEADERS.items():
            if header_key in headers_lower:
                present.append({
                    "header": header_info["name"],
                    "value": headers_lower[header_key],
                    "severity": header_info["severity"]
                })
            else:
                missing.append({
                    "header": header_info["name"],
                    "description": header_info["description"],
                    "severity": header_info["severity"]
                })
        
        score = len(present) / len(self.SECURITY_HEADERS) * 100
        
        return {
            "present": present,
            "missing": missing,
            "score": round(score, 1),
            "grade": self._calculate_grade(score)
        }
    
    def _calculate_grade(self, score: float) -> str:
        """Calculate security grade based on score."""
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"
    
    def _detect_cdn_waf(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect CDN and WAF from headers."""
        detected = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for indicator, service in self.CDN_WAF_INDICATORS.items():
            if ":" in indicator:
                header, value = indicator.split(": ", 1)
                if header in headers_lower and value.lower() in headers_lower[header].lower():
                    if service not in detected:
                        detected.append(service)
            else:
                if indicator in headers_lower:
                    if service not in detected:
                        detected.append(service)
        
        return {
            "detected": detected,
            "has_cdn": len(detected) > 0
        }
    
    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract server information from headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        return {
            "server": headers_lower.get("server", "Unknown"),
            "powered_by": headers_lower.get("x-powered-by"),
            "aspnet_version": headers_lower.get("x-aspnet-version"),
            "php_version": self._extract_php_version(headers_lower)
        }
    
    def _extract_php_version(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract PHP version if disclosed."""
        powered_by = headers.get("x-powered-by", "")
        if "PHP" in powered_by:
            return powered_by
        return None
    
    def _parse_cookies(self, headers: Any) -> List[Dict[str, Any]]:
        """Parse Set-Cookie headers."""
        cookies = []
        
        if hasattr(headers, 'getall'):
            cookie_headers = headers.getall('Set-Cookie', [])
        else:
            cookie_headers = []
            if 'Set-Cookie' in headers:
                cookie_headers = [headers['Set-Cookie']]
        
        for cookie in cookie_headers:
            parts = cookie.split(';')
            if parts:
                name_value = parts[0].strip()
                if '=' in name_value:
                    name, value = name_value.split('=', 1)
                    cookie_info = {
                        "name": name.strip(),
                        "secure": "secure" in cookie.lower(),
                        "httponly": "httponly" in cookie.lower(),
                        "samesite": self._extract_samesite(cookie)
                    }
                    cookies.append(cookie_info)
        
        return cookies
    
    def _extract_samesite(self, cookie: str) -> Optional[str]:
        """Extract SameSite attribute from cookie."""
        cookie_lower = cookie.lower()
        if "samesite=strict" in cookie_lower:
            return "Strict"
        elif "samesite=lax" in cookie_lower:
            return "Lax"
        elif "samesite=none" in cookie_lower:
            return "None"
        return None
