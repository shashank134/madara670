"""
JavaScript static analyzer.
Performs safe static analysis on JavaScript files to extract URLs, secrets, and sensitive data.
"""

import re
import math
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin
import aiohttp

from src.core.rate_limiter import RateLimiter
from src.core.logger import logger


@dataclass
class Finding:
    type: str
    value: str
    context: str
    line_number: int
    confidence: str
    description: str
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'value': self.value,
            'context': self.context[:200] if self.context else '',
            'line_number': self.line_number,
            'confidence': self.confidence,
            'description': self.description
        }


@dataclass
class JSAnalysisResult:
    url: str
    size: int = 0
    success: bool = False
    error: Optional[str] = None
    
    urls: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    internal_refs: List[Finding] = field(default_factory=list)
    secrets: List[Finding] = field(default_factory=list)
    sensitive_data: List[Finding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'size': self.size,
            'success': self.success,
            'error': self.error,
            'urls': self.urls,
            'api_endpoints': self.api_endpoints,
            'internal_refs': [f.to_dict() for f in self.internal_refs],
            'secrets': [f.to_dict() for f in self.secrets],
            'sensitive_data': [f.to_dict() for f in self.sensitive_data],
            'stats': {
                'total_urls': len(self.urls),
                'total_endpoints': len(self.api_endpoints),
                'total_internal_refs': len(self.internal_refs),
                'total_secrets': len(self.secrets),
                'total_sensitive': len(self.sensitive_data)
            }
        }


class JSAnalyzer:
    
    SECRET_PATTERNS = [
        (r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'api_key', 'high'),
        (r'(?i)api[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'api_secret', 'high'),
        (r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'secret_key', 'high'),
        (r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'access_token', 'high'),
        (r'(?i)auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'auth_token', 'high'),
        (r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'bearer_token', 'high'),
        
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'high'),
        (r'(?i)aws[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret', 'high'),
        
        (r'AIza[0-9A-Za-z_-]{35}', 'google_api_key', 'high'),
        (r'(?i)gcp[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'gcp_key', 'medium'),
        
        (r'sk_live_[a-zA-Z0-9]{24,}', 'stripe_secret_key', 'high'),
        (r'pk_live_[a-zA-Z0-9]{24,}', 'stripe_publishable_key', 'medium'),
        (r'sk_test_[a-zA-Z0-9]{24,}', 'stripe_test_key', 'low'),
        
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'slack_token', 'high'),
        
        (r'ghp_[a-zA-Z0-9]{36}', 'github_pat', 'high'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'github_fine_grained', 'high'),
        
        (r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'password', 'medium'),
        (r'(?i)passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'password', 'medium'),
        
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'jwt_token', 'high'),
        
        (r'(?i)private[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'private_key', 'high'),
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', 'private_key_pem', 'high'),
        
        (r'(?i)twilio[_-]?(?:auth|account|sid)["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']', 'twilio_key', 'high'),
        (r'(?i)sendgrid[_-]?(?:api)?[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9._\-]{40,})["\']', 'sendgrid_key', 'high'),
        (r'(?i)mailgun[_-]?(?:api)?[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]{30,})["\']', 'mailgun_key', 'high'),
    ]
    
    INTERNAL_PATTERNS = [
        (r'\blocalhost\b', 'localhost', 'Localhost reference'),
        (r'\b127\.0\.0\.1\b', 'localhost_ip', 'Localhost IP'),
        (r'\b0\.0\.0\.0\b', 'bind_all', 'Bind all interfaces'),
        (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'internal_ip_10', 'Internal IP (10.x.x.x)'),
        (r'\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b', 'internal_ip_172', 'Internal IP (172.16-31.x.x)'),
        (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 'internal_ip_192', 'Internal IP (192.168.x.x)'),
        (r'(?i)\b(?:dev|staging|test|internal|local)\.', 'dev_domain', 'Development/staging domain'),
        (r'(?i)\.(?:local|internal|dev|test)\b', 'internal_tld', 'Internal TLD'),
    ]
    
    URL_PATTERNS = [
        r'https?://[^\s"\'<>\)\]\}]+',
        r'(?<=["\'])\/[a-zA-Z0-9_\-\/\.]+(?=["\'])',
        r'(?i)(?:api|endpoint|url|path)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    SENSITIVE_PATTERNS = [
        (r'(?i)(?:feature[_-]?flag|toggle)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)', 'feature_flag', 'Feature flag'),
        (r'(?i)debug\s*[:=]\s*(?:true|1|"true")', 'debug_enabled', 'Debug mode enabled'),
        (r'(?i)(?:NODE_ENV|ENVIRONMENT)["\']?\s*[:=]\s*["\']?(development|staging|test)', 'env_exposure', 'Environment variable exposed'),
        (r'(?i)(?:admin|root|superuser)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'hardcoded_role', 'Hardcoded admin/role'),
        (r'(?i)webhook["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'webhook_url', 'Webhook URL'),
        (r'(?i)(?:callback|redirect)[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'callback_url', 'Callback/redirect URL'),
    ]
    
    def __init__(self, max_size: int = 10 * 1024 * 1024):
        self.max_size = max_size
        self.rate_limiter = RateLimiter(requests_per_second=2.0, max_concurrent=3)
    
    async def analyze_urls(self, js_urls: List[str], session: aiohttp.ClientSession) -> List[JSAnalysisResult]:
        results = []
        
        for url in js_urls:
            result = await self.analyze_url(url, session)
            results.append(result)
        
        return results
    
    async def analyze_url(self, url: str, session: aiohttp.ClientSession) -> JSAnalysisResult:
        result = JSAnalysisResult(url=url)
        
        try:
            logger.debug(f"[JSAnalyzer] Analyzing {url}")
            
            response = await self.rate_limiter.request(session, url, timeout=30)
            
            if not response:
                result.error = "Failed to fetch JavaScript file"
                return result
            
            if response.status != 200:
                result.error = f"HTTP {response.status}"
                return result
            
            content = await response.text()
            result.size = len(content)
            
            if result.size > self.max_size:
                result.error = f"File too large ({result.size} bytes)"
                return result
            
            result.urls = self._extract_urls(content)
            result.api_endpoints = self._extract_api_endpoints(content)
            result.internal_refs = self._find_internal_refs(content)
            result.secrets = self._find_secrets(content)
            result.sensitive_data = self._find_sensitive_data(content)
            
            result.success = True
            
            logger.debug(f"[JSAnalyzer] Found {len(result.secrets)} secrets, "
                        f"{len(result.urls)} URLs in {url}")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"[JSAnalyzer] Error analyzing {url}: {e}")
        
        return result
    
    def _extract_urls(self, content: str) -> List[str]:
        urls = set()
        
        for pattern in self.URL_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) > 3:
                    urls.add(match)
        
        return list(urls)[:500]
    
    def _extract_api_endpoints(self, content: str) -> List[str]:
        endpoints = set()
        
        api_patterns = [
            r'(?i)["\']\/api\/[^"\']+["\']',
            r'(?i)["\']\/v\d+\/[^"\']+["\']',
            r'(?i)["\']\/graphql[^"\']*["\']',
            r'(?i)["\']\/rest\/[^"\']+["\']',
            r'(?i)fetch\s*\(\s*["\']([^"\']+)["\']',
            r'(?i)axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'(?i)\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                clean = match.strip('"\'')
                if clean and '/' in clean:
                    endpoints.add(clean)
        
        return list(endpoints)[:200]
    
    def _find_internal_refs(self, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, ref_type, description in self.INTERNAL_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append(Finding(
                        type='internal_reference',
                        value=match.group(0),
                        context=line[:200],
                        line_number=line_num,
                        confidence='medium',
                        description=description
                    ))
        
        return findings[:100]
    
    def _find_secrets(self, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, secret_type, confidence in self.SECRET_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    if self._is_likely_placeholder(value):
                        continue
                    
                    findings.append(Finding(
                        type=secret_type,
                        value=self._mask_secret(value),
                        context=self._get_context(line, match.start()),
                        line_number=line_num,
                        confidence=confidence,
                        description=f"Potential {secret_type.replace('_', ' ')}"
                    ))
        
        return findings[:100]
    
    def _find_sensitive_data(self, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, data_type, description in self.SENSITIVE_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    findings.append(Finding(
                        type=data_type,
                        value=value[:100],
                        context=line[:200],
                        line_number=line_num,
                        confidence='medium',
                        description=description
                    ))
        
        return findings[:100]
    
    def _is_likely_placeholder(self, value: str) -> bool:
        placeholders = [
            'xxx', 'yyy', 'zzz', 'your', 'enter', 'insert', 'replace',
            'example', 'sample', 'test', 'demo', 'placeholder', 'changeme',
            'todo', 'fixme', 'undefined', 'null', 'none', 'empty'
        ]
        
        lower_value = value.lower()
        
        for placeholder in placeholders:
            if placeholder in lower_value:
                return True
        
        if len(set(value.lower())) <= 3:
            return True
        
        return False
    
    def _mask_secret(self, value: str) -> str:
        if len(value) <= 8:
            return '*' * len(value)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    
    def _get_context(self, line: str, position: int) -> str:
        start = max(0, position - 30)
        end = min(len(line), position + 50)
        return line[start:end]
    
    def _calculate_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(value)
        
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
