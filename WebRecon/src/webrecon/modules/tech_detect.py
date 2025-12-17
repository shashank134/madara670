"""Technology Detection and Fingerprinting Module."""

import re
from typing import Dict, Any, List, Optional, Set
import aiohttp
from bs4 import BeautifulSoup
import mmh3
import hashlib

from .base import BaseModule


class TechDetectModule(BaseModule):
    """
    Module for deep technology fingerprinting and detection.
    
    Detects:
    - Web servers (nginx, Apache, IIS, etc.)
    - Programming languages (PHP, Java, Node.js, Python, Ruby, etc.)
    - Frameworks (Laravel, Django, Spring, Rails, Next.js, React, Vue)
    - CMS (WordPress, Drupal, Joomla, etc.)
    - Analytics (GA, GTM, Mixpanel, Segment)
    - Payment gateways
    - CDN & WAF
    - JS libraries
    - Third-party services
    """
    
    name = "tech_detect"
    description = "Technology fingerprinting and detection"
    is_active = False
    
    TECH_SIGNATURES = {
        "web_servers": {
            "nginx": {"headers": ["server:nginx"], "patterns": []},
            "Apache": {"headers": ["server:apache"], "patterns": []},
            "IIS": {"headers": ["server:microsoft-iis"], "patterns": []},
            "LiteSpeed": {"headers": ["server:litespeed"], "patterns": []},
            "Caddy": {"headers": ["server:caddy"], "patterns": []},
            "Tomcat": {"headers": ["server:apache-coyote"], "patterns": []},
            "gunicorn": {"headers": ["server:gunicorn"], "patterns": []},
            "uvicorn": {"headers": ["server:uvicorn"], "patterns": []},
        },
        "languages": {
            "PHP": {
                "headers": ["x-powered-by:php"],
                "patterns": [r"\.php", r"PHPSESSID"],
                "cookies": ["PHPSESSID"]
            },
            "ASP.NET": {
                "headers": ["x-powered-by:asp.net", "x-aspnet-version"],
                "patterns": [r"\.aspx", r"\.ashx", r"__VIEWSTATE"],
                "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"]
            },
            "Java": {
                "headers": ["x-powered-by:servlet"],
                "patterns": [r"\.jsp", r"\.jsf", r"jsessionid"],
                "cookies": ["JSESSIONID"]
            },
            "Python": {
                "headers": ["x-powered-by:python", "server:python"],
                "patterns": [r"csrfmiddlewaretoken"]
            },
            "Ruby": {
                "headers": ["x-powered-by:phusion"],
                "patterns": [r"\.rb"],
                "cookies": ["_session_id"]
            },
            "Node.js": {
                "headers": ["x-powered-by:express"],
                "patterns": []
            },
        },
        "frameworks": {
            "Laravel": {
                "patterns": [r"laravel_session", r"XSRF-TOKEN"],
                "cookies": ["laravel_session", "XSRF-TOKEN"]
            },
            "Django": {
                "patterns": [r"csrfmiddlewaretoken", r"django"],
                "cookies": ["csrftoken", "sessionid"]
            },
            "Flask": {
                "patterns": [],
                "cookies": ["session"]
            },
            "Rails": {
                "patterns": [r"csrf-token", r"data-turbolinks"],
                "cookies": ["_session"]
            },
            "Spring": {
                "patterns": [r"_csrf", r"spring"],
                "cookies": ["JSESSIONID"]
            },
            "Express": {
                "headers": ["x-powered-by:express"],
                "patterns": []
            },
            "Next.js": {
                "patterns": [r"_next/static", r"__NEXT_DATA__", r"next/dist"],
                "headers": ["x-nextjs-cache", "x-vercel-cache"]
            },
            "Nuxt.js": {
                "patterns": [r"_nuxt/", r"__NUXT__"]
            },
            "React": {
                "patterns": [r"react", r"_reactRootContainer", r"data-reactroot", r"react-dom"]
            },
            "Vue.js": {
                "patterns": [r"vue", r"data-v-", r"Vue\."]
            },
            "Angular": {
                "patterns": [r"ng-version", r"ng-app", r"angular", r"\[ng-"]
            },
            "Svelte": {
                "patterns": [r"svelte", r"__svelte"]
            },
        },
        "cms": {
            "WordPress": {
                "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
                "meta": ["generator:wordpress"]
            },
            "Drupal": {
                "patterns": [r"/sites/default/", r"Drupal\.settings", r"drupal"],
                "headers": ["x-drupal-cache", "x-generator:drupal"]
            },
            "Joomla": {
                "patterns": [r"/components/com_", r"/modules/mod_", r"joomla"],
                "meta": ["generator:joomla"]
            },
            "Magento": {
                "patterns": [r"/skin/frontend/", r"/js/mage/", r"Mage\."],
                "cookies": ["frontend"]
            },
            "Shopify": {
                "patterns": [r"cdn\.shopify\.com", r"shopify", r"myshopify\.com"],
                "headers": ["x-shopify-stage"]
            },
            "Wix": {
                "patterns": [r"wix\.com", r"wixstatic\.com", r"_wix_browser_sess"]
            },
            "Squarespace": {
                "patterns": [r"squarespace", r"static\.squarespace\.com"]
            },
            "Ghost": {
                "patterns": [r"ghost", r"/ghost/"],
                "meta": ["generator:ghost"]
            },
            "Webflow": {
                "patterns": [r"webflow", r"assets\.website-files\.com"]
            },
        },
        "analytics": {
            "Google Analytics": {
                "patterns": [r"google-analytics\.com", r"gtag\(", r"ga\(", r"UA-\d+", r"G-[A-Z0-9]+"]
            },
            "Google Tag Manager": {
                "patterns": [r"googletagmanager\.com", r"GTM-[A-Z0-9]+"]
            },
            "Facebook Pixel": {
                "patterns": [r"connect\.facebook\.net", r"fbq\(", r"facebook\.com/tr"]
            },
            "Mixpanel": {
                "patterns": [r"mixpanel\.com", r"mixpanel\."]
            },
            "Segment": {
                "patterns": [r"segment\.com", r"analytics\.js", r"cdn\.segment\.com"]
            },
            "Hotjar": {
                "patterns": [r"hotjar\.com", r"hj\("]
            },
            "Heap": {
                "patterns": [r"heap\.io", r"heapanalytics"]
            },
            "Amplitude": {
                "patterns": [r"amplitude\.com", r"amplitude\."]
            },
            "Plausible": {
                "patterns": [r"plausible\.io"]
            },
        },
        "payment": {
            "Stripe": {
                "patterns": [r"stripe\.com", r"js\.stripe\.com", r"Stripe\("]
            },
            "PayPal": {
                "patterns": [r"paypal\.com", r"paypalobjects\.com"]
            },
            "Square": {
                "patterns": [r"squareup\.com", r"square\.com"]
            },
            "Braintree": {
                "patterns": [r"braintree", r"braintreegateway\.com"]
            },
        },
        "cdn_waf": {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
                "patterns": [r"cloudflare"]
            },
            "AWS CloudFront": {
                "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
                "patterns": [r"cloudfront\.net"]
            },
            "Akamai": {
                "headers": ["x-akamai-transformed"],
                "patterns": [r"akamai"]
            },
            "Fastly": {
                "headers": ["x-served-by", "x-cache:.*fastly"],
                "patterns": [r"fastly"]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id"],
                "patterns": [r"sucuri"]
            },
            "Incapsula": {
                "headers": ["x-iinfo"],
                "patterns": [r"incapsula"]
            },
        },
        "js_libraries": {
            "jQuery": {"patterns": [r"jquery", r"jQuery"]},
            "Bootstrap": {"patterns": [r"bootstrap"]},
            "Tailwind CSS": {"patterns": [r"tailwind"]},
            "Lodash": {"patterns": [r"lodash"]},
            "Moment.js": {"patterns": [r"moment\.js", r"moment\.min\.js"]},
            "Axios": {"patterns": [r"axios"]},
            "D3.js": {"patterns": [r"d3\.js", r"d3\.min\.js"]},
            "Three.js": {"patterns": [r"three\.js", r"three\.min\.js"]},
            "Chart.js": {"patterns": [r"chart\.js"]},
            "Socket.io": {"patterns": [r"socket\.io"]},
            "Alpine.js": {"patterns": [r"alpinejs", r"x-data"]},
            "HTMX": {"patterns": [r"htmx", r"hx-get", r"hx-post"]},
        },
        "services": {
            "reCAPTCHA": {"patterns": [r"recaptcha", r"google\.com/recaptcha"]},
            "hCaptcha": {"patterns": [r"hcaptcha"]},
            "Cloudinary": {"patterns": [r"cloudinary\.com"]},
            "Imgix": {"patterns": [r"imgix\.net"]},
            "Sentry": {"patterns": [r"sentry\.io", r"sentry"]},
            "Intercom": {"patterns": [r"intercom", r"widget\.intercom\.io"]},
            "Zendesk": {"patterns": [r"zendesk"]},
            "Drift": {"patterns": [r"drift\.com"]},
            "Crisp": {"patterns": [r"crisp\.chat"]},
            "Typeform": {"patterns": [r"typeform\.com"]},
            "Mailchimp": {"patterns": [r"mailchimp"]},
            "HubSpot": {"patterns": [r"hubspot", r"hs-scripts\.com"]},
            "Salesforce": {"patterns": [r"salesforce", r"force\.com"]},
        }
    }
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Perform technology detection scan."""
        self.logger.info(f"Scanning technologies for {url}")
        
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
            
            html_content = ""
            try:
                html_content = await response.text() if hasattr(response, 'text') else ""
            except:
                try:
                    html_content = response._body.decode('utf-8', errors='ignore') if hasattr(response, '_body') else ""
                except:
                    pass
            
            headers_dict = dict(response.headers)
            
            cookies = []
            if hasattr(response, 'cookies'):
                cookies = list(response.cookies.keys())
            
            detected = await self._detect_technologies(
                html_content,
                headers_dict,
                cookies,
                url
            )
            
            return self._create_result(
                success=True,
                data=detected
            )
            
        except Exception as e:
            self.logger.error(f"Error in tech detection: {e}")
            return self._create_result(success=False, error=str(e))
        finally:
            if should_close:
                await session.close()
    
    async def _detect_technologies(
        self,
        html: str,
        headers: Dict[str, str],
        cookies: List[str],
        url: str
    ) -> Dict[str, Any]:
        """Detect all technologies from content."""
        detected: Dict[str, Set[str]] = {
            "web_servers": set(),
            "languages": set(),
            "frameworks": set(),
            "cms": set(),
            "analytics": set(),
            "payment": set(),
            "cdn_waf": set(),
            "js_libraries": set(),
            "services": set()
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        html_lower = html.lower()
        cookies_lower = [c.lower() for c in cookies]
        
        soup = BeautifulSoup(html, 'lxml')
        meta_tags = self._extract_meta_tags(soup)
        scripts = self._extract_script_sources(soup)
        
        for category, technologies in self.TECH_SIGNATURES.items():
            for tech_name, signatures in technologies.items():
                if self._check_technology(
                    signatures,
                    headers_lower,
                    html_lower,
                    cookies_lower,
                    meta_tags,
                    scripts
                ):
                    detected[category].add(tech_name)
        
        result = {
            category: sorted(list(techs))
            for category, techs in detected.items()
        }
        
        result["summary"] = {
            "total_detected": sum(len(v) for v in detected.values()),
            "categories_with_findings": [
                cat for cat, techs in detected.items() if techs
            ]
        }
        
        return result
    
    def _check_technology(
        self,
        signatures: Dict,
        headers: Dict[str, str],
        html: str,
        cookies: List[str],
        meta_tags: Dict[str, str],
        scripts: List[str]
    ) -> bool:
        """Check if technology is present based on signatures."""
        for header_sig in signatures.get("headers", []):
            if ":" in header_sig:
                h_name, h_val = header_sig.split(":", 1)
                if h_name in headers and h_val in headers[h_name]:
                    return True
            elif header_sig in headers:
                return True
        
        for pattern in signatures.get("patterns", []):
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        for cookie_sig in signatures.get("cookies", []):
            if cookie_sig.lower() in cookies:
                return True
        
        for meta_sig in signatures.get("meta", []):
            if ":" in meta_sig:
                m_name, m_val = meta_sig.split(":", 1)
                if m_name in meta_tags and m_val.lower() in meta_tags[m_name].lower():
                    return True
        
        return False
    
    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta tag values."""
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name", "") or tag.get("property", "")
            content = tag.get("content", "")
            if name and content:
                meta[name.lower()] = content
        return meta
    
    def _extract_script_sources(self, soup: BeautifulSoup) -> List[str]:
        """Extract script sources."""
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                scripts.append(src.lower())
            if script.string:
                scripts.append(script.string[:500].lower())
        return scripts
