"""URL normalization and parsing utilities."""

import re
from typing import List, Set, Optional
from urllib.parse import urlparse, urlunparse
import tldextract


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """
    Normalize a URL by ensuring it has a scheme and is properly formatted.
    
    Args:
        url: Raw URL or domain string
        default_scheme: Scheme to use if none provided (default: https)
    
    Returns:
        Normalized URL string
    """
    url = url.strip()
    
    if not url:
        return ""
    
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"{default_scheme}://{url}"
    
    parsed = urlparse(url)
    
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    
    normalized = urlunparse((
        parsed.scheme.lower(),
        netloc,
        path,
        parsed.params,
        parsed.query,
        ""
    ))
    
    return normalized


def extract_domain(url: str) -> str:
    """
    Extract the registered domain from a URL.
    
    Args:
        url: URL string
    
    Returns:
        Registered domain (e.g., example.com)
    """
    extracted = tldextract.extract(url)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain


def extract_hostname(url: str) -> str:
    """
    Extract the full hostname from a URL.
    
    Args:
        url: URL string
    
    Returns:
        Full hostname (e.g., www.example.com)
    """
    parsed = urlparse(url)
    if parsed.netloc:
        return parsed.netloc.split(":")[0]
    
    extracted = tldextract.extract(url)
    parts = [p for p in [extracted.subdomain, extracted.domain, extracted.suffix] if p]
    return ".".join(parts)


def parse_targets(input_value: str) -> List[str]:
    """
    Parse targets from either a single URL/domain or a file path.
    
    Args:
        input_value: Either a URL/domain string or path to a file containing URLs
    
    Returns:
        List of normalized URLs
    """
    targets = []
    
    try:
        with open(input_value, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    normalized = normalize_url(line)
                    if normalized:
                        targets.append(normalized)
    except (FileNotFoundError, IOError, OSError):
        normalized = normalize_url(input_value)
        if normalized:
            targets.append(normalized)
    
    return targets


def deduplicate_targets(targets: List[str]) -> List[str]:
    """
    Remove duplicate targets while preserving order.
    
    Args:
        targets: List of URL strings
    
    Returns:
        Deduplicated list of URLs
    """
    seen: Set[str] = set()
    unique = []
    
    for target in targets:
        hostname = extract_hostname(target)
        if hostname not in seen:
            seen.add(hostname)
            unique.append(target)
    
    return unique


def get_base_url(url: str) -> str:
    """
    Get the base URL (scheme + netloc) from a full URL.
    
    Args:
        url: Full URL string
    
    Returns:
        Base URL (e.g., https://example.com)
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: URL string to validate
    
    Returns:
        True if valid URL, False otherwise
    """
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False
