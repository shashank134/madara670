# WebRecon - Professional Web Reconnaissance Tool

## Overview
WebRecon is a production-grade, modular web reconnaissance and asset intelligence tool designed for security professionals, bug bounty hunters, and penetration testers. It performs deep passive and active information collection on target URLs/domains.

## Project Architecture

```
src/webrecon/
├── __init__.py          # Package initialization
├── config.py            # Configuration management
├── scanner.py           # Main orchestrator (async)
├── cli.py               # Click-based CLI interface
├── modules/             # Reconnaissance modules
│   ├── base.py          # Base module class
│   ├── headers.py       # HTTP/Security headers analysis
│   ├── dns_module.py    # DNS enumeration & network intel
│   ├── ssl_module.py    # TLS/SSL certificate analysis
│   ├── whois_module.py  # WHOIS domain intelligence
│   ├── tech_detect.py   # Technology fingerprinting
│   ├── screenshot.py    # Playwright screenshot capture
│   └── extra_intel.py   # Additional intelligence gathering
├── utils/               # Utility modules
│   ├── url_utils.py     # URL normalization & parsing
│   └── logger.py        # Logging configuration
└── output/              # Output handlers
    ├── json_output.py   # JSON output formatter
    └── html_output.py   # HTML report generator
```

## Modules & Capabilities

### Passive Modules
- **headers**: HTTP response headers, security header analysis (CSP, HSTS, XFO, etc.), CDN/WAF detection
- **dns**: DNS records (A, AAAA, MX, TXT, NS, CNAME), reverse DNS, ASN/ISP information
- **ssl**: TLS certificate chain, issuer, validity, expiry, weak protocol detection
- **whois**: Domain registration, registrar, age, expiry, name servers
- **tech_detect**: Deep technology fingerprinting (servers, frameworks, CMS, analytics, CDN)

### Active Modules
- **screenshot**: Full-page Playwright screenshots (desktop/mobile), thumbnails

### Mixed Modules
- **extra_intel**: robots.txt, sitemap.xml, favicon hash, HTTP methods, redirect chains, admin panels

## Usage Examples

```bash
# Scan a single domain
python main.py scan example.com

# Scan with custom output directory
python main.py scan example.com -o results

# Scan multiple targets from file
python main.py scan urls.txt --concurrency 10

# Disable certain modules
python main.py scan example.com --no-screenshot --no-whois

# Generate HTML report
python main.py scan example.com --html

# Verbose mode
python main.py scan example.com -v

# List available modules
python main.py modules

# Generate config file
python main.py init -o config.json
```

## Output Structure

```
output/
├── scan_summary.json           # Master summary of all scans
├── report.html                 # HTML report (if --html)
└── <hostname>/
    ├── scan_results.json       # Full JSON results
    ├── screenshot_desktop.png  # Desktop screenshot
    ├── screenshot_thumb.png    # Thumbnail
    └── screenshot_mobile.png   # Mobile screenshot (if --mobile)
```

## Key Technologies
- **Language**: Python 3.11
- **Async HTTP**: aiohttp
- **Screenshots**: Playwright (Chromium)
- **DNS**: dnspython
- **WHOIS**: python-whois
- **SSL**: cryptography
- **HTML Parsing**: BeautifulSoup + lxml
- **CLI**: Click
- **Config**: Pydantic dataclasses

## Development Notes

### Adding New Modules
1. Create new module in `src/webrecon/modules/`
2. Inherit from `BaseModule`
3. Implement `async def scan(self, url, session)` method
4. Register in `scanner.py` and `modules/__init__.py`

### Configuration
Default config values are in `src/webrecon/config.py`. Users can override via:
- CLI flags
- JSON config file (`--config config.json`)

## Recent Changes
- Initial implementation with 7 reconnaissance modules
- Async/concurrent scanning with rate limiting
- JSON output with optional HTML reports
- Modular architecture for extensibility
