# WebRecon - Professional Web Reconnaissance Tool

## Overview
WebRecon is a production-grade, modular web reconnaissance and asset intelligence tool designed for security professionals, bug bounty hunters, and penetration testers. It performs deep passive and active information collection on target URLs/domains.

## How to Run

This is a CLI (command-line interface) tool. Run it from the `WebRecon` directory:

```bash
# Show help
cd WebRecon && python main.py --help

# Scan a single domain
cd WebRecon && python main.py scan example.com

# Scan with custom output directory
cd WebRecon && python main.py scan example.com -o results

# Scan multiple targets from file
cd WebRecon && python main.py scan urls.txt --concurrency 10

# Disable certain modules
cd WebRecon && python main.py scan example.com --no-screenshot --no-whois

# Generate HTML report
cd WebRecon && python main.py scan example.com --html

# Verbose mode
cd WebRecon && python main.py scan example.com -v

# List available modules
cd WebRecon && python main.py modules

# Generate config file
cd WebRecon && python main.py init -o config.json
```

## Project Architecture

```
WebRecon/
├── main.py              # Entry point
└── src/webrecon/
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

## Recent Changes
- **Dec 2025**: Major HTML report redesign
  - Modern dark theme UI with cyan/blue gradient styling
  - Sidebar navigation with collapsible sections
  - Embedded base64 screenshots in reports
  - Responsive layout with beautiful cards and data grids
- **Dec 2025**: Enhanced reconnaissance modules
  - Technology detection: 200+ signatures across 9 categories with confidence scoring
  - WHOIS: Registrar details, domain age analysis, expiry status, nameserver provider identification
  - SSL: Certificate chain analysis, security issue detection, weak protocol warnings
  - Screenshots: System Chromium integration with thumbnail generation
- **Initial Setup**: Configured for Replit environment
  - Installed Python dependencies (click, aiohttp, dnspython, python-whois, cryptography, beautifulsoup4, lxml, pydantic, playwright, tldextract, ipwhois, mmh3, pillow)
  - Installed system Chromium browser for screenshots
  - Set up console workflow for CLI execution
