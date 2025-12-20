# WebRecon - Professional Web Reconnaissance Tool

## Overview
WebRecon is a production-grade, modular web reconnaissance and asset intelligence tool designed for security professionals, bug bounty hunters, and penetration testers. It performs deep passive and active information collection on target URLs/domains with enterprise-scale support for 200-300 concurrent domain scanning.

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

# Large-scale scanning (200+ domains)
cd WebRecon && python main.py scan large_domain_list.txt --concurrency 10 --html --timeout 30
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
    │   ├── tech_detect.py   # Technology fingerprinting (500+ signatures)
    │   ├── screenshot.py    # Playwright screenshot capture with retry logic
    │   └── extra_intel.py   # Additional intelligence gathering
    ├── utils/               # Utility modules
    │   ├── url_utils.py     # URL normalization & parsing
    │   └── logger.py        # Logging configuration
    └── output/              # Output handlers
        ├── json_output.py   # JSON output formatter
        └── html_output.py   # HTML report generator with pagination
```

## Modules & Capabilities

### Passive Modules
- **headers**: HTTP response headers, security header analysis (CSP, HSTS, XFO, etc.), CDN/WAF detection
- **dns**: DNS records (A, AAAA, MX, TXT, NS, CNAME), reverse DNS, ASN/ISP information
- **ssl**: TLS certificate chain, issuer, validity, expiry, weak protocol detection
- **whois**: Domain registration, registrar, age, expiry, name servers
- **tech_detect**: Wappalyzer-level fingerprinting (500+ signatures) across 17 categories with confidence scoring

### Active Modules
- **screenshot**: Full-page Playwright screenshots (desktop/mobile) with 3x retry mechanism and thumbnail generation

### Mixed Modules
- **extra_intel**: robots.txt, sitemap.xml, favicon hash, HTTP methods, redirect chains, admin panels

## Technology Detection Categories (17)
- Web Servers, Languages, Frameworks, CMS, Analytics, Payment
- CDN/WAF, JavaScript Libraries, CSS Frameworks, Services, Hosting
- E-commerce, Security, Marketing, AI/ML, Communication, Database

## Key Technologies
- **Language**: Python 3.11
- **Async HTTP**: aiohttp (concurrent scanning)
- **Screenshots**: Playwright (Chromium) with retry logic
- **DNS**: dnspython
- **WHOIS**: python-whois
- **SSL**: cryptography
- **HTML Parsing**: BeautifulSoup + lxml
- **CLI**: Click
- **Config**: Pydantic dataclasses

## Dependencies
Python packages: click, aiohttp, dnspython, python-whois, cryptography, beautifulsoup4, lxml, pydantic, playwright, tldextract, ipwhois, mmh3, pillow

System: Chromium browser (for Playwright screenshots)

## Output Structure (Consolidated)

```
output/
├── scan_summary.json       # Master summary of all scans
├── report.html             # HTML report with full pagination
├── screenshots/            # All screenshots (consolidated)
│   ├── example_com_desktop.png
│   ├── example_com_thumb.png
│   └── example_com_mobile.png
└── results/                # All JSON results (consolidated)
    └── example_com.json
```

The consolidated folder structure saves disk space when scanning 200-300+ domains by avoiding per-domain folder overhead.

## Recent Changes (Dec 2025)
- **Tech Detection**: Expanded from 350 to 500+ signatures for Wappalyzer-level detection
- **Folder Structure**: Changed from per-domain folders to consolidated `screenshots/` and `results/` folders
- **CLI**: Cleaned up output formatting for professional, concise display
- **HTML Report**: Fixed grid view to show ALL filtered results with proper pagination (removed 50-item limit)
- **HTML Styling**: Enhanced with modern gradients, improved responsiveness, and better UX
