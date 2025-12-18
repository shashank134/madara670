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
    │   ├── tech_detect.py   # Technology fingerprinting (350+ signatures)
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
- **tech_detect**: Deep technology fingerprinting (350+ signatures) across 15+ categories with confidence scoring

### Active Modules
- **screenshot**: Full-page Playwright screenshots (desktop/mobile) with 3x retry mechanism and thumbnail generation

### Mixed Modules
- **extra_intel**: robots.txt, sitemap.xml, favicon hash, HTTP methods, redirect chains, admin panels

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

## Output Structure

```
output/
├── scan_summary.json           # Master summary of all scans
├── report.html                 # HTML report with pagination (20 domains/page)
└── <hostname>/
    ├── scan_results.json       # Full JSON results
    ├── screenshot_desktop.png  # Desktop screenshot
    ├── screenshot_thumb.png    # Thumbnail
    └── screenshot_mobile.png   # Mobile screenshot (if --mobile)
```

## Technology Detection Categories

### Core Detection (Original)
- Web Servers, Programming Languages, Frameworks, CMS, Analytics, Payment Gateways
- CDN/WAF, JavaScript Libraries, Services, Hosting Providers

### Extended Detection (New)
- **E-commerce**: Stripe, WooCommerce, Shopify Plus, BigCommerce, Snipcart, Paddle, Gumroad, and 8+ more
- **Security**: Cloudflare Bot Management, PerimeterX, DataDome, Fingerprint.js, Sift, and 8+ more
- **Marketing**: Google Ads, Facebook Pixel, LinkedIn Insight, TikTok Pixel, Criteo, AdRoll, and 8+ more
- **AI/ML**: OpenAI, Claude, Google AI, Hugging Face, Replicate, Pinecone, and 8+ more
- **Communication**: Slack, Discord, WhatsApp, Telegram, Microsoft Teams, Zoom, and 3+ more
- **Database**: MongoDB, PostgreSQL, MySQL, Redis, Supabase, PlanetScale, and 7+ more

Total: 350+ technology signatures across 15 categories with confidence scoring

## Recent Changes

### Dec 2025 - Enterprise-Scale Enhancements
- **Screenshot Module Reliability** (screenshot.py)
  - Implemented 3x retry mechanism with exponential backoff
  - Fixed browser lifecycle management (proper context/page closure)
  - Added resource cleanup to prevent browser memory leaks
  - Graceful handling of transient connection failures
  
- **HTML Report for Large Scans** (html_output.py)
  - Client-side pagination: 20 domains per page
  - Search and filter functionality across all domains
  - Grid/List view toggle for flexible visualization
  - Lazy loading for screenshots to prevent performance degradation
  - Modern dark theme with cyan/blue gradients
  - Responsive layout with collapsible sections
  - Base64 embedded screenshots for portability
  
- **Expanded Technology Detection** (tech_detect.py)
  - Added 150+ new technology signatures
  - Extended favicon hash database (32+ hashes)
  - New detection categories: ecommerce, security, marketing, AI/ML, communication, database
  - Improved detection accuracy with category-specific patterns
  - Support for modern SaaS and enterprise tools

- **Enterprise-Scale Capability**
  - Tool now optimized for scanning 200-300 domains efficiently
  - Adjustable concurrency (default: 5, recommended: 10-20 for large scans)
  - HTML report pagination prevents UI lag on large result sets
  - Memory-efficient screenshot handling with proper resource cleanup

### Previous Versions
- **Initial Setup**: Configured for Replit environment
  - Installed Python dependencies (click, aiohttp, dnspython, python-whois, cryptography, beautifulsoup4, lxml, pydantic, playwright, tldextract, ipwhois, mmh3, pillow)
  - Installed system Chromium browser for screenshots
  - Set up console workflow for CLI execution
