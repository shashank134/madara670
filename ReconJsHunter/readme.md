# ReconHunter - Bug Bounty Reconnaissance Tool

## Overview
ReconHunter is a professional-grade OSINT and JavaScript intelligence tool designed for authorized bug bounty security testing. It collects URLs, endpoints, subdomains, and JavaScript files from multiple passive intelligence sources, then performs static analysis to detect potential secrets, internal references, and sensitive data.

## Current State
- **Version**: 1.0.0
- **Status**: Fully functional MVP
- **Last Updated**: December 2024

## Project Architecture

```
reconhunter/
├── app.py                    # Flask web server (main entry point)
├── cli.py                    # Command-line interface
├── config.yaml               # Configuration file
├── src/
│   ├── core/
│   │   ├── config.py         # Configuration management
│   │   ├── logger.py         # Colored logging system
│   │   ├── normalizer.py     # URL/domain normalization
│   │   └── rate_limiter.py   # Async rate limiting
│   ├── collectors/
│   │   ├── base.py           # Base collector class
│   │   ├── wayback.py        # Wayback Machine collector
│   │   ├── urlscan.py        # URLScan.io collector
│   │   └── alienvault.py     # AlienVault OTX collector
│   ├── analyzers/
│   │   └── js_analyzer.py    # JavaScript static analyzer
│   ├── output/
│   │   ├── json_exporter.py  # JSON report generator
│   │   └── html_report.py    # HTML report generator
│   └── recon_engine.py       # Main orchestration engine
└── recon_output/             # Generated reports directory
```

## Key Features
1. **OSINT Collection**: Wayback Machine, URLScan.io, AlienVault OTX
2. **URL Categorization**: Main domain, subdomains, JavaScript files, endpoints
3. **JavaScript Analysis**: Secret detection, API endpoints, internal references
4. **Rate Limiting**: Configurable delays to avoid IP bans
5. **Interactive HTML Reports**: Visual presentation of all findings
6. **JSON Export**: Structured data for further analysis

## Running the Application

### Web Interface (Primary)
```bash
python app.py
```
Access at: http://localhost:5000

### CLI Usage
```bash
python cli.py scan example.com -o output_dir
python cli.py batch targets.txt
python cli.py sources
```

## Environment Variables (Optional)
- `URLSCAN_API_KEY`: For higher rate limits on URLScan.io
- `ALIENVAULT_API_KEY`: For AlienVault OTX API access
- `SESSION_SECRET`: Flask session secret

## User Preferences
- Web-based visual presentation preferred over CLI
- Dark theme for HTML reports
- Professional bug bounty focus

## Recent Changes
- Initial implementation with full OSINT collection
- JavaScript static analyzer with secret detection patterns
- Interactive HTML report generator
- Flask web interface for easy access
