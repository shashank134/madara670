"""Command Line Interface for WebRecon."""

import sys
import click
import asyncio
from typing import Optional, List

from . import __version__
from .config import Config
from .scanner import WebReconScanner
from .utils.logger import setup_logging
from .utils.url_utils import parse_targets, deduplicate_targets


@click.group()
@click.version_option(version=__version__, prog_name="webrecon")
def cli():
    """
    WebRecon - Professional Web Reconnaissance Tool
    
    A modular, async-first reconnaissance tool for security professionals,
    bug bounty hunters, and penetration testers.
    """
    pass


@cli.command()
@click.argument("target")
@click.option("-o", "--output", default="output", help="Output directory")
@click.option("-c", "--concurrency", default=5, help="Number of concurrent scans")
@click.option("-t", "--timeout", default=30, help="Request timeout in seconds")
@click.option("--rate-limit", default=1.0, help="Seconds between requests")
@click.option("--no-screenshot", is_flag=True, help="Disable screenshot capture")
@click.option("--no-whois", is_flag=True, help="Disable WHOIS lookup")
@click.option("--no-dns", is_flag=True, help="Disable DNS enumeration")
@click.option("--no-ssl", is_flag=True, help="Disable SSL analysis")
@click.option("--no-tech", is_flag=True, help="Disable technology detection")
@click.option("--no-extra", is_flag=True, help="Disable extra intelligence")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--mobile", is_flag=True, help="Capture mobile screenshot")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output (DEBUG level)")
@click.option("--log-file", default=None, help="Log file path")
@click.option("--config", "config_file", default=None, help="Config file path (JSON)")
def scan(
    target: str,
    output: str,
    concurrency: int,
    timeout: int,
    rate_limit: float,
    no_screenshot: bool,
    no_whois: bool,
    no_dns: bool,
    no_ssl: bool,
    no_tech: bool,
    no_extra: bool,
    html: bool,
    mobile: bool,
    verbose: bool,
    log_file: Optional[str],
    config_file: Optional[str]
):
    """
    Scan a target URL/domain or file containing targets.
    
    TARGET can be:
    
    \b
    - A single URL: example.com, https://example.com
    - A file path: urls.txt (one URL per line)
    
    Examples:
    
    \b
    webrecon scan example.com
    webrecon scan https://example.com -o results
    webrecon scan urls.txt --concurrency 10
    webrecon scan example.com --no-screenshot --html
    """
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(level=log_level, log_file=log_file)
    
    if config_file:
        try:
            config = Config.from_file(config_file)
        except Exception as e:
            click.echo(f"Error loading config file: {e}", err=True)
            sys.exit(1)
    else:
        config = Config()
    
    config.output_dir = output
    config.concurrency = concurrency
    config.timeout = timeout
    config.rate_limit = rate_limit
    config.enable_screenshot = not no_screenshot
    config.enable_whois = not no_whois
    config.enable_dns = not no_dns
    config.enable_ssl = not no_ssl
    config.enable_tech_detect = not no_tech
    config.enable_extra_intel = not no_extra
    config.generate_html = html
    config.screenshot_mobile = mobile
    config.log_level = log_level
    config.log_file = log_file
    
    targets = parse_targets(target)
    
    if not targets:
        click.echo("Error: No valid targets found", err=True)
        sys.exit(1)
    
    targets = deduplicate_targets(targets)
    
    click.echo(f"\n{'='*60}")
    click.echo(f"  WebRecon v{__version__}")
    click.echo(f"{'='*60}")
    click.echo(f"  Targets: {len(targets)}")
    click.echo(f"  Output:  {output}")
    click.echo(f"  Concurrency: {concurrency}")
    click.echo(f"{'='*60}\n")
    
    scanner = WebReconScanner(config)
    
    try:
        results = scanner.scan_sync(targets)
        
        successful = sum(1 for r in results["results"] if r.get("success"))
        failed = len(results["results"]) - successful
        
        click.echo(f"\n{'='*60}")
        click.echo(f"  Scan Complete")
        click.echo(f"{'='*60}")
        click.echo(f"  Duration: {results['scan_info']['duration']}s")
        click.echo(f"  Successful: {successful}")
        click.echo(f"  Failed: {failed}")
        click.echo(f"  Output: {results['summary_path']}")
        click.echo(f"{'='*60}\n")
        
    except KeyboardInterrupt:
        click.echo("\nScan interrupted by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"\nError during scan: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option("-o", "--output", default="config.json", help="Output file path")
def init(output: str):
    """
    Generate a sample configuration file.
    
    Creates a JSON config file with all available options
    and their default values.
    """
    config = Config()
    
    try:
        config.save(output)
        click.echo(f"Configuration file created: {output}")
    except Exception as e:
        click.echo(f"Error creating config file: {e}", err=True)
        sys.exit(1)


@cli.command()
def modules():
    """List all available reconnaissance modules."""
    click.echo(f"\n{'='*60}")
    click.echo("  WebRecon Modules")
    click.echo(f"{'='*60}\n")
    
    modules_info = [
        ("headers", "HTTP headers and security analysis", "Passive"),
        ("dns", "DNS records and network intelligence", "Passive"),
        ("ssl", "TLS/SSL certificate analysis", "Passive"),
        ("whois", "Domain WHOIS lookup", "Passive"),
        ("tech_detect", "Technology fingerprinting", "Passive"),
        ("screenshot", "Full-page screenshot capture", "Active"),
        ("extra_intel", "Additional intelligence gathering", "Mixed"),
    ]
    
    for name, desc, activity in modules_info:
        activity_color = "green" if activity == "Passive" else "yellow" if activity == "Mixed" else "red"
        click.echo(f"  [{click.style(activity, fg=activity_color)}] {name}")
        click.echo(f"      {desc}\n")
    
    click.echo(f"{'='*60}\n")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
