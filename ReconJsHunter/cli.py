#!/usr/bin/env python3
"""
ReconHunter CLI - Professional Bug Bounty Reconnaissance Tool
"""

import asyncio
import sys
import os
import click
from colorama import init, Fore, Style

init(autoreset=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.config import Config, get_default_config
from src.core.logger import logger, set_verbose
from src.core.normalizer import normalize_input
from src.recon_engine import ReconEngine


def print_banner():
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                                   ║
║   {Fore.WHITE}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                  {Fore.CYAN}║
║   {Fore.WHITE}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                  {Fore.CYAN}║
║   {Fore.WHITE}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                  {Fore.CYAN}║
║   {Fore.WHITE}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                  {Fore.CYAN}║
║   {Fore.WHITE}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                  {Fore.CYAN}║
║   {Fore.WHITE}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                  {Fore.CYAN}║
║                                                                   ║
║   {Fore.YELLOW}██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗        {Fore.CYAN}║
║   {Fore.YELLOW}██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗       {Fore.CYAN}║
║   {Fore.YELLOW}███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝       {Fore.CYAN}║
║   {Fore.YELLOW}██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗       {Fore.CYAN}║
║   {Fore.YELLOW}██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║       {Fore.CYAN}║
║   {Fore.YELLOW}╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       {Fore.CYAN}║
║                                                                   ║
║   {Fore.GREEN}Professional Bug Bounty Reconnaissance Tool v1.0.0          {Fore.CYAN}║
║   {Fore.WHITE}For authorized security testing only                        {Fore.CYAN}║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


@click.group()
@click.version_option(version='1.0.0', prog_name='ReconHunter')
def cli():
    """ReconHunter - Professional Bug Bounty Reconnaissance Tool"""
    pass


@cli.command()
@click.argument('target')
@click.option('-o', '--output', default='recon_output', help='Output directory')
@click.option('--no-js', is_flag=True, help='Skip JavaScript analysis')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
@click.option('--json-only', is_flag=True, help='Export JSON only (no HTML)')
@click.option('--html-only', is_flag=True, help='Export HTML only (no JSON)')
@click.option('--wayback/--no-wayback', default=True, help='Enable/disable Wayback Machine')
@click.option('--urlscan/--no-urlscan', default=True, help='Enable/disable URLScan.io')
@click.option('--alienvault/--no-alienvault', default=True, help='Enable/disable AlienVault OTX')
def scan(target, output, no_js, verbose, json_only, html_only, wayback, urlscan, alienvault):
    """
    Scan a target domain for reconnaissance.
    
    TARGET can be a domain (example.com) or URL (https://example.com)
    """
    print_banner()
    
    if verbose:
        set_verbose(True)
    
    config = get_default_config()
    config.output_dir = output
    config.wayback.enabled = wayback
    config.urlscan.enabled = urlscan
    config.alienvault.enabled = alienvault
    config.js_analysis = not no_js
    
    logger.info(f"Target: {target}")
    logger.info(f"Output directory: {output}")
    
    engine = ReconEngine(config)
    
    try:
        asyncio.run(engine.run(target, analyze_js=not no_js))
        
        if not json_only:
            html_path = engine.export_html(target, output)
            logger.info(f"HTML report: {html_path}")
        
        if not html_only:
            json_dir = engine.export_json(target, output)
            logger.info(f"JSON exports: {json_dir}")
        
        print(f"\n{Fore.GREEN}[+] Reconnaissance complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    View results in: {output}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('-o', '--output', default='recon_output', help='Output directory')
@click.option('--no-js', is_flag=True, help='Skip JavaScript analysis')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
def batch(file, output, no_js, verbose):
    """
    Scan multiple targets from a file.
    
    FILE should contain one domain/URL per line.
    """
    print_banner()
    
    if verbose:
        set_verbose(True)
    
    with open(file, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not targets:
        logger.error("No valid targets found in file")
        sys.exit(1)
    
    logger.info(f"Loaded {len(targets)} targets from {file}")
    
    config = get_default_config()
    config.output_dir = output
    config.js_analysis = not no_js
    
    for i, target in enumerate(targets, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing target {i}/{len(targets)}: {target}")
        logger.info(f"{'='*60}\n")
        
        engine = ReconEngine(config)
        
        try:
            asyncio.run(engine.run(target, analyze_js=not no_js))
            engine.export_html(target, output)
            engine.export_json(target, output)
        except Exception as e:
            logger.error(f"Failed to scan {target}: {e}")
            continue
    
    print(f"\n{Fore.GREEN}[+] Batch scan complete!{Style.RESET_ALL}")


@cli.command()
def sources():
    """List available OSINT sources."""
    print_banner()
    
    sources_info = [
        ("Wayback Machine", "Historical URL archive from web.archive.org", "No API key required"),
        ("URLScan.io", "URL scanning and analysis", "API key optional (higher rate limits)"),
        ("AlienVault OTX", "Threat intelligence platform", "API key optional"),
    ]
    
    print(f"\n{Fore.CYAN}Available OSINT Sources:{Style.RESET_ALL}\n")
    
    for name, desc, auth in sources_info:
        print(f"  {Fore.GREEN}{name}{Style.RESET_ALL}")
        print(f"    {desc}")
        print(f"    {Fore.YELLOW}Auth: {auth}{Style.RESET_ALL}\n")


if __name__ == '__main__':
    cli()
