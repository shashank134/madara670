"""
WebRecon - Professional Web Reconnaissance and Asset Intelligence Tool

A modular, async-first reconnaissance tool for security professionals,
bug bounty hunters, and penetration testers.
"""

__version__ = "1.0.0"
__author__ = "Security Engineer"

from .scanner import WebReconScanner
from .config import Config

__all__ = ["WebReconScanner", "Config", "__version__"]
