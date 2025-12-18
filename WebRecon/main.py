#!/usr/bin/env python3
"""
WebRecon - Professional Web Reconnaissance Tool

Entry point for the WebRecon CLI application.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from webrecon.cli import main

if __name__ == "__main__":
    main()
