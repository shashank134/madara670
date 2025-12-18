"""
Logging configuration for ReconHunter.
Provides colored console output and file logging.
"""

import logging
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }
    
    ICONS = {
        logging.DEBUG: "[*]",
        logging.INFO: "[+]",
        logging.WARNING: "[!]",
        logging.ERROR: "[-]",
        logging.CRITICAL: "[X]"
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelno, Fore.WHITE)
        icon = self.ICONS.get(record.levelno, "[?]")
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = f"{color}{icon} [{timestamp}] {record.getMessage()}{Style.RESET_ALL}"
        
        return message


class FileFormatter(logging.Formatter):
    def format(self, record):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)
        return f"[{timestamp}] {level} | {record.getMessage()}"


def setup_logger(name: str = "reconhunter", level: int = logging.INFO, 
                 log_file: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter())
    console_handler.setLevel(level)
    logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(FileFormatter())
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
    
    return logger


logger = setup_logger()


def set_verbose(verbose: bool = True):
    global logger
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(level)
