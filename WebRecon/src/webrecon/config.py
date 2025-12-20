"""Configuration management for WebRecon."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import json
import os


@dataclass
class Config:
    """Configuration settings for WebRecon scanner."""
    
    concurrency: int = 5
    timeout: int = 30
    retries: int = 3
    rate_limit: float = 1.0
    
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    enable_headers: bool = True
    enable_dns: bool = True
    enable_ssl: bool = True
    enable_whois: bool = True
    enable_tech_detect: bool = True
    enable_screenshot: bool = True
    enable_extra_intel: bool = True
    
    screenshot_width: int = 1920
    screenshot_height: int = 1080
    screenshot_mobile: bool = False
    screenshot_full_page: bool = True
    
    dns_timeout: int = 10
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    
    common_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443, 3000, 8000])
    
    output_dir: str = "output"
    output_format: str = "json"
    generate_html: bool = False
    generate_csv: bool = False
    
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from a JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create configuration from a dictionary."""
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "concurrency": self.concurrency,
            "timeout": self.timeout,
            "retries": self.retries,
            "rate_limit": self.rate_limit,
            "user_agent": self.user_agent,
            "enable_headers": self.enable_headers,
            "enable_dns": self.enable_dns,
            "enable_ssl": self.enable_ssl,
            "enable_whois": self.enable_whois,
            "enable_tech_detect": self.enable_tech_detect,
            "enable_screenshot": self.enable_screenshot,
            "enable_extra_intel": self.enable_extra_intel,
            "screenshot_width": self.screenshot_width,
            "screenshot_height": self.screenshot_height,
            "screenshot_mobile": self.screenshot_mobile,
            "screenshot_full_page": self.screenshot_full_page,
            "dns_timeout": self.dns_timeout,
            "dns_servers": self.dns_servers,
            "common_ports": self.common_ports,
            "output_dir": self.output_dir,
            "output_format": self.output_format,
            "generate_html": self.generate_html,
            "generate_csv": self.generate_csv,
            "log_level": self.log_level,
            "log_file": self.log_file,
        }
    
    def save(self, path: str) -> None:
        """Save configuration to a JSON file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
