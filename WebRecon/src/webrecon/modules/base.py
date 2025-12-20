"""Base module class for WebRecon reconnaissance modules."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import asyncio
import aiohttp
from datetime import datetime

from ..utils.logger import get_logger
from ..config import Config


class BaseModule(ABC):
    """
    Abstract base class for all reconnaissance modules.
    
    All modules should inherit from this class and implement
    the `scan` method.
    """
    
    name: str = "base"
    description: str = "Base reconnaissance module"
    is_active: bool = False
    
    def __init__(self, config: Config):
        """
        Initialize the module with configuration.
        
        Args:
            config: WebRecon configuration object
        """
        self.config = config
        self.logger = get_logger(self.name)
    
    @abstractmethod
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """
        Perform reconnaissance scan on the target URL.
        
        Args:
            url: Target URL to scan
            session: Optional aiohttp session for HTTP requests
        
        Returns:
            Dictionary containing scan results
        """
        pass
    
    async def _make_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """
        Make an HTTP request with retry logic.
        
        Args:
            session: aiohttp session
            url: Target URL
            method: HTTP method
            **kwargs: Additional request parameters
        
        Returns:
            Response object or None if failed
        """
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self.config.user_agent)
        
        for attempt in range(self.config.retries):
            try:
                timeout = aiohttp.ClientTimeout(total=self.config.timeout)
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=timeout,
                    ssl=False,
                    **kwargs
                ) as response:
                    await response.read()
                    return response
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
            except aiohttp.ClientError as e:
                self.logger.warning(f"Request error on attempt {attempt + 1}: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                break
            
            if attempt < self.config.retries - 1:
                await asyncio.sleep(1 * (attempt + 1))
        
        return None
    
    def _create_result(
        self,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a standardized result dictionary.
        
        Args:
            success: Whether the scan was successful
            data: Scan result data
            error: Error message if failed
        
        Returns:
            Standardized result dictionary
        """
        return {
            "module": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "is_active": self.is_active,
            "data": data or {},
            "error": error
        }
