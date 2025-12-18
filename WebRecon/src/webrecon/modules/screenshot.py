"""Screenshot Capture Module using Playwright."""

import asyncio
import os
from typing import Dict, Any, Optional
from pathlib import Path
import aiohttp
from PIL import Image

from .base import BaseModule


class ScreenshotModule(BaseModule):
    """
    Module for capturing full-page screenshots using Playwright.
    
    Features:
    - Desktop viewport screenshots
    - Optional mobile viewport
    - Full-page capture
    - Thumbnail generation
    - Handles JS-heavy sites
    """
    
    name = "screenshot"
    description = "Full-page screenshot capture with Playwright"
    is_active = True
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None,
        output_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """Capture screenshots of the target URL."""
        from ..utils.url_utils import extract_hostname
        
        self.logger.info(f"Capturing screenshot for {url}")
        
        hostname = extract_hostname(url)
        safe_hostname = hostname.replace(".", "_").replace(":", "_")
        
        if output_dir is None:
            output_dir = os.path.join(self.config.output_dir, safe_hostname)
        
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                import shutil
                chromium_path = shutil.which("chromium") or shutil.which("chromium-browser")
                
                launch_options = {
                    "headless": True,
                    "args": [
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-software-rasterizer'
                    ]
                }
                
                if chromium_path:
                    launch_options["executable_path"] = chromium_path
                
                browser = await p.chromium.launch(**launch_options)
                
                try:
                    context = await browser.new_context(
                        viewport={
                            "width": self.config.screenshot_width,
                            "height": self.config.screenshot_height
                        },
                        user_agent=self.config.user_agent,
                        ignore_https_errors=True
                    )
                    
                    page = await context.new_page()
                    
                    await page.goto(
                        url,
                        wait_until="networkidle",
                        timeout=self.config.timeout * 1000
                    )
                    
                    await asyncio.sleep(2)
                    
                    desktop_path = os.path.join(output_dir, "screenshot_desktop.png")
                    await page.screenshot(
                        path=desktop_path,
                        full_page=self.config.screenshot_full_page
                    )
                    
                    thumb_path = os.path.join(output_dir, "screenshot_thumb.png")
                    self._create_thumbnail(desktop_path, thumb_path)
                    
                    result_data = {
                        "desktop": {
                            "path": desktop_path,
                            "width": self.config.screenshot_width,
                            "height": self.config.screenshot_height,
                            "full_page": self.config.screenshot_full_page
                        },
                        "thumbnail": {
                            "path": thumb_path
                        },
                        "page_title": await page.title(),
                        "final_url": page.url
                    }
                    
                    if self.config.screenshot_mobile:
                        await context.close()
                        
                        mobile_context = await browser.new_context(
                            viewport={"width": 375, "height": 812},
                            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
                            is_mobile=True,
                            has_touch=True,
                            ignore_https_errors=True
                        )
                        
                        mobile_page = await mobile_context.new_page()
                        await mobile_page.goto(
                            url,
                            wait_until="networkidle",
                            timeout=self.config.timeout * 1000
                        )
                        
                        await asyncio.sleep(2)
                        
                        mobile_path = os.path.join(output_dir, "screenshot_mobile.png")
                        await mobile_page.screenshot(
                            path=mobile_path,
                            full_page=self.config.screenshot_full_page
                        )
                        
                        result_data["mobile"] = {
                            "path": mobile_path,
                            "width": 375,
                            "height": 812
                        }
                        
                        await mobile_context.close()
                    else:
                        await context.close()
                    
                    return self._create_result(
                        success=True,
                        data=result_data
                    )
                    
                finally:
                    await browser.close()
                    
        except ImportError:
            error_msg = "Playwright not installed. Run: pip install playwright && playwright install chromium"
            self.logger.error(error_msg)
            return self._create_result(success=False, error=error_msg)
            
        except Exception as e:
            self.logger.error(f"Error capturing screenshot: {e}")
            return self._create_result(success=False, error=str(e))
    
    def _create_thumbnail(
        self,
        source_path: str,
        output_path: str,
        size: tuple = (320, 180)
    ) -> None:
        """Create a thumbnail from the screenshot."""
        try:
            with Image.open(source_path) as img:
                img.thumbnail(size, Image.Resampling.LANCZOS)
                img.save(output_path, "PNG", optimize=True)
        except Exception as e:
            self.logger.warning(f"Failed to create thumbnail: {e}")
