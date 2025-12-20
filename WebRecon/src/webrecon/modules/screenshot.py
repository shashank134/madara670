"""Screenshot Capture Module using Playwright - Optimized folder structure."""

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
    All screenshots saved to consolidated screenshots folder.
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
        
        self.logger.debug(f"Capturing screenshot for {url}")
        
        hostname = extract_hostname(url)
        safe_hostname = hostname.replace(".", "_").replace(":", "_")
        
        if output_dir is None:
            output_dir = os.path.join(self.config.output_dir, "screenshots")
        
        os.makedirs(output_dir, exist_ok=True)
        
        max_retries = 3
        last_error = None
        
        for attempt in range(max_retries):
            try:
                result = await self._capture_screenshot(url, output_dir, safe_hostname, attempt)
                if result.get("success"):
                    return result
                last_error = result.get("error", "Unknown error")
            except Exception as e:
                last_error = str(e)
                self.logger.warning(f"Screenshot attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(1 * (attempt + 1))
        
        return self._create_result(success=False, error=f"Failed after {max_retries} attempts: {last_error}")
    
    async def _capture_screenshot(
        self,
        url: str,
        output_dir: str,
        safe_hostname: str,
        attempt: int = 0
    ) -> Dict[str, Any]:
        """Internal method to capture screenshot with proper browser management."""
        browser = None
        context = None
        
        try:
            from playwright.async_api import async_playwright
            
            playwright = await async_playwright().start()
            
            try:
                launch_options = {
                    "headless": True,
                    "args": [
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-software-rasterizer',
                        '--disable-extensions',
                        '--disable-background-networking',
                        '--disable-sync',
                        '--disable-translate',
                        '--disable-features=IsolateOrigins,site-per-process',
                        '--no-zygote',
                        '--no-first-run',
                        '--disable-default-apps',
                        '--hide-scrollbars',
                        '--mute-audio',
                    ],
                    "timeout": 60000,
                }
                
                browser = await playwright.chromium.launch(**launch_options)
                
                context = await browser.new_context(
                    viewport={
                        "width": self.config.screenshot_width,
                        "height": self.config.screenshot_height
                    },
                    user_agent=self.config.user_agent,
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                
                context.set_default_timeout(self.config.timeout * 1000)
                context.set_default_navigation_timeout(self.config.timeout * 1000)
                
                page = await context.new_page()
                
                try:
                    await page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=self.config.timeout * 1000
                    )
                except Exception as nav_error:
                    self.logger.warning(f"Navigation issue (continuing): {nav_error}")
                
                await asyncio.sleep(2)
                
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    pass
                
                desktop_path = os.path.join(output_dir, f"{safe_hostname}_desktop.png")
                
                try:
                    await page.screenshot(
                        path=desktop_path,
                        full_page=self.config.screenshot_full_page,
                        timeout=30000
                    )
                except Exception as ss_error:
                    self.logger.warning(f"Full page screenshot failed, trying viewport only: {ss_error}")
                    await page.screenshot(
                        path=desktop_path,
                        full_page=False,
                        timeout=30000
                    )
                
                thumb_path = os.path.join(output_dir, f"{safe_hostname}_thumb.png")
                self._create_thumbnail(desktop_path, thumb_path)
                
                page_title = ""
                try:
                    page_title = await page.title()
                except:
                    pass
                
                final_url = page.url
                
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
                    "page_title": page_title,
                    "final_url": final_url
                }
                
                if self.config.screenshot_mobile:
                    try:
                        await page.close()
                        
                        mobile_context = await browser.new_context(
                            viewport={"width": 375, "height": 812},
                            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
                            is_mobile=True,
                            has_touch=True,
                            ignore_https_errors=True
                        )
                        
                        mobile_page = await mobile_context.new_page()
                        
                        try:
                            await mobile_page.goto(
                                url,
                                wait_until="domcontentloaded",
                                timeout=self.config.timeout * 1000
                            )
                        except:
                            pass
                        
                        await asyncio.sleep(2)
                        
                        mobile_path = os.path.join(output_dir, f"{safe_hostname}_mobile.png")
                        await mobile_page.screenshot(
                            path=mobile_path,
                            full_page=self.config.screenshot_full_page,
                            timeout=30000
                        )
                        
                        result_data["mobile"] = {
                            "path": mobile_path,
                            "width": 375,
                            "height": 812
                        }
                        
                        await mobile_context.close()
                    except Exception as mobile_err:
                        self.logger.warning(f"Mobile screenshot failed: {mobile_err}")
                
                return self._create_result(
                    success=True,
                    data=result_data
                )
                
            finally:
                if context:
                    try:
                        await context.close()
                    except:
                        pass
                if browser:
                    try:
                        await browser.close()
                    except:
                        pass
                try:
                    await playwright.stop()
                except:
                    pass
                    
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
