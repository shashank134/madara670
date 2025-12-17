"""WHOIS and Domain Intelligence Module."""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp
import whois

from .base import BaseModule


class WhoisModule(BaseModule):
    """
    Module for WHOIS lookup and domain intelligence.
    
    Collects:
    - Registrar information
    - Domain age
    - Creation/expiry dates
    - Name servers
    - Registrant info (if available)
    """
    
    name = "whois"
    description = "WHOIS and domain intelligence"
    is_active = False
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Perform WHOIS lookup for the target domain."""
        from ..utils.url_utils import extract_domain
        
        domain = extract_domain(url)
        
        if not domain:
            return self._create_result(
                success=False,
                error="Could not extract domain from URL"
            )
        
        self.logger.info(f"Performing WHOIS lookup for {domain}")
        
        try:
            whois_data = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._perform_whois(domain)
            )
            
            if whois_data.get("error"):
                return self._create_result(
                    success=False,
                    error=whois_data["error"]
                )
            
            return self._create_result(
                success=True,
                data=whois_data
            )
            
        except Exception as e:
            self.logger.error(f"Error in WHOIS scan: {e}")
            return self._create_result(success=False, error=str(e))
    
    def _perform_whois(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup (runs in executor)."""
        try:
            w = whois.whois(domain)
            
            if w.status is None and w.registrar is None:
                return {"error": "No WHOIS data available"}
            
            creation_date = self._parse_date(w.creation_date)
            expiration_date = self._parse_date(w.expiration_date)
            updated_date = self._parse_date(w.updated_date)
            
            domain_age = None
            if creation_date:
                age_delta = datetime.utcnow() - creation_date
                domain_age = {
                    "days": age_delta.days,
                    "years": round(age_delta.days / 365.25, 1)
                }
            
            days_until_expiry = None
            if expiration_date:
                expiry_delta = expiration_date - datetime.utcnow()
                days_until_expiry = expiry_delta.days
            
            return {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "domain_age": domain_age,
                "days_until_expiry": days_until_expiry,
                "name_servers": self._normalize_list(w.name_servers),
                "status": self._normalize_list(w.status),
                "registrant": {
                    "name": w.name if hasattr(w, 'name') else None,
                    "organization": w.org if hasattr(w, 'org') else None,
                    "country": w.country if hasattr(w, 'country') else None,
                    "state": w.state if hasattr(w, 'state') else None,
                    "city": w.city if hasattr(w, 'city') else None
                },
                "emails": self._normalize_list(w.emails) if hasattr(w, 'emails') else [],
                "dnssec": w.dnssec if hasattr(w, 'dnssec') else None
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_date(self, date_value) -> Optional[datetime]:
        """Parse date from WHOIS response (handles list or single value)."""
        if date_value is None:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if isinstance(date_value, datetime):
            return date_value
        
        if isinstance(date_value, str):
            for fmt in [
                "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%S",
                "%d-%b-%Y",
                "%Y/%m/%d",
            ]:
                try:
                    return datetime.strptime(date_value, fmt)
                except ValueError:
                    continue
        
        return None
    
    def _normalize_list(self, value) -> list:
        """Normalize a value to a list."""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v).lower() if isinstance(v, str) else v for v in value]
        return [str(value).lower() if isinstance(value, str) else value]
