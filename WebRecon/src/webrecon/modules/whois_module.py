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
    - DNSSEC status
    - Domain status flags
    - Contact information
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
            age_category = None
            if creation_date:
                age_delta = datetime.utcnow() - creation_date
                years = round(age_delta.days / 365.25, 1)
                domain_age = {
                    "days": age_delta.days,
                    "years": years,
                    "months": round(age_delta.days / 30.44, 1)
                }
                if years < 1:
                    age_category = "New Domain"
                elif years < 3:
                    age_category = "Young Domain"
                elif years < 10:
                    age_category = "Established Domain"
                else:
                    age_category = "Mature Domain"
            
            days_until_expiry = None
            expiry_status = None
            if expiration_date:
                expiry_delta = expiration_date - datetime.utcnow()
                days_until_expiry = expiry_delta.days
                if days_until_expiry < 0:
                    expiry_status = "Expired"
                elif days_until_expiry <= 30:
                    expiry_status = "Critical - Expires Soon"
                elif days_until_expiry <= 90:
                    expiry_status = "Warning - Expiring"
                elif days_until_expiry <= 365:
                    expiry_status = "Healthy"
                else:
                    expiry_status = "Long-term"
            
            registrant = self._extract_registrant(w)
            admin_contact = self._extract_admin_contact(w)
            tech_contact = self._extract_tech_contact(w)
            
            emails = self._normalize_list(getattr(w, 'emails', None))
            emails = [e for e in emails if e and '@' in str(e)]
            
            name_servers = self._normalize_list(w.name_servers)
            ns_providers = self._identify_ns_providers(name_servers)
            
            status_list = self._normalize_list(w.status)
            status_analysis = self._analyze_status(status_list)
            
            dnssec = getattr(w, 'dnssec', None)
            if isinstance(dnssec, list):
                dnssec = dnssec[0] if dnssec else None
            
            return {
                "domain": domain,
                "registrar": w.registrar,
                "registrar_url": getattr(w, 'registrar_url', None),
                "registrar_iana_id": getattr(w, 'registrar_iana_id', None),
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "domain_age": domain_age,
                "age_category": age_category,
                "days_until_expiry": days_until_expiry,
                "expiry_status": expiry_status,
                "name_servers": name_servers,
                "ns_providers": ns_providers,
                "status": status_list,
                "status_analysis": status_analysis,
                "registrant": registrant,
                "admin_contact": admin_contact,
                "tech_contact": tech_contact,
                "emails": emails,
                "dnssec": dnssec,
                "whois_server": getattr(w, 'whois_server', None),
                "raw_text_available": bool(getattr(w, 'text', None)),
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_registrant(self, w) -> Dict[str, Any]:
        """Extract registrant information."""
        return {
            "name": self._get_attr(w, ['name', 'registrant_name']),
            "organization": self._get_attr(w, ['org', 'registrant_org', 'registrant_organization']),
            "country": self._get_attr(w, ['country', 'registrant_country']),
            "state": self._get_attr(w, ['state', 'registrant_state', 'registrant_state_province']),
            "city": self._get_attr(w, ['city', 'registrant_city']),
            "address": self._get_attr(w, ['address', 'registrant_address', 'registrant_street']),
            "postal_code": self._get_attr(w, ['zipcode', 'registrant_postal_code']),
            "email": self._get_attr(w, ['registrant_email']),
            "phone": self._get_attr(w, ['registrant_phone']),
        }
    
    def _extract_admin_contact(self, w) -> Dict[str, Any]:
        """Extract admin contact information."""
        return {
            "name": self._get_attr(w, ['admin_name']),
            "organization": self._get_attr(w, ['admin_organization', 'admin_org']),
            "email": self._get_attr(w, ['admin_email']),
            "phone": self._get_attr(w, ['admin_phone']),
            "country": self._get_attr(w, ['admin_country']),
        }
    
    def _extract_tech_contact(self, w) -> Dict[str, Any]:
        """Extract tech contact information."""
        return {
            "name": self._get_attr(w, ['tech_name']),
            "organization": self._get_attr(w, ['tech_organization', 'tech_org']),
            "email": self._get_attr(w, ['tech_email']),
            "phone": self._get_attr(w, ['tech_phone']),
            "country": self._get_attr(w, ['tech_country']),
        }
    
    def _get_attr(self, obj, attrs: list) -> Optional[str]:
        """Get first available attribute from list."""
        for attr in attrs:
            val = getattr(obj, attr, None)
            if val:
                if isinstance(val, list):
                    val = val[0] if val else None
                if val:
                    return str(val)
        return None
    
    def _identify_ns_providers(self, name_servers: list) -> list:
        """Identify NS providers from name server hostnames."""
        providers = set()
        provider_map = {
            "cloudflare": "Cloudflare",
            "awsdns": "Amazon Route 53",
            "azure-dns": "Microsoft Azure DNS",
            "googledomains": "Google Domains",
            "google": "Google Cloud DNS",
            "domaincontrol": "GoDaddy",
            "registrar-servers": "Namecheap",
            "ns.cloudflare": "Cloudflare",
            "dnsimple": "DNSimple",
            "dnsmadeeasy": "DNS Made Easy",
            "ultradns": "Neustar UltraDNS",
            "nsone": "NS1",
            "digitalocean": "DigitalOcean",
            "linode": "Linode",
            "vultr": "Vultr",
            "netlify": "Netlify",
            "vercel": "Vercel",
            "hostgator": "HostGator",
            "bluehost": "Bluehost",
            "siteground": "SiteGround",
            "wpengine": "WP Engine",
            "ovh": "OVH",
            "hetzner": "Hetzner",
        }
        
        for ns in name_servers:
            ns_lower = str(ns).lower()
            for key, provider in provider_map.items():
                if key in ns_lower:
                    providers.add(provider)
                    break
        
        return list(providers)
    
    def _analyze_status(self, status_list: list) -> Dict[str, Any]:
        """Analyze domain status codes."""
        analysis = {
            "is_locked": False,
            "is_protected": False,
            "transfer_prohibited": False,
            "delete_prohibited": False,
            "update_prohibited": False,
            "pending_operations": [],
            "flags": []
        }
        
        for status in status_list:
            status_lower = str(status).lower()
            
            if "clienttransferprohibited" in status_lower or "servertransferprohibited" in status_lower:
                analysis["is_locked"] = True
                analysis["transfer_prohibited"] = True
            
            if "clientdeleteprohibited" in status_lower or "serverdeleteprohibited" in status_lower:
                analysis["delete_prohibited"] = True
                analysis["is_protected"] = True
            
            if "clientupdateprohibited" in status_lower or "serverupdateprohibited" in status_lower:
                analysis["update_prohibited"] = True
            
            if "pending" in status_lower:
                analysis["pending_operations"].append(status)
            
            if "redemptionperiod" in status_lower:
                analysis["flags"].append("In Redemption Period")
            
            if "pendingdelete" in status_lower:
                analysis["flags"].append("Pending Deletion")
        
        return analysis
    
    def _parse_date(self, date_value) -> Optional[datetime]:
        """Parse date from WHOIS response (handles list or single value)."""
        if date_value is None:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if date_value is None:
            return None
        
        if isinstance(date_value, datetime):
            if date_value.tzinfo is not None:
                return date_value.replace(tzinfo=None)
            return date_value
        
        if isinstance(date_value, str):
            clean_value = date_value.split('.')[0].split('+')[0].split('Z')[0].strip()
            for fmt in [
                "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%d-%b-%Y",
                "%Y/%m/%d",
                "%d/%m/%Y",
                "%Y.%m.%d",
            ]:
                try:
                    return datetime.strptime(clean_value, fmt)
                except ValueError:
                    continue
        
        return None
    
    def _normalize_list(self, value) -> list:
        """Normalize a value to a list."""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v).lower() if isinstance(v, str) else v for v in value if v]
        if value:
            return [str(value).lower() if isinstance(value, str) else value]
        return []
