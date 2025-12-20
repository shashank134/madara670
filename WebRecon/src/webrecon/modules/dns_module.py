"""DNS and Network Intelligence Module."""

import asyncio
import socket
from typing import Dict, Any, List, Optional
import aiohttp
import dns.resolver
import dns.reversename
from ipwhois import IPWhois

from .base import BaseModule


class DNSModule(BaseModule):
    """
    Module for DNS enumeration and network intelligence gathering.
    
    Collects:
    - DNS records (A, AAAA, MX, TXT, NS, CNAME)
    - Reverse DNS
    - IP resolution (IPv4/IPv6)
    - ASN and ISP information
    - GeoIP data (basic)
    """
    
    name = "dns"
    description = "DNS and network infrastructure intelligence"
    is_active = False
    
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Perform DNS enumeration and network intelligence gathering."""
        from ..utils.url_utils import extract_hostname, extract_domain
        
        hostname = extract_hostname(url)
        domain = extract_domain(url)
        
        self.logger.info(f"Scanning DNS for {hostname}")
        
        try:
            dns_records = await self._resolve_all_records(hostname)
            
            ip_addresses = dns_records.get("A", []) + dns_records.get("AAAA", [])
            
            reverse_dns = {}
            asn_info = {}
            
            if ip_addresses:
                primary_ip = dns_records.get("A", [None])[0]
                if primary_ip:
                    reverse_dns = await self._reverse_lookup(primary_ip)
                    asn_info = await self._get_asn_info(primary_ip)
            
            return self._create_result(
                success=True,
                data={
                    "hostname": hostname,
                    "domain": domain,
                    "records": dns_records,
                    "ip_addresses": {
                        "ipv4": dns_records.get("A", []),
                        "ipv6": dns_records.get("AAAA", [])
                    },
                    "reverse_dns": reverse_dns,
                    "asn": asn_info,
                    "nameservers": dns_records.get("NS", []),
                    "mail_servers": self._parse_mx_records(dns_records.get("MX", []))
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error in DNS scan: {e}")
            return self._create_result(success=False, error=str(e))
    
    async def _resolve_all_records(self, hostname: str) -> Dict[str, List[str]]:
        """Resolve all DNS record types for the hostname."""
        records = {}
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.dns_timeout
        resolver.lifetime = self.config.dns_timeout
        
        if self.config.dns_servers:
            resolver.nameservers = self.config.dns_servers
        
        for record_type in self.RECORD_TYPES:
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda rt=record_type: resolver.resolve(hostname, rt)
                )
                
                record_values = []
                for rdata in answers:
                    if record_type == "MX":
                        record_values.append(f"{rdata.preference} {rdata.exchange}")
                    elif record_type == "SOA":
                        record_values.append({
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum
                        })
                    else:
                        record_values.append(str(rdata))
                
                records[record_type] = record_values
                
            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"NXDOMAIN for {record_type} record")
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {record_type} record found")
            except dns.resolver.NoNameservers:
                self.logger.warning(f"No nameservers available for {record_type}")
            except Exception as e:
                self.logger.debug(f"Error resolving {record_type}: {e}")
        
        return records
    
    async def _reverse_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup."""
        try:
            reverse_name = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config.dns_timeout
            
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(reverse_name, "PTR")
            )
            
            ptr_records = [str(rdata) for rdata in answers]
            
            return {
                "ip": ip,
                "ptr_records": ptr_records
            }
            
        except Exception as e:
            self.logger.debug(f"Reverse lookup failed for {ip}: {e}")
            return {"ip": ip, "ptr_records": [], "error": str(e)}
    
    async def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN and network information for an IP address."""
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._perform_whois_lookup(ip)
            )
            return result
        except Exception as e:
            self.logger.debug(f"ASN lookup failed for {ip}: {e}")
            return {"error": str(e)}
    
    def _perform_whois_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform IP WHOIS lookup (runs in executor)."""
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            return {
                "asn": results.get("asn"),
                "asn_description": results.get("asn_description"),
                "asn_country_code": results.get("asn_country_code"),
                "network": {
                    "name": results.get("network", {}).get("name"),
                    "cidr": results.get("asn_cidr"),
                    "country": results.get("asn_country_code")
                },
                "isp": results.get("asn_description", "").split(" - ")[0] if results.get("asn_description") else None
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_mx_records(self, mx_records: List[str]) -> List[Dict[str, Any]]:
        """Parse MX records into structured format."""
        parsed = []
        for record in mx_records:
            parts = record.split(" ", 1)
            if len(parts) == 2:
                try:
                    priority = int(parts[0])
                    host = parts[1].rstrip(".")
                    parsed.append({"priority": priority, "host": host})
                except ValueError:
                    parsed.append({"raw": record})
            else:
                parsed.append({"raw": record})
        
        return sorted(parsed, key=lambda x: x.get("priority", 999))
