"""TLS/SSL Certificate Analysis Module."""

import ssl
import socket
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from .base import BaseModule


class SSLModule(BaseModule):
    """
    Module for TLS/SSL certificate analysis.
    
    Analyzes:
    - Certificate chain
    - Issuer information
    - Validity period
    - Expiry status
    - Weak protocols/ciphers (basic)
    - Self-signed detection
    """
    
    name = "ssl"
    description = "TLS/SSL certificate analysis"
    is_active = False
    
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"
    ]
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Analyze TLS/SSL certificate for the target."""
        from ..utils.url_utils import extract_hostname
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        hostname = extract_hostname(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        if parsed.scheme != "https":
            https_url = url.replace("http://", "https://", 1)
            hostname = extract_hostname(https_url)
        
        self.logger.info(f"Scanning SSL certificate for {hostname}:{port}")
        
        try:
            cert_info = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._get_certificate_info(hostname, port)
            )
            
            if cert_info.get("error"):
                return self._create_result(
                    success=False,
                    error=cert_info["error"]
                )
            
            return self._create_result(
                success=True,
                data=cert_info
            )
            
        except Exception as e:
            self.logger.error(f"Error in SSL scan: {e}")
            return self._create_result(success=False, error=str(e))
    
    def _get_certificate_info(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
            
            if cert_der:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                cert_info = self._parse_certificate(cert, cert_dict)
            else:
                cert_info = {}
            
            cert_info["connection"] = {
                "protocol": protocol,
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None
            }
            
            cert_info["security_issues"] = self._check_security_issues(
                cert_info, protocol, cipher
            )
            
            return cert_info
            
        except ssl.SSLError as e:
            return {"error": f"SSL Error: {str(e)}"}
        except socket.timeout:
            return {"error": "Connection timeout"}
        except socket.error as e:
            return {"error": f"Socket error: {str(e)}"}
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_certificate(
        self,
        cert: x509.Certificate,
        cert_dict: Dict
    ) -> Dict[str, Any]:
        """Parse certificate details."""
        now = datetime.utcnow()
        
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        
        if hasattr(not_before, 'replace'):
            not_before = not_before.replace(tzinfo=None)
        if hasattr(not_after, 'replace'):
            not_after = not_after.replace(tzinfo=None)
        
        days_until_expiry = (not_after - now).days
        
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value
        
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value
        
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        is_self_signed = cert.issuer == cert.subject
        
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
        
        return {
            "subject": {
                "common_name": subject.get("commonName"),
                "organization": subject.get("organizationName"),
                "organizational_unit": subject.get("organizationalUnitName"),
                "country": subject.get("countryName"),
                "state": subject.get("stateOrProvinceName"),
                "locality": subject.get("localityName")
            },
            "issuer": {
                "common_name": issuer.get("commonName"),
                "organization": issuer.get("organizationName"),
                "country": issuer.get("countryName")
            },
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "is_valid": not_before <= now <= not_after,
                "days_until_expiry": days_until_expiry,
                "is_expired": days_until_expiry < 0,
                "expires_soon": 0 <= days_until_expiry <= 30
            },
            "serial_number": format(cert.serial_number, 'x'),
            "version": cert.version.name,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "subject_alternative_names": san_list,
            "is_self_signed": is_self_signed,
            "fingerprints": {
                "sha256": fingerprint_sha256,
                "sha1": fingerprint_sha1
            }
        }
    
    def _check_security_issues(
        self,
        cert_info: Dict[str, Any],
        protocol: str,
        cipher: tuple
    ) -> List[Dict[str, Any]]:
        """Check for security issues in the certificate and connection."""
        issues = []
        
        weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
        if protocol in weak_protocols:
            issues.append({
                "type": "weak_protocol",
                "severity": "high",
                "description": f"Weak TLS protocol in use: {protocol}",
                "recommendation": "Upgrade to TLS 1.2 or TLS 1.3"
            })
        
        if cipher:
            cipher_name = cipher[0]
            for weak in self.WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    issues.append({
                        "type": "weak_cipher",
                        "severity": "high",
                        "description": f"Weak cipher suite: {cipher_name}",
                        "recommendation": "Use strong cipher suites (AES-GCM, ChaCha20)"
                    })
                    break
        
        if cert_info.get("is_self_signed"):
            issues.append({
                "type": "self_signed",
                "severity": "medium",
                "description": "Certificate is self-signed",
                "recommendation": "Use a certificate from a trusted CA"
            })
        
        validity = cert_info.get("validity", {})
        if validity.get("is_expired"):
            issues.append({
                "type": "expired",
                "severity": "critical",
                "description": "Certificate has expired",
                "recommendation": "Renew the certificate immediately"
            })
        elif validity.get("expires_soon"):
            issues.append({
                "type": "expiring_soon",
                "severity": "warning",
                "description": f"Certificate expires in {validity.get('days_until_expiry')} days",
                "recommendation": "Plan for certificate renewal"
            })
        
        sig_algo = cert_info.get("signature_algorithm", "")
        if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
            issues.append({
                "type": "weak_signature",
                "severity": "high",
                "description": f"Weak signature algorithm: {sig_algo}",
                "recommendation": "Use SHA-256 or stronger for signatures"
            })
        
        return issues
