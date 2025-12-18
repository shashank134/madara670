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
from cryptography.x509.oid import ExtensionOID, NameOID

from .base import BaseModule


class SSLModule(BaseModule):
    """
    Module for TLS/SSL certificate analysis.
    
    Analyzes:
    - Certificate chain
    - Issuer information
    - Validity period
    - Expiry status
    - Subject Alternative Names
    - Weak protocols/ciphers
    - Self-signed detection
    - Key size and algorithm
    - Certificate transparency
    - OCSP and CRL information
    """
    
    name = "ssl"
    description = "TLS/SSL certificate analysis"
    is_active = False
    
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "RC2", "IDEA"
    ]
    
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
    
    KNOWN_CAS = {
        "Let's Encrypt": ["Let's Encrypt", "R3", "E1", "ISRG Root"],
        "DigiCert": ["DigiCert", "GeoTrust", "RapidSSL", "Thawte"],
        "Sectigo": ["Sectigo", "Comodo", "COMODO"],
        "GlobalSign": ["GlobalSign"],
        "GoDaddy": ["Go Daddy", "GoDaddy", "Starfield"],
        "Amazon": ["Amazon", "AWS"],
        "Cloudflare": ["Cloudflare"],
        "ZeroSSL": ["ZeroSSL"],
        "Google Trust Services": ["Google Trust Services", "GTS"],
        "Microsoft": ["Microsoft"],
        "Entrust": ["Entrust"],
        "IdenTrust": ["IdenTrust", "DST Root"],
    }
    
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
                cert_info = self._parse_certificate(cert, cert_dict, hostname)
            else:
                cert_info = {}
            
            cipher_analysis = self._analyze_cipher(cipher)
            protocol_analysis = self._analyze_protocol(protocol)
            
            cert_info["connection"] = {
                "protocol": protocol,
                "protocol_version": self._get_protocol_version(protocol),
                "is_secure_protocol": protocol not in self.WEAK_PROTOCOLS,
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "cipher_analysis": cipher_analysis,
                "protocol_analysis": protocol_analysis,
            }
            
            cert_info["security_issues"] = self._check_security_issues(
                cert_info, protocol, cipher
            )
            
            cert_info["security_grade"] = self._calculate_security_grade(cert_info)
            
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
        cert_dict: Dict,
        hostname: str
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
        cert_lifetime = (not_after - not_before).days
        
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value
        
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value
        
        san_list = []
        wildcard_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(name.value)
                    if name.value.startswith("*."):
                        wildcard_domains.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_list.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        
        is_self_signed = cert.issuer == cert.subject
        
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
        fingerprint_md5 = cert.fingerprint(hashes.MD5()).hex()
        
        key_info = self._get_key_info(cert)
        
        issuer_ca = self._identify_ca(issuer)
        
        ocsp_urls = []
        crl_urls = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia.value:
                if desc.access_method._name == "OCSP":
                    ocsp_urls.append(desc.access_location.value)
                elif desc.access_method._name == "caIssuers":
                    pass
        except x509.ExtensionNotFound:
            pass
        
        try:
            crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for point in crl.value:
                if point.full_name:
                    for name in point.full_name:
                        if hasattr(name, 'value'):
                            crl_urls.append(name.value)
        except x509.ExtensionNotFound:
            pass
        
        basic_constraints = None
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            basic_constraints = {
                "is_ca": bc.value.ca,
                "path_length": bc.value.path_length
            }
        except x509.ExtensionNotFound:
            pass
        
        key_usage = []
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if ku.value.digital_signature:
                key_usage.append("Digital Signature")
            if ku.value.key_encipherment:
                key_usage.append("Key Encipherment")
            if ku.value.content_commitment:
                key_usage.append("Content Commitment")
            if ku.value.data_encipherment:
                key_usage.append("Data Encipherment")
            if ku.value.key_agreement:
                key_usage.append("Key Agreement")
            if ku.value.key_cert_sign:
                key_usage.append("Certificate Signing")
            if ku.value.crl_sign:
                key_usage.append("CRL Signing")
        except x509.ExtensionNotFound:
            pass
        
        ext_key_usage = []
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            for usage in eku.value:
                ext_key_usage.append(usage._name)
        except x509.ExtensionNotFound:
            pass
        
        hostname_valid = self._check_hostname_match(hostname, subject.get("commonName"), san_list)
        
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
                "country": issuer.get("countryName"),
                "organizational_unit": issuer.get("organizationalUnitName"),
                "identified_ca": issuer_ca,
            },
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "is_valid": not_before <= now <= not_after,
                "days_until_expiry": days_until_expiry,
                "is_expired": days_until_expiry < 0,
                "expires_soon": 0 <= days_until_expiry <= 30,
                "certificate_lifetime_days": cert_lifetime,
            },
            "serial_number": format(cert.serial_number, 'x'),
            "version": cert.version.name,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "signature_hash": self._get_signature_hash(cert.signature_algorithm_oid._name),
            "key_info": key_info,
            "subject_alternative_names": san_list,
            "san_count": len(san_list),
            "wildcard_domains": wildcard_domains,
            "has_wildcard": len(wildcard_domains) > 0,
            "is_self_signed": is_self_signed,
            "hostname_valid": hostname_valid,
            "fingerprints": {
                "sha256": fingerprint_sha256,
                "sha1": fingerprint_sha1,
                "md5": fingerprint_md5,
            },
            "extensions": {
                "basic_constraints": basic_constraints,
                "key_usage": key_usage,
                "extended_key_usage": ext_key_usage,
                "ocsp_urls": ocsp_urls,
                "crl_urls": crl_urls,
                "has_ocsp": len(ocsp_urls) > 0,
                "has_crl": len(crl_urls) > 0,
            }
        }
    
    def _get_key_info(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Extract public key information."""
        public_key = cert.public_key()
        key_type = type(public_key).__name__
        
        key_size = None
        curve = None
        
        if hasattr(public_key, 'key_size'):
            key_size = public_key.key_size
        
        if 'EC' in key_type:
            if hasattr(public_key, 'curve'):
                curve = public_key.curve.name
            key_type = "Elliptic Curve"
        elif 'RSA' in key_type:
            key_type = "RSA"
        elif 'DSA' in key_type:
            key_type = "DSA"
        elif 'Ed25519' in key_type:
            key_type = "Ed25519"
            key_size = 256
        elif 'Ed448' in key_type:
            key_type = "Ed448"
            key_size = 448
        
        is_strong = True
        weakness_reason = None
        
        if key_type == "RSA" and key_size and key_size < 2048:
            is_strong = False
            weakness_reason = f"RSA key size {key_size} bits is too small (minimum 2048)"
        elif key_type == "Elliptic Curve" and key_size and key_size < 256:
            is_strong = False
            weakness_reason = f"EC key size {key_size} bits is too small (minimum 256)"
        elif key_type == "DSA":
            is_strong = False
            weakness_reason = "DSA keys are deprecated"
        
        return {
            "type": key_type,
            "size": key_size,
            "curve": curve,
            "is_strong": is_strong,
            "weakness_reason": weakness_reason,
        }
    
    def _identify_ca(self, issuer: Dict[str, str]) -> Optional[str]:
        """Identify the Certificate Authority."""
        issuer_str = " ".join(str(v) for v in issuer.values() if v)
        
        for ca_name, identifiers in self.KNOWN_CAS.items():
            for identifier in identifiers:
                if identifier.lower() in issuer_str.lower():
                    return ca_name
        return None
    
    def _get_signature_hash(self, algorithm: str) -> str:
        """Extract hash algorithm from signature algorithm."""
        algo_lower = algorithm.lower()
        if "sha256" in algo_lower:
            return "SHA-256"
        elif "sha384" in algo_lower:
            return "SHA-384"
        elif "sha512" in algo_lower:
            return "SHA-512"
        elif "sha1" in algo_lower:
            return "SHA-1 (Weak)"
        elif "md5" in algo_lower:
            return "MD5 (Weak)"
        return algorithm
    
    def _get_protocol_version(self, protocol: str) -> str:
        """Get human-readable protocol version."""
        versions = {
            "TLSv1.3": "TLS 1.3 (Modern)",
            "TLSv1.2": "TLS 1.2 (Recommended)",
            "TLSv1.1": "TLS 1.1 (Deprecated)",
            "TLSv1.0": "TLS 1.0 (Deprecated)",
            "TLSv1": "TLS 1.0 (Deprecated)",
            "SSLv3": "SSL 3.0 (Insecure)",
            "SSLv2": "SSL 2.0 (Insecure)",
        }
        return versions.get(protocol, protocol)
    
    def _analyze_cipher(self, cipher: tuple) -> Dict[str, Any]:
        """Analyze cipher suite strength."""
        if not cipher:
            return {"analyzed": False}
        
        cipher_name = cipher[0]
        cipher_bits = cipher[2] if len(cipher) > 2 else None
        
        is_weak = False
        weakness_reasons = []
        
        for weak in self.WEAK_CIPHERS:
            if weak.upper() in cipher_name.upper():
                is_weak = True
                weakness_reasons.append(f"Uses weak algorithm: {weak}")
        
        if cipher_bits and cipher_bits < 128:
            is_weak = True
            weakness_reasons.append(f"Key length too short: {cipher_bits} bits")
        
        has_pfs = "DHE" in cipher_name or "ECDHE" in cipher_name
        uses_aead = "GCM" in cipher_name or "CHACHA" in cipher_name or "CCM" in cipher_name
        
        return {
            "analyzed": True,
            "name": cipher_name,
            "bits": cipher_bits,
            "is_weak": is_weak,
            "weakness_reasons": weakness_reasons,
            "has_perfect_forward_secrecy": has_pfs,
            "uses_aead": uses_aead,
            "is_recommended": has_pfs and uses_aead and not is_weak,
        }
    
    def _analyze_protocol(self, protocol: str) -> Dict[str, Any]:
        """Analyze TLS protocol version."""
        is_weak = protocol in self.WEAK_PROTOCOLS
        is_modern = protocol == "TLSv1.3"
        is_recommended = protocol in ["TLSv1.2", "TLSv1.3"]
        
        return {
            "version": protocol,
            "is_weak": is_weak,
            "is_modern": is_modern,
            "is_recommended": is_recommended,
        }
    
    def _check_hostname_match(self, hostname: str, cn: Optional[str], san_list: List[str]) -> bool:
        """Check if hostname matches certificate."""
        hostname_lower = hostname.lower()
        
        if cn and self._hostname_matches(hostname_lower, cn.lower()):
            return True
        
        for san in san_list:
            if self._hostname_matches(hostname_lower, san.lower()):
                return True
        
        return False
    
    def _hostname_matches(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches pattern (including wildcards)."""
        if pattern == hostname:
            return True
        
        if pattern.startswith("*."):
            pattern_suffix = pattern[2:]
            if hostname.endswith("." + pattern_suffix):
                prefix = hostname[:-len(pattern_suffix)-1]
                if "." not in prefix:
                    return True
        
        return False
    
    def _check_security_issues(
        self,
        cert_info: Dict[str, Any],
        protocol: str,
        cipher: tuple
    ) -> List[Dict[str, Any]]:
        """Check for security issues in the certificate and connection."""
        issues = []
        
        if protocol in self.WEAK_PROTOCOLS:
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
        
        key_info = cert_info.get("key_info", {})
        if not key_info.get("is_strong", True):
            issues.append({
                "type": "weak_key",
                "severity": "high",
                "description": key_info.get("weakness_reason", "Weak key detected"),
                "recommendation": "Use RSA 2048+ or ECDSA 256+ bit keys"
            })
        
        if not cert_info.get("hostname_valid", True):
            issues.append({
                "type": "hostname_mismatch",
                "severity": "high",
                "description": "Certificate does not match the hostname",
                "recommendation": "Obtain a certificate that includes the correct hostname"
            })
        
        return issues
    
    def _calculate_security_grade(self, cert_info: Dict[str, Any]) -> str:
        """Calculate an overall security grade."""
        issues = cert_info.get("security_issues", [])
        connection = cert_info.get("connection", {})
        
        critical_count = sum(1 for i in issues if i.get("severity") == "critical")
        high_count = sum(1 for i in issues if i.get("severity") == "high")
        medium_count = sum(1 for i in issues if i.get("severity") == "medium")
        warning_count = sum(1 for i in issues if i.get("severity") == "warning")
        
        if critical_count > 0:
            return "F"
        
        if high_count > 0:
            return "D"
        
        protocol = connection.get("protocol", "")
        cipher_analysis = connection.get("cipher_analysis", {})
        
        if protocol == "TLSv1.3" and cipher_analysis.get("is_recommended"):
            if medium_count == 0 and warning_count == 0:
                return "A+"
            elif medium_count == 0:
                return "A"
            else:
                return "A-"
        
        if protocol == "TLSv1.2":
            if medium_count == 0 and warning_count == 0:
                return "A"
            elif medium_count == 0:
                return "B+"
            else:
                return "B"
        
        if medium_count > 0:
            return "C"
        
        return "B"
