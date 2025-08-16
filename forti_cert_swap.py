#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# forti_cert_swap.py — Upload/rotate a certificate on FortiGate and bind it to GUI, SSL-VPN, and FTM.
#
# Features:
#  - YAML config (-C/--config) merging with CLI arguments
#  - Automatic cert naming from CN + expiry date, or override with --name
#  - GLOBAL vs VDOM certificate store selection
#  - Dry-run mode for testing without changes
#  - Prune older certificates with same base name after successful bindings (only unbound certificates)
#  - Rebind-only mode: --rebind <existing-cert-name>
#  - Certificate-only mode: --cert-only (upload certificate without service bindings)
#  - SSL inspection certificate mode: --ssl-inspection-certificate (automated SSL inspection profile rebinding)
#  - Robust retry policy with intelligent error handling
#  - TLS verification with --insecure option for self-signed certificates
#  - Enhanced logging with --log FILE and --log-level {standard,debug}
#  - Comprehensive certificate chain validation and display
#  - Operation correlation IDs for debugging
#  - Sensitive data scrubbing in logs for security
#
# Version: 1.10.0
#
# MIT License
# Copyright (c) 2025 CyB0rgg <dev@bluco.re>

import argparse
import json
import os
import sys
import re
import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List, Union
from dataclasses import dataclass
from enum import Enum

# Dependency checking with better error messages
missing_msgs = []

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
except ImportError as e:
    missing_msgs.append(("[cryptography]", "pip3 install cryptography", "sudo apt-get install python3-cryptography", str(e)))

try:
    import yaml as yml
except ImportError:
    yml = None

try:
    import requests
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
except ImportError as e:
    missing_msgs.append(("[requests]", "pip3 install requests", "sudo apt-get install python3-requests", str(e)))

if missing_msgs:
    for pkg, pip_hint, apt_hint, error in missing_msgs:
        print(f"[!] Missing required Python module: {pkg}")
        print(f"    pip:   {pip_hint}")
        print(f"    apt:   {apt_hint}")
        print(f"    error: {error}")
    if any("[cryptography]" in m[0] or "[requests]" in m[0] for m in missing_msgs):
        sys.exit(1)

API_PREFIX = "/api/v2"
VERSION = "1.10.0"

# ---------------------------
# Configuration & Validation
# ---------------------------

class LogLevel(Enum):
    """Supported log levels."""
    STANDARD = "standard"
    DEBUG = "debug"

@dataclass
class Config:
    """Configuration container with validation."""
    host: str
    port: int
    token: str
    cert: Optional[str] = None
    key: Optional[str] = None
    name: Optional[str] = None
    vdom: Optional[str] = None
    insecure: bool = False
    dry_run: bool = False
    prune: bool = False
    timeout_connect: int = 5
    timeout_read: int = 30
    log: Optional[str] = None
    log_level: str = "standard"
    rebind: Optional[str] = None
    cert_only: bool = False
    ssl_inspection_cert: bool = False

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()

    def _validate(self):
        """Validate configuration values."""
        if not self.host:
            raise ValueError("Host is required")
        
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError(f"Port must be an integer between 1-65535, got: {self.port}")
        
        if not self.token:
            raise ValueError("Token is required")
        
        if self.timeout_connect <= 0:
            raise ValueError(f"timeout_connect must be positive, got: {self.timeout_connect}")
        
        if self.timeout_read <= 0:
            raise ValueError(f"timeout_read must be positive, got: {self.timeout_read}")
        
        if self.log_level not in [level.value for level in LogLevel]:
            raise ValueError(f"log_level must be one of {[level.value for level in LogLevel]}, got: {self.log_level}")
        
        # Expand paths
        if self.log:
            self.log = str(Path(self.log).expanduser().resolve())
        if self.cert:
            self.cert = str(Path(self.cert).expanduser().resolve())
        if self.key:
            self.key = str(Path(self.key).expanduser().resolve())

    @property
    def store(self) -> str:
        """Return certificate store type."""
        return "GLOBAL" if not self.vdom else "VDOM"

# ---------------------------
# Custom Exceptions
# ---------------------------

class FortiCertSwapError(Exception):
    """Base exception for FortiCertSwap errors."""
    pass

class ConfigurationError(FortiCertSwapError):
    """Configuration validation error."""
    pass

class CertificateError(FortiCertSwapError):
    """Certificate processing error."""
    pass

class APIError(FortiCertSwapError):
    """FortiGate API error."""
    pass

# ---------------------------
# Logging (improved)
# ---------------------------

class Logger:
    """Enhanced logger with operation tracking and better scrubbing."""
    
    def __init__(self, path: Optional[str], level: LogLevel):
        self.path = path
        self.level = level
        self.fp = None
        self.operation_id: Optional[str] = None
        
        if self.path:
            self._open_log_file()

    def _open_log_file(self):
        """Open log file with proper error handling."""
        try:
            # Ensure directory exists
            log_path = Path(self.path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self.fp = open(log_path, "a", encoding="utf-8")
        except Exception as e:
            print(f"[!] Could not open log file '{self.path}': {e}")
            self.fp = None

    def set_operation_id(self, operation_id: str):
        """Set operation ID for correlation."""
        self.operation_id = operation_id

    def _ts(self) -> str:
        """Generate timestamp."""
        return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _scrub(self, s: Union[str, Dict, Any]) -> str:
        """Scrub sensitive information from log messages."""
        if not isinstance(s, str):
            try:
                s = json.dumps(s, default=str)
            except Exception:
                s = str(s)
        
        # Enhanced scrubbing patterns
        patterns = [
            # API tokens
            (r"(Bearer\s+)[A-Za-z0-9._\-]+=*", r"\1<REDACTED>"),
            (r"([\"']token[\"']\s*:\s*[\"']).+?([\"'])", r"\1<REDACTED>\2"),
            (r"(Authorization:\s*Bearer\s+)[^\s]+", r"\1<REDACTED>"),
            # Private keys
            (r"(private-key[\"']\s*:\s*[\"']).+?([\"'])", r"\1<REDACTED>\2"),
            (r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", "<PRIVATE-KEY-REDACTED>"),
            (r"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----", "<RSA-PRIVATE-KEY-REDACTED>"),
            # Certificates (keep structure but redact content)
            (r"(certificate[\"']\s*:\s*[\"']).+?([\"'])", r"\1<CERTIFICATE-REDACTED>\2"),
            (r"-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----", "<CERTIFICATE-REDACTED>"),
        ]
        
        for pattern, replacement in patterns:
            s = re.sub(pattern, replacement, s, flags=re.IGNORECASE | re.DOTALL)
        
        return s

    def _format_message(self, level: str, msg: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Format log message with operation correlation."""
        timestamp = self._ts()
        
        # Add operation ID if available
        op_prefix = f"[{self.operation_id[:8]}] " if self.operation_id else ""
        
        # Format based on log level
        if self.level == LogLevel.DEBUG and context:
            # Debug: Include full context
            context_str = f" | context={json.dumps(context, default=str)}"
            formatted_msg = f"{op_prefix}{msg}{context_str}"
        else:
            # Standard: Clean message only
            formatted_msg = f"{op_prefix}{msg}"
        
        return f"{timestamp} {level.upper()} {self._scrub(formatted_msg)}"

    def _write(self, level: str, msg: str, context: Optional[Dict[str, Any]] = None):
        """Write log entry."""
        if not self.fp:
            return
        
        try:
            line = self._format_message(level, msg, context) + "\n"
            self.fp.write(line)
            self.fp.flush()
        except Exception:
            # Fail silently for logging errors
            pass

    def info(self, msg: str, context: Optional[Dict[str, Any]] = None, also_stdout: bool = False):
        """Log info message."""
        self._write("info", msg, context)
        if also_stdout:
            op_prefix = f"[{self.operation_id[:8]}] " if self.operation_id else ""
            print(f"{op_prefix}{msg}")

    def warn(self, msg: str, context: Optional[Dict[str, Any]] = None, also_stdout: bool = False):
        """Log warning message."""
        self._write("warn", msg, context)
        if also_stdout:
            op_prefix = f"[{self.operation_id[:8]}] " if self.operation_id else ""
            print(f"[!] {op_prefix}{msg}")

    def error(self, msg: str, context: Optional[Dict[str, Any]] = None, also_stdout: bool = False):
        """Log error message."""
        self._write("error", msg, context)
        if also_stdout:
            op_prefix = f"[{self.operation_id[:8]}] " if self.operation_id else ""
            print(f"[!] {op_prefix}{msg}", file=sys.stderr)

    def debug(self, msg: str, context: Optional[Dict[str, Any]] = None, also_stdout: bool = False):
        """Log debug message."""
        if self.level == LogLevel.DEBUG:
            self._write("debug", msg, context)
            if also_stdout:
                op_prefix = f"[{self.operation_id[:8]}] " if self.operation_id else ""
                print(f"[DEBUG] {op_prefix}{msg}")

    def close(self):
        """Close log file."""
        if self.fp:
            self.fp.close()
            self.fp = None

# ---------------------------
# Certificate Processing
# ---------------------------

class CertificateProcessor:
    """Handle certificate parsing and validation."""
    
    @staticmethod
    def load_file(path: str) -> str:
        """Load file content with validation."""
        file_path = Path(path)
        
        if not file_path.exists():
            raise CertificateError(f"File not found: {path}")
        
        if not file_path.is_file():
            raise CertificateError(f"Path is not a file: {path}")
        
        try:
            with open(file_path, "rb") as f:
                content = f.read().decode("utf-8", errors="ignore")
            
            if not content.strip():
                raise CertificateError(f"File is empty: {path}")
            
            return content
        except UnicodeDecodeError as e:
            raise CertificateError(f"File encoding error {path}: {e}")
        except Exception as e:
            # Handle the case where mock_open returns string instead of bytes
            if "'str' object has no attribute 'decode'" in str(e):
                # This happens in tests with mock_open - return the mocked content directly
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                    if not content.strip():
                        raise CertificateError(f"File is empty: {path}")
                    return content
                except Exception as inner_e:
                    raise CertificateError(f"Failed to read file {path}: {inner_e}")
            raise CertificateError(f"Failed to read file {path}: {e}")

    @staticmethod
    def validate_certificate_format(cert_pem: str) -> None:
        """Validate certificate PEM format."""
        if "BEGIN CERTIFICATE" not in cert_pem or "END CERTIFICATE" not in cert_pem:
            raise CertificateError("Invalid certificate format: missing PEM markers")
        
        # Try to parse the first certificate
        try:
            chunks = CertificateProcessor._split_pem_chain(cert_pem)
            if not chunks:
                raise CertificateError("No valid certificates found in PEM data")
            
            # Validate first certificate can be parsed
            x509.load_pem_x509_certificate(chunks[0].encode("utf-8"), default_backend())
        except Exception as e:
            raise CertificateError(f"Invalid certificate format: {e}")

    @staticmethod
    def validate_private_key_format(key_pem: str) -> None:
        """Validate private key PEM format."""
        key_markers = ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"]
        
        if not any(marker in key_pem for marker in key_markers):
            raise CertificateError("Invalid private key format: missing PEM markers")

    @staticmethod
    def _split_pem_chain(pem: str) -> List[str]:
        """Split PEM chain into individual certificates."""
        parts = []
        current = []
        
        for line in pem.splitlines():
            if "BEGIN CERTIFICATE" in line:
                current = [line]
            elif "END CERTIFICATE" in line:
                current.append(line)
                parts.append("\n".join(current) + "\n")
                current = []
            elif current:
                current.append(line)
        
        return parts if parts else [pem]

    @staticmethod
    def summarize_chain(cert_pem: str) -> str:
        """Generate certificate chain summary."""
        try:
            chunks = CertificateProcessor._split_pem_chain(cert_pem)
            lines = ["[*] Certificate chain summary:"]
            
            for idx, chunk in enumerate(chunks):
                try:
                    cert = x509.load_pem_x509_certificate(chunk.encode("utf-8"), default_backend())
                    not_after = cert.not_valid_after
                    
                    # Get CN or first SAN
                    cn = CertificateProcessor._extract_cn_or_san(cert)
                    
                    # Calculate days until expiry
                    now = datetime.datetime.utcnow()
                    days_left = (not_after - now).days
                    
                    # Format expiry information
                    if days_left < 0:
                        expiry_info = f"EXPIRED {abs(days_left)} days ago"
                    elif days_left == 0:
                        expiry_info = "EXPIRES TODAY"
                    elif days_left == 1:
                        expiry_info = "expires tomorrow"
                    elif days_left <= 30:
                        expiry_info = f"expires in {days_left} days"
                    else:
                        expiry_info = f"expires {not_after.strftime('%Y-%m-%d')} ({days_left} days)"
                    
                    tag = "[leaf]" if idx == 0 else f"[ca-{idx}]"
                    lines.append(f"    {tag} {cn} - {expiry_info}")
                except Exception:
                    lines.append(f"    [cert-{idx}] <unparsed certificate>")
            
            return "\n".join(lines)
        except Exception as e:
            return f"[!] Failed to summarize certificate chain: {e}"

    @staticmethod
    def _extract_cn_or_san(cert: x509.Certificate) -> str:
        """Extract CN or first SAN from certificate."""
        # Try CN first
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
        
        # Fall back to SAN
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = san.get_values_for_type(x509.DNSName)
            return dns_names[0] if dns_names else "(no CN/SAN)"
        except Exception:
            return "(no CN/SAN)"

    @staticmethod
    def planned_cert_name(cert_pem: str, override: Optional[str]) -> str:
        """Generate planned certificate name."""
        if override:
            return override
        
        try:
            leaf = CertificateProcessor._split_pem_chain(cert_pem)[0]
            cert = x509.load_pem_x509_certificate(leaf.encode("utf-8"), default_backend())
            
            base = CertificateProcessor._extract_cn_or_san(cert)
            if base == "(no CN/SAN)":
                base = "cert"
            
            # Clean up base name
            base = re.sub(r"^\*\.", "", base.strip())
            base = re.sub(r"[^A-Za-z0-9._-]", "-", base)
            
            exp = cert.not_valid_after.strftime("%Y%m%d")
            return f"{base}-{exp}"
        except Exception as e:
            raise CertificateError(f"Failed to generate certificate name: {e}")

    @staticmethod
    def base_from_name(name: str) -> str:
        """Extract base name from certificate name."""
        match = re.match(r"^(.*)-\d{8}$", name)
        return match.group(1) if match else name

# ---------------------------
# Configuration Management
# ---------------------------

class ConfigManager:
    """Handle configuration loading and validation."""
    
    @staticmethod
    def load_yaml_config(path: Optional[str]) -> Dict[str, Any]:
        """Load YAML configuration file."""
        if not path:
            return {}
        
        if yml is None:
            raise ConfigurationError(
                "YAML config requested but PyYAML is not installed.\n"
                "    pip:  pip3 install pyyaml\n"
                "    apt:  sudo apt-get install python3-yaml"
            )
        
        config_path = Path(path).expanduser().resolve()
        
        if not config_path.exists():
            raise ConfigurationError(f"Config file not found: {path}")
        
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yml.safe_load(f) or {}
            
            if not isinstance(config, dict):
                raise ConfigurationError("Config file must contain a YAML dictionary")
            
            return config
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file {path}: {e}")

    @staticmethod
    def merge_args_with_config(args: argparse.Namespace, cfg: Dict[str, Any]) -> Config:
        """Merge CLI arguments with config file."""
        # Convert args to dict, handling None values and excluding internal args
        args_dict = {}
        # Exclude internal argparse parameters that shouldn't be merged
        exclude_keys = {'config'}  # The -C/--config parameter is just the filename
        
        for key, value in vars(args).items():
            if key in exclude_keys:
                continue  # Skip internal parameters
            if value is not None and value != "" and value != 0 and value is not False:
                args_dict[key] = value
        
        # Merge config with args (args take precedence)
        merged = {**cfg, **args_dict}
        
        try:
            return Config(**merged)
        except TypeError as e:
            # Handle unknown config keys gracefully
            valid_keys = set(Config.__annotations__.keys())
            provided_keys = set(merged.keys())
            unknown_keys = provided_keys - valid_keys
            
            if unknown_keys:
                print(f"[!] Warning: Unknown config keys ignored: {', '.join(unknown_keys)}")
                # Filter out unknown keys
                filtered = {k: v for k, v in merged.items() if k in valid_keys}
                return Config(**filtered)
            else:
                raise ConfigurationError(f"Configuration error: {e}")

# ---------------------------
# FortiGate API Client
# ---------------------------

def _scope_params(scope: str, vdom: Optional[str]) -> Dict[str, Any]:
    """Generate scope parameters for API calls."""
    if scope == "global":
        return {"scope": "global"}
    return {"vdom": vdom or "root"}

class FortiAPI:
    """FortiGate API client with improved error handling."""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.base_url = f"https://{config.host}:{config.port}{API_PREFIX}"
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        """Build requests session with retry policy."""
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {self.config.token}"})
        
        # Configure retry policy
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]),
            raise_on_status=False,
        )
        
        adapter = requests.adapters.HTTPAdapter(max_retries=retry, pool_maxsize=10)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        if self.config.insecure:
            urllib3.disable_warnings(InsecureRequestWarning)
        
        return session

    def _req(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
             json_body: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """Make API request with logging."""
        url = f"{self.base_url}{path}"
        
        # Log request (scrub sensitive data)
        log_json = json_body.copy() if json_body else {}
        if log_json and 'private-key' in log_json:
            log_json['private-key'] = '<REDACTED>'
        
        # Extract meaningful endpoint from URL
        if "/api/v2/cmdb/" in url:
            endpoint = url.split("/api/v2/cmdb/")[1].split("?")[0]
        else:
            endpoint = url
        
        self.logger.debug(
            f"HTTP {method} {endpoint}",
            context={
                "params": params or {},
                "json": log_json,
                "verify": not self.config.insecure
            }
        )
        
        try:
            response = self.session.request(
                method, url,
                params=params or {},
                json=json_body,
                files=files,
                verify=not self.config.insecure,
                timeout=(self.config.timeout_connect, self.config.timeout_read)
            )
            
            code = response.status_code
            
            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text}
            
            # Log response with better formatting
            if "/api/v2/cmdb/" in url:
                endpoint = url.split("/api/v2/cmdb/")[1].split("?")[0]
            else:
                endpoint = path
            
            if code >= 400:
                # Log errors with more context
                if code == 500 and isinstance(data, dict) and 'error' in data:
                    forti_error = data.get('error', 'unknown')
                    self.logger.debug(f"HTTP {method} {endpoint} -> {code} (FortiGate error: {forti_error})", context=data)
                else:
                    self.logger.debug(f"HTTP {method} {endpoint} -> {code}", context=data)
            else:
                # Success responses - minimal logging
                self.logger.debug(f"HTTP {method} {endpoint} -> {code}")
            
            return code, data
            
        except requests.exceptions.SSLError as e:
            error_msg = "certificate verify failed" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "TLS/SSL error"
            raise APIError(f"TLS verification failed: {error_msg}. Consider using --insecure if expected.") from e
        except requests.exceptions.Timeout as e:
            raise APIError(f"Request timeout: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise APIError(f"Connection error: {e}") from e
        except Exception as e:
            raise APIError(f"Request failed: {e}") from e

    def cmdb_get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """GET request to CMDB API."""
        return self._req("GET", f"/cmdb/{path}", params=params)

    def cmdb_post(self, path: str, json_body: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """POST request to CMDB API."""
        return self._req("POST", f"/cmdb/{path}", params=params, json_body=json_body)

    def cmdb_put(self, path: str, json_body: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """PUT request to CMDB API."""
        return self._req("PUT", f"/cmdb/{path}", params=params, json_body=json_body)

    def cmdb_delete(self, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """DELETE request to CMDB API."""
        return self._req("DELETE", f"/cmdb/{path}", params=params)

# ---------------------------
# Certificate Operations
# ---------------------------

class CertificateOperations:
    """Handle certificate operations on FortiGate."""
    
    def __init__(self, api: FortiAPI, config: Config, logger: Logger):
        self.api = api
        self.config = config
        self.logger = logger

    def upload_or_update_cert(self, name: str, cert_pem: str, key_pem: str) -> Tuple[str, Any]:
        """Upload or update certificate on FortiGate."""
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        payload = {
            "name": name,
            "certificate": cert_pem,
            "private-key": key_pem,
            "range": self.config.store.lower()
        }
        
        if self.config.dry_run:
            self.logger.info(f"DRYRUN: would POST vpn.certificate/local name={name} store={self.config.store}")
            return "dry_run", {"would_post": True, "path": "vpn.certificate/local", "params": params}
        
        # Try POST first (create new)
        code, data = self.api.cmdb_post("vpn.certificate/local", payload, params=params)
        if code == 200:
            return "created", data
        
        # Try PUT (update existing)
        code, data = self.api.cmdb_put(f"vpn.certificate/local/{name}", payload, params=params)
        if code == 200:
            return "updated", data
        
        return "error", {"http_status": code, "detail": data}

    def cert_only_upload(self, name: str, cert_pem: str, key_pem: str) -> Tuple[str, Any]:
        """Upload or update certificate only, without any service bindings."""
        # Use the same logic as the main script: try POST first, then PUT
        return self.upload_or_update_cert(name, cert_pem, key_pem)

    def bind_gui(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        """Bind certificate to GUI."""
        payload = {"admin-server-cert": name}
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        code, data = self.api.cmdb_put("system/global", payload, params=params)
        return (code == 200), {"http_status": code, "detail": data}

    def bind_ssl_vpn(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        """Bind certificate to SSL VPN."""
        payload = {"servercert": name}
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        code, data = self.api.cmdb_put("vpn.ssl/settings", payload, params=params)
        return (code == 200), {"http_status": code, "detail": data}

    def bind_ftm(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        """Bind certificate to FTM."""
        payload = {"server-cert": name}
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        code, data = self.api.cmdb_put("system/ftm-push", payload, params=params)
        return (code == 200), {"http_status": code, "detail": data}

    def list_local_certs(self) -> List[str]:
        """List local certificates."""
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        code, data = self.api.cmdb_get("vpn.certificate/local", params=params)
        
        names = []
        if code == 200 and isinstance(data, dict):
            results = data.get("results") or data.get("data") or []
            for item in results:
                name = item.get("name")
                if isinstance(name, str):
                    names.append(name)
        
        return names

    def get_ssl_inspection_certificates(self) -> List[str]:
        """Get certificates currently used in SSL inspection profiles."""
        mappings = self.get_ssl_inspection_profile_mappings()
        return list(mappings.keys())

    def get_ssl_inspection_profile_mappings(self) -> Dict[str, List[str]]:
        """Get complete mapping of certificates to SSL inspection profiles that use them."""
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        
        # Get SSL inspection profiles
        code, data = self.api.cmdb_get("firewall/ssl-ssh-profile", params=params)
        
        cert_to_profiles = {}  # cert_name -> [profile_names]
        if code == 200 and isinstance(data, dict):
            results = data.get("results") or data.get("data") or []
            for profile in results:
                profile_name = profile.get("name", "unknown")
                
                # Check server-cert array (for replace mode)
                server_certs = profile.get("server-cert", [])
                if isinstance(server_certs, list):
                    for cert_obj in server_certs:
                        if isinstance(cert_obj, dict):
                            cert_name = cert_obj.get("name")
                            if cert_name:
                                if cert_name not in cert_to_profiles:
                                    cert_to_profiles[cert_name] = []
                                if profile_name not in cert_to_profiles[cert_name]:
                                    cert_to_profiles[cert_name].append(profile_name)
                                self.logger.debug(f"Found SSL inspection cert: {cert_name} in profile: {profile_name}")
                
                # Check ssl-server array (alternative location)
                ssl_servers = profile.get("ssl-server", [])
                if isinstance(ssl_servers, list):
                    for server_obj in ssl_servers:
                        if isinstance(server_obj, dict):
                            cert_name = server_obj.get("name")
                            if cert_name:
                                if cert_name not in cert_to_profiles:
                                    cert_to_profiles[cert_name] = []
                                if profile_name not in cert_to_profiles[cert_name]:
                                    cert_to_profiles[cert_name].append(profile_name)
                                self.logger.debug(f"Found SSL server cert: {cert_name} in profile: {profile_name}")
        
        return cert_to_profiles

    def suggest_ssl_inspection_cert_name(self, planned_name: str, cert_pem: str) -> Optional[str]:
        """Suggest existing SSL inspection certificate name based on domain matching."""
        try:
            # Extract domain from the certificate we're trying to upload
            upload_domain = self._extract_domain_from_cert(cert_pem)
            if not upload_domain:
                self.logger.debug("Could not extract domain from certificate")
                return None
            
            # Get all SSL inspection profile mappings
            profile_mappings = self.get_ssl_inspection_profile_mappings()
            if not profile_mappings:
                self.logger.debug("No SSL inspection certificates found")
                return None
            
            # Try to match by domain using hybrid approach
            domain_matches = []
            for cert_name, profiles in profile_mappings.items():
                # First try: Fast text-based matching from certificate name
                cert_domain = self._extract_domain_from_cert_name(cert_name)
                if cert_domain and self._domains_match(upload_domain, cert_domain):
                    domain_matches.append((cert_name, profiles))
                    self.logger.debug(f"Domain match found (text-based): {cert_name} (domain: {cert_domain}) used in profiles: {', '.join(profiles)}")
                    continue
                
                # Second try: Fetch and parse actual certificate from FortiGate
                cert_domain = self._extract_domain_from_fortigate_cert(cert_name)
                if cert_domain and self._domains_match(upload_domain, cert_domain):
                    domain_matches.append((cert_name, profiles))
                    self.logger.debug(f"Domain match found (certificate-based): {cert_name} (domain: {cert_domain}) used in profiles: {', '.join(profiles)}")
            
            if len(domain_matches) == 1:
                cert_name, profiles = domain_matches[0]
                self.logger.info(f"SSL inspection certificate match: {cert_name} used in {len(profiles)} profile(s): {', '.join(profiles)}")
                return cert_name
            elif len(domain_matches) > 1:
                cert_names = [match[0] for match in domain_matches]
                total_profiles = sum(len(match[1]) for match in domain_matches)
                self.logger.warn(f"Multiple SSL inspection certificates found for domain {upload_domain}: {', '.join(cert_names)} (total {total_profiles} profiles)")
                # Return the first match for now
                cert_name, profiles = domain_matches[0]
                self.logger.info(f"Using first match: {cert_name} used in {len(profiles)} profile(s): {', '.join(profiles)}")
                return cert_name
            
            self.logger.debug(f"No SSL inspection certificates found matching domain: {upload_domain}")
            return None
            
        except Exception as e:
            self.logger.debug(f"Could not suggest SSL inspection certificate name: {e}")
            return None

    def _extract_domain_from_cert(self, cert_pem: str) -> Optional[str]:
        """Extract domain from certificate PEM."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.x509.oid import NameOID
            
            # Get the first certificate from the chain
            chunks = CertificateProcessor._split_pem_chain(cert_pem)
            if not chunks:
                return None
            
            cert = x509.load_pem_x509_certificate(chunks[0].encode("utf-8"), default_backend())
            
            # Try CN first
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    domain = attr.value.strip()
                    # Remove wildcard prefix if present
                    if domain.startswith("*."):
                        domain = domain[2:]
                    return domain.lower()
            
            # Fall back to SAN
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                dns_names = san.get_values_for_type(x509.DNSName)
                if dns_names:
                    domain = dns_names[0].strip()
                    # Remove wildcard prefix if present
                    if domain.startswith("*."):
                        domain = domain[2:]
                    return domain.lower()
            except Exception:
                pass
            
            return None
        except Exception as e:
            self.logger.debug(f"Failed to extract domain from certificate: {e}")
            return None

    def _extract_domain_from_cert_name(self, cert_name: str) -> Optional[str]:
        """Extract domain from certificate name (e.g., 'BluCore.io' -> 'blucore.io')."""
        try:
            # Handle standard naming scheme (domain-YYYYMMDD)
            if re.match(r"^.+-\d{8}$", cert_name):
                domain = cert_name.rsplit("-", 1)[0]
                return domain.lower()
            
            # Handle direct domain names (like 'BluCore.io')
            # Remove common certificate name patterns
            domain = cert_name.lower()
            
            # Check if it looks like a domain
            if "." in domain and not domain.startswith("fortinet"):
                return domain
            
            return None
        except Exception:
            return None

    def _extract_domain_from_fortigate_cert(self, cert_name: str) -> Optional[str]:
        """Extract domain from FortiGate certificate by fetching and parsing it."""
        try:
            # Fetch certificate from FortiGate
            params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
            code, data = self.api.cmdb_get(f"vpn.certificate/local/{cert_name}", params=params)
            
            if code != 200 or not isinstance(data, dict):
                self.logger.debug(f"Failed to fetch certificate {cert_name}: HTTP {code}")
                return None
            
            # Extract certificate content
            results = data.get("results")
            if not results:
                self.logger.debug(f"No results for certificate {cert_name}")
                return None
            
            # Handle both single result and array of results
            cert_data = results[0] if isinstance(results, list) else results
            cert_pem = cert_data.get("certificate")
            
            if not cert_pem:
                self.logger.debug(f"No certificate content found for {cert_name}")
                return None
            
            # Parse certificate and extract domain
            return self._extract_domain_from_cert(cert_pem)
            
        except Exception as e:
            self.logger.debug(f"Failed to extract domain from FortiGate certificate {cert_name}: {e}")
            return None

    def _domains_match(self, domain1: str, domain2: str) -> bool:
        """Check if two domains match (case-insensitive)."""
        if not domain1 or not domain2:
            return False
        return domain1.lower() == domain2.lower()

    def check_certificate_bindings(self, cert_name: str) -> Dict[str, bool]:
        """Check if certificate is bound to any services."""
        bindings = {
            "gui": False,
            "ssl_vpn": False,
            "ftm": False,
            "ssl_inspection": False
        }
        
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        
        try:
            # Check GUI binding
            code, data = self.api.cmdb_get("system/global", params=params)
            if code == 200 and isinstance(data, dict):
                results = data.get("results")
                if results:
                    result_data = results[0] if isinstance(results, list) else results
                    admin_cert = result_data.get("admin-server-cert")
                    if admin_cert == cert_name:
                        bindings["gui"] = True
                        self.logger.debug(f"Certificate {cert_name} is bound to GUI")
            
            # Check SSL-VPN binding
            code, data = self.api.cmdb_get("vpn.ssl/settings", params=params)
            if code == 200 and isinstance(data, dict):
                results = data.get("results")
                if results:
                    result_data = results[0] if isinstance(results, list) else results
                    ssl_cert = result_data.get("servercert")
                    if ssl_cert == cert_name:
                        bindings["ssl_vpn"] = True
                        self.logger.debug(f"Certificate {cert_name} is bound to SSL-VPN")
            
            # Check FTM binding
            code, data = self.api.cmdb_get("system/ftm-push", params=params)
            if code == 200 and isinstance(data, dict):
                results = data.get("results")
                if results:
                    result_data = results[0] if isinstance(results, list) else results
                    ftm_cert = result_data.get("server-cert")
                    if ftm_cert == cert_name:
                        bindings["ftm"] = True
                        self.logger.debug(f"Certificate {cert_name} is bound to FTM")
            
            # Check SSL inspection bindings
            ssl_inspection_mappings = self.get_ssl_inspection_profile_mappings()
            if cert_name in ssl_inspection_mappings:
                bindings["ssl_inspection"] = True
                profiles = ssl_inspection_mappings[cert_name]
                self.logger.debug(f"Certificate {cert_name} is bound to SSL inspection profiles: {', '.join(profiles)}")
                
        except Exception as e:
            self.logger.warn(f"Error checking certificate bindings for {cert_name}: {e}")
        
        return bindings

    def delete_cert(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        """Delete certificate."""
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        code, data = self.api.cmdb_delete(f"vpn.certificate/local/{name}", params=params)
        return (code == 200), {"http_status": code, "detail": data}

    def prune_old_certificates(self, current_name: str) -> Dict[str, Any]:
        """Enhanced pruning: delete certificates with same base domain, older expiry, and no service bindings."""
        result = {"deleted": [], "skipped": []}
        
        if not self.config.prune:
            return result
        
        # Extract base domain and expiry from current certificate
        current_base = CertificateProcessor.base_from_name(current_name)
        current_expiry = self._extract_expiry_from_name(current_name)
        
        if not current_expiry:
            self.logger.warn(f"Could not extract expiry date from current certificate name: {current_name}")
            return result
        
        # Get all local certificates
        all_certs = self.list_local_certs()
        
        for cert_name in all_certs:
            if cert_name == current_name:
                continue  # Skip current certificate
            
            # Check if certificate has same base domain
            cert_base = CertificateProcessor.base_from_name(cert_name)
            if cert_base != current_base:
                result["skipped"].append({"name": cert_name, "reason": "different base domain"})
                continue
            
            # Extract expiry date from certificate name
            cert_expiry = self._extract_expiry_from_name(cert_name)
            if not cert_expiry:
                result["skipped"].append({"name": cert_name, "reason": "could not extract expiry date"})
                continue
            
            # Only consider certificates with older expiry dates
            if cert_expiry >= current_expiry:
                result["skipped"].append({"name": cert_name, "reason": f"not older (expires {cert_expiry}, current expires {current_expiry})"})
                continue
            
            # Check if certificate is bound to any services
            bindings = self.check_certificate_bindings(cert_name)
            bound_services = [service for service, is_bound in bindings.items() if is_bound]
            
            if bound_services:
                result["skipped"].append({"name": cert_name, "reason": f"bound to services: {', '.join(bound_services)}"})
                self.logger.info(f"Skipping certificate {cert_name} - bound to services: {', '.join(bound_services)}")
                continue
            
            # Safe to delete: same base domain, older expiry, no service bindings
            self.logger.info(f"Pruning old certificate: {cert_name} (expires {cert_expiry}, current expires {current_expiry}, no service bindings)")
            
            if self.config.dry_run:
                self.logger.info(f"DRYRUN: would delete old certificate: {cert_name}")
                result["deleted"].append(cert_name)
                continue
            
            success, detail = self.delete_cert(cert_name)
            if success:
                result["deleted"].append(cert_name)
                self.logger.info(f"Pruned old certificate: {cert_name}")
            else:
                reason = f"delete failed (HTTP {detail.get('http_status')})"
                result["skipped"].append({"name": cert_name, "reason": reason})
                self.logger.warn(f"Failed to prune certificate {cert_name}: {reason}")
        
        return result

    def rebind_ssl_inspection_profiles(self, old_cert_name: str, new_cert_name: str, profiles: List[str]) -> Dict[str, Any]:
        """Rebind SSL inspection profiles from old certificate to new certificate."""
        result = {"rebound": [], "failed": []}
        
        if not profiles:
            self.logger.debug("No SSL inspection profiles to rebind")
            return result
        
        params = _scope_params("global" if self.config.store == "GLOBAL" else "vdom", self.config.vdom)
        
        for profile_name in profiles:
            try:
                # Update the profile to use the new certificate
                payload = {"server-cert": [{"name": new_cert_name}]}
                
                if self.config.dry_run:
                    self.logger.info(f"DRYRUN: would rebind SSL inspection profile '{profile_name}' from '{old_cert_name}' to '{new_cert_name}'")
                    result["rebound"].append({"profile": profile_name, "old_cert": old_cert_name, "new_cert": new_cert_name, "dry_run": True})
                    continue
                
                # URL encode the profile name for API call
                import urllib.parse
                encoded_profile = urllib.parse.quote(profile_name, safe='')
                
                code, data = self.api.cmdb_put(f"firewall/ssl-ssh-profile/{encoded_profile}", payload, params=params)
                
                if code == 200:
                    result["rebound"].append({"profile": profile_name, "old_cert": old_cert_name, "new_cert": new_cert_name})
                    self.logger.info(f"Rebound SSL inspection profile '{profile_name}' from '{old_cert_name}' to '{new_cert_name}'")
                else:
                    error_detail = {"profile": profile_name, "http_status": code, "detail": data}
                    result["failed"].append(error_detail)
                    self.logger.error(f"Failed to rebind SSL inspection profile '{profile_name}': HTTP {code}")
                    
            except Exception as e:
                error_detail = {"profile": profile_name, "error": str(e)}
                result["failed"].append(error_detail)
                self.logger.error(f"Exception rebinding SSL inspection profile '{profile_name}': {e}")
        
        return result

    def prune_ssl_inspection_certificates(self, current_name: str, domain: str) -> Dict[str, Any]:
        """Prune old SSL inspection certificates with same domain and older expiry dates."""
        result = {"deleted": [], "skipped": []}
        
        if not self.config.prune:
            return result
        
        # Extract expiry date from current certificate name
        current_expiry = self._extract_expiry_from_name(current_name)
        if not current_expiry:
            self.logger.warn(f"Could not extract expiry date from current certificate name: {current_name}")
            return result
        
        # Get all local certificates
        all_certs = self.list_local_certs()
        
        # Find certificates with same domain but older expiry dates
        for cert_name in all_certs:
            if cert_name == current_name:
                continue  # Skip current certificate
            
            # Check if certificate matches the domain
            cert_domain = self._extract_domain_from_cert_name(cert_name)
            if not cert_domain:
                # Try fetching and parsing the actual certificate
                cert_domain = self._extract_domain_from_fortigate_cert(cert_name)
            
            if not cert_domain or not self._domains_match(domain, cert_domain):
                continue  # Skip certificates for different domains
            
            # Extract expiry date from certificate name
            cert_expiry = self._extract_expiry_from_name(cert_name)
            if not cert_expiry:
                self.logger.debug(f"Could not extract expiry date from certificate name: {cert_name}")
                continue
            
            # Only delete certificates with older expiry dates
            if cert_expiry < current_expiry:
                self.logger.info(f"Pruning old SSL inspection certificate: {cert_name} (expires {cert_expiry}, current expires {current_expiry})")
                
                if self.config.dry_run:
                    self.logger.info(f"DRYRUN: would delete old SSL inspection certificate: {cert_name}")
                    result["deleted"].append(cert_name)
                    continue
                
                success, detail = self.delete_cert(cert_name)
                if success:
                    result["deleted"].append(cert_name)
                    self.logger.info(f"Pruned old SSL inspection certificate: {cert_name}")
                else:
                    reason = f"delete failed (HTTP {detail.get('http_status')})"
                    result["skipped"].append({"name": cert_name, "reason": reason})
                    self.logger.warn(f"Failed to prune SSL inspection certificate {cert_name}: {reason}")
            else:
                self.logger.debug(f"Skipping certificate {cert_name} (expires {cert_expiry}, not older than current {current_expiry})")
        
        return result

    def _extract_expiry_from_name(self, cert_name: str) -> Optional[str]:
        """Extract expiry date from certificate name (e.g., 'blucore.io-20251114' -> '20251114')."""
        try:
            # Handle standard naming scheme (domain-YYYYMMDD)
            match = re.match(r"^.+-(\d{8})$", cert_name)
            if match:
                return match.group(1)
            return None
        except Exception:
            return None

# ---------------------------
# Main Application
# ---------------------------

class FortiCertSwap:
    """Main application class."""
    
    def __init__(self):
        self.logger: Optional[Logger] = None
        self.config: Optional[Config] = None

    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="Upload/rotate FortiGate certificate and bind to GUI/SSL-VPN/FTM, or upload certificate only.",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Connection settings
        parser.add_argument("--host", help="FortiGate hostname")
        parser.add_argument("--port", type=int, help="HTTPS port (e.g., 443 or 8443)")
        parser.add_argument("--token", help="REST API token")
        
        # Certificate settings
        parser.add_argument("--cert", help="PEM certificate (leaf + chain)")
        parser.add_argument("--key", help="PEM private key")
        parser.add_argument("--name", help="Override planned certificate name")
        parser.add_argument("--vdom", help="VDOM name (omit for GLOBAL store)")
        
        # Behavior settings
        parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
        parser.add_argument("--dry-run", dest="dry_run", action="store_true", 
                          help="Do not change FortiGate; show planned actions")
        parser.add_argument("--prune", action="store_true", 
                          help="Delete older certs with the same base name after successful bindings")
        
        # Timeout settings
        parser.add_argument("--timeout-connect", dest="timeout_connect", type=int, default=5)
        parser.add_argument("--timeout-read", dest="timeout_read", type=int, default=30)
        
        # Configuration
        parser.add_argument("-C", "--config", help="YAML config file")
        
        # Operation modes
        mode_group = parser.add_mutually_exclusive_group()
        mode_group.add_argument("--rebind", metavar="CERTNAME",
                               help="Bind GUI/SSL-VPN/FTM to existing certificate name on FortiGate")
        mode_group.add_argument("--cert-only", dest="cert_only", action="store_true",
                               help="Upload/update certificate only without binding to any services")
        mode_group.add_argument("--ssl-inspection-certificate", dest="ssl_inspection_cert", action="store_true",
                               help="Upload certificate with standard naming and rebind SSL inspection profiles")
        
        # Logging
        parser.add_argument("--log", help="Write a plain log to this file")
        parser.add_argument("--log-level", dest="log_level", 
                          choices=["standard", "debug"], default="standard",
                          help="Log verbosity when --log is used (default: standard)")
        
        return parser.parse_args()

    def setup_logging(self, config: Config):
        """Setup logging."""
        log_level = LogLevel.DEBUG if config.log_level == "debug" else LogLevel.STANDARD
        self.logger = Logger(config.log, log_level)

    def print_effective_config(self, config: Config, used_config: bool):
        """Print effective configuration."""
        print("[*] Effective configuration:")
        print(f"    host: {config.host}")
        print(f"    port: {config.port}")
        print(f"    vdom: {'GLOBAL' if not config.vdom else config.vdom}")
        print(f"    insecure: {config.insecure}")
        print(f"    dry_run: {config.dry_run}")
        print(f"    prune: {config.prune}")
        print(f"    timeout_connect: {config.timeout_connect}s")
        print(f"    timeout_read: {config.timeout_read}s")
        if config.log:
            print(f"    log: {config.log}")
            print(f"    log_level: {config.log_level}")

    def run_upload_mode(self, config: Config) -> Dict[str, Any]:
        """Run in upload mode."""
        # Load and validate certificate files
        cert_pem = CertificateProcessor.load_file(config.cert)
        key_pem = CertificateProcessor.load_file(config.key)
        
        # Validate formats
        CertificateProcessor.validate_certificate_format(cert_pem)
        CertificateProcessor.validate_private_key_format(key_pem)
        
        # Display certificate summary
        print(CertificateProcessor.summarize_chain(cert_pem))
        
        # Generate certificate name
        planned_name = CertificateProcessor.planned_cert_name(cert_pem, config.name)
        print(f"[*] Planned certificate name: {planned_name}")
        self.logger.info(f"planned_name={planned_name}")
        
        return self._execute_certificate_operations(config, planned_name, cert_pem, key_pem)

    def run_rebind_mode(self, config: Config) -> Dict[str, Any]:
        """Run in rebind-only mode."""
        planned_name = config.rebind
        print(f"[*] Rebinding existing certificate: {planned_name}")
        self.logger.info(f"rebind_only name={planned_name}")
        
        return self._execute_certificate_operations(config, planned_name, None, None)

    def run_cert_only_mode(self, config: Config) -> Dict[str, Any]:
        """Run in certificate-only mode (no service bindings)."""
        # Load and validate certificate files
        cert_pem = CertificateProcessor.load_file(config.cert)
        key_pem = CertificateProcessor.load_file(config.key)
        
        # Validate formats
        CertificateProcessor.validate_certificate_format(cert_pem)
        CertificateProcessor.validate_private_key_format(key_pem)
        
        # Display certificate summary
        print(CertificateProcessor.summarize_chain(cert_pem))
        
        # Generate certificate name (user-specified or auto-generated)
        planned_name = CertificateProcessor.planned_cert_name(cert_pem, config.name)
        print(f"[*] Certificate name: {planned_name}")
        print(f"[*] Certificate-only mode: {planned_name}")
        print(f"[*] Target store: {config.store}")
        
        # Initialize API client
        api = FortiAPI(config, self.logger)
        cert_ops = CertificateOperations(api, config, self.logger)
        
        result = {
            "status": "ok",
            "certificate": None,
            "mode": "cert_only",
            "version": VERSION
        }
        
        # Upload certificate only (no bindings)
        try:
            state, detail = cert_ops.cert_only_upload(planned_name, cert_pem, key_pem)
        except APIError as e:
            self.logger.error(f"Certificate upload failed: {e}")
            raise
        
        if state == "dry_run":
            return {"status": "dry_run", "detail": detail, "mode": "cert_only", "version": VERSION}
        
        msg = {
            "created": "created new",
            "updated": "updated existing",
            "error": "failed to upload"
        }.get(state, "unknown state")
        
        http_code = detail.get('http_status', 'n/a') if isinstance(detail, dict) else 'n/a'
        method = 'cmdb_post' if state == 'created' else 'cmdb_put'
        
        print(f"[*] Result: {msg} certificate \"{planned_name}\" in {config.store} store (via {method}, HTTP {http_code})")
        print(f"[*] Certificate uploaded without service bindings")
        
        self.logger.info(f"Certificate-only upload completed: {msg} (HTTP {http_code})")
        
        if state == "error":
            raise APIError(f"Certificate upload failed: HTTP {http_code}")
        
        result["certificate"] = {"name": planned_name, "store": config.store, "state": state}
        
        # Enhanced pruning for cert-only mode if requested
        if config.prune:
            prune_result = cert_ops.prune_old_certificates(planned_name)
            result["pruned"] = {"deleted": prune_result["deleted"], "skipped": prune_result["skipped"]}
            
            deleted_count = len(prune_result["deleted"])
            skipped_count = len(prune_result["skipped"])
            
            if deleted_count > 0:
                print(f"[*] Pruned {deleted_count} old certificate(s): {', '.join(prune_result['deleted'])}")
            if skipped_count > 0:
                print(f"[!] Skipped {skipped_count} certificate(s) during pruning")
        
        return result

    def run_ssl_inspection_cert_mode(self, config: Config) -> Dict[str, Any]:
        """Run in SSL inspection certificate mode with standard naming and rebinding."""
        # Load and validate certificate files
        cert_pem = CertificateProcessor.load_file(config.cert)
        key_pem = CertificateProcessor.load_file(config.key)
        
        # Validate formats
        CertificateProcessor.validate_certificate_format(cert_pem)
        CertificateProcessor.validate_private_key_format(key_pem)
        
        # Display certificate summary
        print(CertificateProcessor.summarize_chain(cert_pem))
        
        # Generate standard certificate name (like main script)
        planned_name = CertificateProcessor.planned_cert_name(cert_pem, config.name)
        print(f"[*] SSL inspection certificate mode: {planned_name}")
        print(f"[*] Target store: {config.store}")
        
        # Initialize API client
        api = FortiAPI(config, self.logger)
        cert_ops = CertificateOperations(api, config, self.logger)
        
        result = {
            "status": "ok",
            "certificate": None,
            "ssl_inspection": {"profiles_rebound": [], "profiles_failed": []},
            "pruned": {"deleted": [], "skipped": []},
            "mode": "ssl_inspection_cert",
            "version": VERSION
        }
        
        # Get SSL inspection profile mappings for the domain
        upload_domain = cert_ops._extract_domain_from_cert(cert_pem)
        if not upload_domain:
            raise CertificateError("Could not extract domain from certificate for SSL inspection matching")
        
        profile_mappings = cert_ops.get_ssl_inspection_profile_mappings()
        
        # Find SSL inspection certificates for this domain
        old_ssl_certs = []
        profiles_to_rebind = []
        
        for cert_name, profiles in profile_mappings.items():
            cert_domain = cert_ops._extract_domain_from_cert_name(cert_name)
            if not cert_domain:
                cert_domain = cert_ops._extract_domain_from_fortigate_cert(cert_name)
            
            if cert_domain and cert_ops._domains_match(upload_domain, cert_domain):
                old_ssl_certs.append(cert_name)
                profiles_to_rebind.extend(profiles)
                self.logger.info(f"Found SSL inspection certificate: {cert_name} used in {len(profiles)} profile(s): {', '.join(profiles)}")
        
        if not profiles_to_rebind:
            self.logger.warn(f"No SSL inspection profiles found for domain {upload_domain}")
        else:
            print(f"[*] Found {len(profiles_to_rebind)} SSL inspection profile(s) to rebind: {', '.join(profiles_to_rebind)}")
        
        # Upload new certificate
        try:
            state, detail = cert_ops.upload_or_update_cert(planned_name, cert_pem, key_pem)
        except APIError as e:
            self.logger.error(f"Certificate upload failed: {e}")
            raise
        
        if state == "dry_run":
            return {"status": "dry_run", "detail": detail, "ssl_inspection": result["ssl_inspection"], "mode": "ssl_inspection_cert", "version": VERSION}
        
        msg = {
            "created": "created new",
            "updated": "updated existing",
            "error": "failed to upload"
        }.get(state, "unknown state")
        
        http_code = detail.get('http_status', 'n/a') if isinstance(detail, dict) else 'n/a'
        method = 'cmdb_post' if state == 'created' else 'cmdb_put'
        
        print(f"[*] Result: {msg} certificate \"{planned_name}\" in {config.store} store (via {method}, HTTP {http_code})")
        self.logger.info(f"Certificate upload completed: {msg} (HTTP {http_code})")
        
        if state == "error":
            raise APIError(f"Certificate upload failed: HTTP {http_code}")
        
        result["certificate"] = {"name": planned_name, "store": config.store, "state": state}
        
        # Rebind SSL inspection profiles
        if profiles_to_rebind:
            print(f"[*] Rebinding {len(profiles_to_rebind)} SSL inspection profile(s)...")
            
            for old_cert in old_ssl_certs:
                profiles_for_cert = [p for p in profiles_to_rebind if p in profile_mappings.get(old_cert, [])]
                if profiles_for_cert:
                    rebind_result = cert_ops.rebind_ssl_inspection_profiles(old_cert, planned_name, profiles_for_cert)
                    result["ssl_inspection"]["profiles_rebound"].extend(rebind_result["rebound"])
                    result["ssl_inspection"]["profiles_failed"].extend(rebind_result["failed"])
            
            rebound_count = len(result["ssl_inspection"]["profiles_rebound"])
            failed_count = len(result["ssl_inspection"]["profiles_failed"])
            
            if rebound_count > 0:
                print(f"[*] Successfully rebound {rebound_count} SSL inspection profile(s)")
            if failed_count > 0:
                print(f"[!] Failed to rebind {failed_count} SSL inspection profile(s)")
        
        # Prune old certificates if requested (enhanced logic with service binding checks)
        if config.prune:
            prune_result = cert_ops.prune_old_certificates(planned_name)
            result["pruned"]["deleted"].extend(prune_result["deleted"])
            result["pruned"]["skipped"].extend(prune_result["skipped"])
            
            deleted_count = len(prune_result["deleted"])
            skipped_count = len(prune_result["skipped"])
            
            if deleted_count > 0:
                print(f"[*] Pruned {deleted_count} old certificate(s): {', '.join(prune_result['deleted'])}")
            if skipped_count > 0:
                print(f"[!] Skipped {skipped_count} certificate(s) during pruning")
        
        return result

    def _execute_certificate_operations(self, config: Config, cert_name: str,
                                      cert_pem: Optional[str], key_pem: Optional[str]) -> Dict[str, Any]:
        """Execute certificate operations."""
        print(f"[*] Target store: {config.store}")
        
        # Initialize API client
        api = FortiAPI(config, self.logger)
        cert_ops = CertificateOperations(api, config, self.logger)
        
        result = {
            "status": "ok",
            "certificate": None,
            "bindings": {},
            "version": VERSION
        }
        
        # Upload certificate (if not rebind mode)
        if cert_pem and key_pem:
            try:
                state, detail = cert_ops.upload_or_update_cert(cert_name, cert_pem, key_pem)
            except APIError as e:
                self.logger.error(f"Certificate upload failed: {e}")
                raise
            
            if state == "dry_run":
                return {"status": "dry_run", "detail": detail, "version": VERSION}
            
            msg = {
                "created": "created new",
                "updated": "re-uploaded existing",
                "error": "failed to upload"
            }.get(state, "unknown state")
            
            http_code = detail.get('http_status', 'n/a') if isinstance(detail, dict) else 'n/a'
            method = 'cmdb_post' if state == 'created' else 'cmdb_put'
            
            print(f"[*] Result: {msg} certificate \"{cert_name}\" in {config.store} store (via {method}, HTTP {http_code})")
            self.logger.info(f"Certificate upload completed: {msg} (HTTP {http_code})")
            
            if state == "error":
                raise APIError(f"Certificate upload failed: HTTP {http_code}")
            
            result["certificate"] = {"name": cert_name, "store": config.store, "state": state}
        else:
            # Rebind mode
            result["certificate"] = {"name": cert_name, "store": config.store, "state": "rebind"}
        
        # Perform bindings
        gui_ok, gui_detail = cert_ops.bind_gui(cert_name)
        ssl_ok, ssl_detail = cert_ops.bind_ssl_vpn(cert_name)
        ftm_ok, ftm_detail = cert_ops.bind_ftm(cert_name)
        
        # Log binding results in a user-friendly way
        results = []
        if gui_ok:
            results.append("GUI✓")
        else:
            results.append("GUI✗")
        
        if ssl_ok:
            results.append("SSL-VPN✓")
        else:
            results.append("SSL-VPN✗")
        
        if ftm_ok:
            results.append("FTM✓")
        else:
            results.append("FTM✗")
        
        success_count = sum([gui_ok, ssl_ok, ftm_ok])
        if success_count == 3:
            self.logger.info(f"All bindings successful: {' | '.join(results)}")
        else:
            self.logger.warn(f"Some bindings failed: {' | '.join(results)}")
        
        result["bindings"] = {
            "gui": {"ok": gui_ok, "http_status": gui_detail["http_status"], "detail": gui_detail["detail"]},
            "ssl_vpn": {"ok": ssl_ok, "http_status": ssl_detail["http_status"], "detail": ssl_detail["detail"]},
            "ftm": {"ok": ftm_ok, "http_status": ftm_detail["http_status"], "detail": ftm_detail["detail"]}
        }
        
        # Prune old certificates if all bindings successful
        if config.prune:
            if gui_ok and ssl_ok and ftm_ok:
                prune_result = cert_ops.prune_old_certificates(cert_name)
                print(json.dumps({"prune": prune_result}, indent=2))
                # Log prune results in a user-friendly way
                deleted = prune_result.get("deleted", [])
                skipped = prune_result.get("skipped", [])
                
                if deleted:
                    self.logger.info(f"Pruned {len(deleted)} old certificates: {', '.join(deleted)}")
                
                if skipped and self.logger.level == LogLevel.DEBUG:
                    # Only log skipped details in debug mode
                    skip_reasons = {}
                    for item in skipped:
                        reason = item.get("reason", "unknown")
                        if reason not in skip_reasons:
                            skip_reasons[reason] = 0
                        skip_reasons[reason] += 1
                    
                    reason_summary = ", ".join([f"{count} {reason}" for reason, count in skip_reasons.items()])
                    self.logger.debug(f"Skipped {len(skipped)} certificates: {reason_summary}")
            else:
                msg = "[!] One or more bindings failed; skipping prune to avoid deleting a cert still needed for rollback."
                print(msg)
                self.logger.warn(msg)
        
        return result

    def run(self) -> int:
        """Main application entry point."""
        try:
            # Parse arguments
            args = self.parse_arguments()
            
            # Load and merge configuration
            yaml_config = ConfigManager.load_yaml_config(args.config)
            self.config = ConfigManager.merge_args_with_config(args, yaml_config)
            
            # Setup logging
            self.setup_logging(self.config)
            
            # Validate required parameters
            if not self.config.rebind and not self.config.cert_only and not self.config.ssl_inspection_cert and (not self.config.cert or not self.config.key):
                raise ConfigurationError("cert and key are required unless --rebind CERTNAME is used.")
            
            if self.config.cert_only and (not self.config.cert or not self.config.key):
                raise ConfigurationError("cert and key are required for --cert-only mode.")
            
            if self.config.ssl_inspection_cert and (not self.config.cert or not self.config.key):
                raise ConfigurationError("cert and key are required for --ssl-inspection-certificate mode.")
            
            # Print effective configuration
            self.print_effective_config(self.config, used_config=bool(args.config))
            
            # Run appropriate mode
            if self.config.rebind:
                result = self.run_rebind_mode(self.config)
            elif self.config.cert_only:
                result = self.run_cert_only_mode(self.config)
            elif self.config.ssl_inspection_cert:
                result = self.run_ssl_inspection_cert_mode(self.config)
            else:
                result = self.run_upload_mode(self.config)
            
            # Output result
            print(json.dumps(result, indent=2))
            
            # Log operation completion
            if result.get("status") == "ok":
                self.logger.info("Certificate operation completed successfully")
            else:
                self.logger.error(f"Certificate operation failed: {result.get('status')}")
            
            return 0
            
        except ConfigurationError as e:
            print(f"[!] Configuration error: {e}", file=sys.stderr)
            if self.logger:
                self.logger.error(f"Configuration error: {e}")
            return 1
        except CertificateError as e:
            print(f"[!] Certificate error: {e}", file=sys.stderr)
            if self.logger:
                self.logger.error(f"Certificate error: {e}")
            return 1
        except APIError as e:
            print(f"[!] API error: {e}", file=sys.stderr)
            if self.logger:
                self.logger.error(f"API error: {e}")
            return 2
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            return 130
        except Exception as e:
            print(f"[!] Unexpected error: {e}", file=sys.stderr)
            if self.logger:
                self.logger.error(f"Unexpected error: {e}")
            return 1
        finally:
            if self.logger:
                self.logger.close()


def main():
    """Main entry point."""
    app = FortiCertSwap()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())