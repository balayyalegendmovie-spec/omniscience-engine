import os
import json
import random
import requests
import socket
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = os.environ.get('TARGET')
CHAT_ID = os.environ.get('CHAT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL')

API_KEYS = [
    os.environ.get('GEMINI_KEY_1'), os.environ.get('GEMINI_KEY_2'),
    os.environ.get('GEMINI_KEY_3'), os.environ.get('GEMINI_KEY_4'),
    os.environ.get('GEMINI_KEY_5'), os.environ.get('GEMINI_KEY_6')
]

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
CDN_SERVERS = ['cloudflare', 'akamai', 'sucuri', 'incapsula', 'cloudfront', 'awselb', 'fastly']

SENSITIVE_PATHS = [
    '/.git/HEAD', '/.env', '/.svn/entries', '/wp-config.php', '/wp-login.php',
    '/phpinfo.php', '/admin', '/admin/login', '/robots.txt', '/sitemap.xml',
    '/server-status', '/.htaccess', '/config.yml', '/package.json',
    '/.DS_Store', '/backup.sql', '/.well-known/security.txt'
]

# NEW: Advanced Vulnerability Endpoints
ADVANCED_ENDPOINTS = [
    '/api/v1', '/api/v2', '/api/docs', '/swagger-ui.html', '/swagger.json', 
    '/openapi.json', '/graphql', '/graphiql', '/actuator/health', '/actuator/env',
    '/actuator/trace', '/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users',
    '/console', '/debug', '/trace', '/.well-known/openid-configuration',
    '/api/users', '/api/admin', '/telemetry', '/metrics'
]

# NEW: Parameters often vulnerable to Open Redirect / SSRF / LFI
REDIRECT_PARAMS = ['url', 'redirect', 'next', 'continue', 'return', 'dest', 'target', 'redir', 'rurl']

SECURITY_HEADERS = [
    'Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy',
    'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
    'X-XSS-Protection', 'Feature-Policy', 'Cross-Origin-Opener-Policy'
]

# ==========================================
# STAGE 1: DEEP RECON
# ==========================================
def fetch_crtsh(target):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=20)
        if r.status_code == 200:
            for entry in r.json():
                for sub in entry.get('name_value', '').split('\n'):
                    sub = sub.strip().lower()
                    if not sub.startswith('*') and sub.endswith(target): subs.add(sub)
    except: pass
    return subs

def fetch_hackertarget(target):
    subs = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                parts = line.split(",")
                if len(parts) == 2: subs.add(parts[0].strip().lower())
    except: pass
    return subs

def resolve_dns(sub):
    try: return socket.gethostbyname(sub)
    except: return None

def probe_subdomain(sub):
    result = {
        "host": sub, "ip": None, "is_cdn": False, "cdn_provider": None,
        "http_status": None, "title": None, "server": None, 
        "technologies": [], "missing_headers": [], "cookie_issues": [],
        "sensitive_files": [], "hidden_api_endpoints": [], "html_size": 0
    }
    
    ip = resolve_dns(sub)
    if not ip: return result
    result["ip"] = ip

    for scheme in ['https', 'http']:
        try:
            r = requests.get(f"{scheme}://{sub}", timeout=5, verify=False, allow_redirects=True)
            result["http_status"] = r.status_code
            
            if "<title>" in r.text.lower():
                s = r.text.lower().find("<title>") + 7
                e = r.text.lower().find("</title>", s)
                result["title"] = r.text[s:e].strip()[:100]
            
            server = r.headers.get("Server", "Unknown")
            result["server"] = server
            if any(cdn in server.lower() for cdn in CDN_SERVERS):
                result["is_cdn"] = True
                result["cdn_provider"] = server
            
            techs = []
            if r.headers.get("X-Powered-By"): techs.append(f"X-Powered-By: {r.headers.get('X-Powered-By')}")
            if r.headers.get("X-AspNet-Version"): techs.append(f"ASP.NET: {r.headers.get('X-AspNet-Version')}")
            if "wordpress" in r.text.lower()[:2000]: techs.append("WordPress Detected")
            result["technologies"] = techs
            
            missing = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in r.headers.keys()]]
            result["missing_headers"] = missing
            
            bad_cookies = []
            for cookie in r.cookies:
                if not cookie.secure: bad_cookies.append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr('httponly'): bad_cookies.append(f"Cookie '{cookie.name}' missing HttpOnly")
            result["cookie_issues"] = bad_cookies

            # NEW: Extract hidden endpoints from JavaScript/HTML
            api_patterns = re.findall(r'(?:["\'])(/(?:api|v[0-9]|graphql|rest|auth|admin|user|upload)/[^"\']*)(?:["\'])', r.text)
            if api_patterns:
                result["hidden_api_endpoints"] = list(set(api_patterns))[:10] # Top 10 unique
                
            result["html_size"] = len(r.content)
            break
        except: continue
    return result

def stage_1_recon(target):
    print(f"[+] Starting Deep Recon on {target}...")
    subs = fetch_crtsh(target) | fetch_hackertarget(target)
    if target in subs: subs.add(target)
    print(f"[+] Found {len(subs)} unique subdomains.")
    
    alive_assets = []
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(probe_subdomain, sub): sub for sub in subs}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res["ip"]: alive_assets.append(res)
            except: pass
    print(f"[+] {len(alive_assets)} hosts alive.")
    return alive_assets

# ==========================================
# STAGE 2: ADVANCED VULNERABILITY AUDIT
# ==========================================
def check_path(base_url, path):
    try:
        r = requests.get(f"{base_url}{path}", timeout=4, verify=False, allow_redirects=False)
        if r.status_code in [200, 403, 401, 405]:
            return {"path": path, "status": r.status_code, "size": len(r.content)}
        return None
    except: return None

def check_open_redirect(base_url, param):
    try:
        payload = f"https://evil.com"
        r = requests.get(f"{base_url}/?{param}={payload}", timeout=4, verify=False, allow_redirects=False)
        # Check if it redirects to our evil payload
        if r.status_code in [301, 302, 303, 307, 308]:
            location = r.headers.get('Location', '')
            if "evil.com" in location:
                return {"parameter": param, "redirect_url": location}
        return None
    except: return None

def check_error_leaks(base_url):
    leaks = []
    payloads = ["'", "{{7*7}}", "<h1>xss</h1>"]
    try:
        for p in payloads:
            r = requests.get(f"{base_url}/?id={p}", timeout=4, verify=False)
            text = r.text.lower()
            if "sql syntax" in text or "mysql_" in text or "pgsql" in text:
                leaks.append({"type": "SQL Error Leak", "payload": p})
            elif "49" in r.text and p == "{{7*7}}": # 7*7 = 49
                leaks.append({"type": "SSTI Detected (49)", "payload": p})
            elif "<h1>xss</h1>" in text.lower():
                leaks.append({"type": "Reflected XSS (No Filter)", "payload": p})
            if leaks: break # One leak is enough to prove the point
    except: pass
    return leaks

def stage_2_web_audit(assets):
    print(f"[+] Starting Advanced Vulnerability Audit...")
    
    for asset in assets:
        if not asset["http_status"]: continue
        base_url = f"https://{asset['host']}"
        
        # 1. Fuzz Sensitive Files + Advanced API Endpoints
        all_paths = SENSITIVE_PATHS + ADVANCED_ENDPOINTS
        found_files = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_path, base_url, path): path for path in all_paths}
            for future in as_completed(futures):
                res = future.result()
                if res: found_files.append(res)
        asset["sensitive_files"] = found_files
        
        # 2. Open Redirect Checks
        open_redirects = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_open_redirect, base_url, param): param for param in REDIRECT_PARAMS}
            for future in as_completed(futures):
                res = future.result()
                if res: open_redirects.append(res)
        asset["open_redirects"] = open_redirects
        
        # 3. Error/Leak Provocation
        asset["data_leaks"] = check_error_leaks(base_url)
        
        if found_files or open_redirects or asset["data_leaks"]:
            print(f"  -> {asset['host']}: Vulns found! {len(found_files)} endpoints, {len(open_redirects)} redirects, {len(asset['data_leaks'])} leaks.")
    
    print(f"[+] Advanced Audit Complete.")
    return assets

# ==========================================
# STAGE 3: ORIGIN PORT SCANNING
# ==========================================
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        if s.connect_ex((ip, port)) == 0: return port
        s.close()
    except: pass
    return None

def stage_3_network_scan(assets):
    origin_assets = [a for a in assets if not a["is_cdn"]]
    cdn_assets = [a for a in assets if a["is_cdn"]]
    print(f"[+] {len(origin_assets)} Origin assets. Scanning top ports...")
    for asset in origin_assets:
        ip = asset["ip"]
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port, ip, p): p for p in TOP_PORTS}
            for future in as_completed(futures):
                port = future.result()
                if port: open_ports.append(port)
        asset["open_ports"] = sorted(open_ports) if open_ports else []
    for a in cdn_assets: a["open_ports"] = ["CDN Protected"]
    return origin_assets + cdn_assets

# ==========================================
# AI STAGES (How & Why Analysis)
# ==========================================
def call_gemini(prompt, api_key):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    payload = {"contents": [{"parts":[{"text": prompt}]}], "generationConfig": { "temperature": 0.4, "maxOutputTokens": 8192 }}
    r = requests.post(url, json=payload, timeout=90)
    r.raise_for_status()
    return r.json()['candidates'][0]['content']['parts'][0]['text']

def call_gemini_with_retry(prompt):
    keys = [k for k in API_KEYS if k]
    random.shuffle(keys)
    for i, key in enumerate(keys):
        try:
            print(f"[+] Attempting API Key #{i+1}...")
            return call_gemini(prompt, key)
        except Exception as e:
            print(f"[-] Key #{i+1} failed: {str(e)}")
    raise Exception("All API keys exhausted.")

def stage_4_ai_analysis(data):
    print("[+] Running AI Stage 1: Vulnerability Evidence Extraction...")
    prompt = f"""You are a Tier-1 Red Team Operator. Analyze this raw scan data for '{TARGET}':
    {json.dumps(data, indent=2)}
    
    STRICT RULES:
    1. DO NOT GUESS. Base everything on the provided evidence.
    2. For EVERY finding, you MUST provide:
       - **what_was_found**: The exact URL/Port/Header.
       - **why_its_vulnerable**: The technical flaw (e.g., "Server blindly redirects to attacker-controlled URL without validation").
       - **how_to_exploit**: Brief scenario (e.g., "Attacker sends link to user; user clicks and is redirected to a fake login page to steal credentials").
    3. Flag exposed API docs (/swagger, /graphql, /openapi) as HIGH severity.
    4. Flag Open Redirects as MEDIUM/HIGH.
    5. Flag SQL/SSTI/XSS error leaks as CRITICAL/HIGH.
    
    Output strictly as JSON array:
    [
        {{
            "asset": "subdomain.target.com",
            "what_was_found": "e.g., /swagger-ui.html returned 200",
            "why_its_vulnerable": "e.g., Exposes API schema allowing attackers to understand internal logic.",
            "how_to_exploit": "e.g., Attacker reads schema -> crafts valid API request to /api/admin/delete",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
            "owasp_category": "e.g., A01:2021 - Broken Access Control",
            "mitre_technique": "e.g., T1190"
        }}
    ]"""
    return call_gemini_with_retry(prompt)

def stage_5_ai_report(intel):
    print("[+] Running AI Stage 2: Final Report Generation...")
    prompt = f"""You are a CISO reporting assistant. Take this red team intelligence for '{TARGET}':
    {intel}
    
    Write a highly detailed, professional Markdown report. Include:
    1. 🎯 **Executive Summary:** (Risk score out of 100, overview of real threats).
    2. 🗺️ **Attack Surface Map:** Summary of assets, CDN protection, and exposed ports.
    3. 🚨 **Vulnerable Endpoints & Exploitability:** Group by severity. For each, explain:
       - **What was found**
       - **Why it is vulnerable** 
       - **How an attacker exploits it**
    4. 🛡️ **OWASP & MITRE Mapping:** Group findings.
    5. 🔧 **Remediation Steps:** Specific, actionable fixes."""
    return call_gemini_with_retry(intel)

# ==========================================
# DELIVERY & MAIN
# ==========================================
def stage_6_deliver(report):
    print("[+] Delivering report...")
    payload = {"action": "delivery", "target": TARGET, "chat_id": CHAT_ID, "report": report}
    try: requests.post(CALLBACK_URL, json=payload, timeout=30)
    except Exception as e: print(f"[-] Failed: {e}")

if __name__ == "__main__":
    print(f"=== OMNISCIENCE ENGINE STARTED ===")
    assets = stage_1_recon(TARGET)
    assets = stage_2_web_audit(assets)
    full_data = stage_3_network_scan(assets)
    
    with open('./cache/raw_data.json', 'w') as f:
        json.dump({"target": TARGET, "assets": full_data}, f, indent=2)
    
    intel = stage_4_ai_analysis(full_data)
    with open('./cache/processed_intel.json', 'w') as f: f.write(intel)
        
    report = stage_5_ai_report(intel)
    with open('./cache/final_report.md', 'w') as f: f.write(report)
        
    stage_6_deliver(report)
    print(f"=== OMNISCIENCE ENGINE COMPLETE ===")
