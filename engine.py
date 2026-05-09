import os
import json
import random
import requests
import socket
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

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
    '/server-status', '/server-info', '/.htaccess', '/config.yml', '/package.json',
    '/.DS_Store', '/backup.sql', '/database.sql', '/.well-known/security.txt'
]

SECURITY_HEADERS = [
    'Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy',
    'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
    'X-XSS-Protection', 'Feature-Policy', 'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy', 'Expect-CT'
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
        "sensitive_files": []
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
            
            # Security Headers Check
            missing = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in r.headers.keys()]]
            result["missing_headers"] = missing
            
            # Cookie Security Check
            bad_cookies = []
            for cookie in r.cookies:
                if not cookie.secure: bad_cookies.append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr('httponly'): bad_cookies.append(f"Cookie '{cookie.name}' missing HttpOnly")
            result["cookie_issues"] = bad_cookies
            
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
# STAGE 2: WEB FUZZING (OWASP Misconfigs)
# ==========================================
def check_sensitive_path(base_url, path):
    try:
        r = requests.get(f"{base_url}{path}", timeout=4, verify=False, allow_redirects=False)
        if r.status_code in [200, 403, 401]: # 403/401 means it exists but is protected
            return {"path": path, "status": r.status_code}
        return None
    except: return None

def stage_2_web_audit(assets):
    print(f"[+] Starting Web Security Audit (Fuzzing & Headers)...")
    
    for asset in assets:
        if not asset["http_status"]: continue # Only audit web-active hosts
        
        scheme = "https" if "443" in str(asset.get("ip", "")) or asset.get("http_status") else "http"
        base_url = f"https://{asset['host']}" # Try https first
        
        # Fuzz sensitive paths
        found_files = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_sensitive_path, base_url, path): path for path in SENSITIVE_PATHS}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found_files.append(res)
        
        asset["sensitive_files"] = found_files
        if found_files:
            print(f"  -> {asset['host']}: Found {len(found_files)} interesting paths (e.g., {found_files[0]['path']}).")
    
    print(f"[+] Web Audit Complete.")
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
        if open_ports: print(f"  -> {asset['host']} ({ip}): Ports {open_ports}")

    for a in cdn_assets: a["open_ports"] = ["CDN Protected - Not Scanned"]
    return origin_assets + cdn_assets

# ==========================================
# AI STAGES (Strict Evidence Only)
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
    print("[+] Running AI Stage 1: Evidence Extraction...")
    prompt = f"""You are an expert, strict, evidence-only Threat Intelligence Analyst. Analyze this raw scan data for '{TARGET}':
    {json.dumps(data, indent=2)}
    
    STRICT RULES:
    1. DO NOT GUESS technologies or vulnerabilities.
    2. Treat exposed sensitive files (.git/HEAD, .env, phpinfo.php, wp-login.php, admin panels, etc.) as security findings.
    3. Treat missing security headers as informational findings.
    4. Flag insecure cookies (missing Secure/HttpOnly) as vulnerabilities.
    5. ONLY flag open ports that are actually in the "open_ports" array.
    6. Map ONLY proven risks to MITRE ATT&CK and OWASP Top 10 (2021).
    
    Output strictly as JSON array:
    [
        {{
            "asset": "subdomain.target.com",
            "ip": "x.x.x.x",
            "finding": "Exact description of what was found",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
            "mitre_tactic": "Tactic (TA####)",
            "mitre_technique": "Technique (T####)",
            "owasp_category": "A01:2021 - Broken Access Control (if applicable)",
            "evidence": "Exact proof from the data")
        }}
    ]"""
    return call_gemini_with_retry(prompt)

def stage_5_ai_report(intel):
    print("[+] Running AI Stage 2: Final Report...")
    prompt = f"""You are a CISO reporting assistant. Take this evidence-based intelligence for '{TARGET}':
    {intel}
    
    Write a professional Markdown report. Base EVERY statement on the provided evidence.
    
    Include:
    1. 🎯 **Executive Summary:** (Risk score out of 100)
    2. 🗺️ **Attack Surface Map:** Differentiate between CDN-protected and Origin assets.
    3. 🚨 **Critical Findings:** Exposed files, EOL tech, open admin ports.
    4. 🛡️ **OWASP & MITRE Mapping:** Group findings strictly by OWASP Top 10 and MITRE ATT&CK.
    5. 🔧 **Remediation Steps:** Actionable advice based strictly on what was found."""
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
    
    # Stage 1: Subdomains & Web Info
    assets = stage_1_recon(TARGET)
    
    # Stage 2: Web Security Audit (Fuzzing + Headers + Cookies)
    assets = stage_2_web_audit(assets)
    
    # Stage 3: Network Origin Port Scan
    full_data = stage_3_network_scan(assets)
    
    with open('./cache/raw_data.json', 'w') as f:
        json.dump({"target": TARGET, "assets": full_data}, f, indent=2)
    
    # Stage 4: AI Analysis
    intel = stage_4_ai_analysis(full_data)
    with open('./cache/processed_intel.json', 'w') as f: f.write(intel)
        
    # Stage 5: AI Report
    report = stage_5_ai_report(intel)
    with open('./cache/final_report.md', 'w') as f: f.write(report)
        
    # Stage 6: Delivery
    stage_6_deliver(report)
    print(f"=== OMNISCIENCE ENGINE COMPLETE ===")
