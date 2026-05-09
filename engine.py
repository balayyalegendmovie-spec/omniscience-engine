import os
import json
import random
import requests
import socket
import urllib3
import re
import time
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
    '/server-status', '/.htaccess', '/config.yml', '/package.json', '/.DS_Store'
]

ADVANCED_ENDPOINTS = [
    '/api/v1', '/swagger-ui.html', '/swagger.json', '/openapi.json', 
    '/graphql', '/actuator/health', '/actuator/env',
    '/wp-json/wp/v2/users', '/console', '/debug'
]

REDIRECT_PARAMS = ['url', 'redirect', 'next', 'continue', 'return', 'dest', 'target']
SECURITY_HEADERS = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options']

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
        "sensitive_files": [], "hidden_api_endpoints": []
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
            result["technologies"] = techs
            
            missing = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in r.headers.keys()]]
            result["missing_headers"] = missing
            
            api_patterns = re.findall(r'(?:["\'])(/(?:api|v[0-9]|graphql|rest|auth|admin|user)/[^"\']*)(?:["\'])', r.text)
            if api_patterns: result["hidden_api_endpoints"] = list(set(api_patterns))[:10]
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
# STAGE 1.5: DEEP OSINT (NEW!)
# ==========================================
def github_secret_dorking(target):
    """Search GitHub for hardcoded secrets belonging to the target"""
    print(f"[+] Running GitHub OSINT for {target}...")
    queries = [
        f'"{target}" password',
        f'"{target}" api_key',
        f'"{target}" .env',
        f'"{target}" secret_key',
        f'"{target}" connection_string'
    ]
    
    leaked_data = []
    for query in queries:
        try:
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 5},
                headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "OMNISCIENCE-Engine"},
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("total_count", 0) > 0:
                    for item in data.get("items", []):
                        leaked_data.append({
                            "file": item.get("path"),
                            "repo": item.get("repository", {}).get("full_name"),
                            "url": item.get("html_url"),
                            "query_used": query
                        })
            time.sleep(3)  # Respect GitHub unauthenticated rate limits (10 req/min)
        except: pass
    
    if leaked_data: print(f"[+] WARNING: Found {len(leaked_data)} potential code leaks on GitHub!")
    else: print(f"[+] GitHub OSINT clean. No obvious leaks found.")
    return leaked_data

def discover_cloud_assets(target):
    """Check for publicly exposed S3, Firebase, and GCS buckets"""
    print(f"[+] Probing Cloud Assets for {target}...")
    org_name = target.split('.')[0]
    
    permutations = [
        f"{org_name}-backup", f"{org_name}-dev", f"{org_name}-staging",
        f"{org_name}-old", f"{org_name}-bucket", f"{target.replace('.', '-')}",
        f"{target}-logs", f"{org_name}-assets", f"{org_name}-data"
    ]
    
    exposed_assets = []
    
    def check_s3(perm):
        url = f"http://{perm}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200:
                return {"type": "AWS S3 (PUBLIC READ)", "url": url, "severity": "CRITICAL", "evidence": "Bucket contents listable"}
            elif r.status_code == 403:
                return {"type": "AWS S3 (EXISTS)", "url": url, "severity": "INFO", "evidence": "Bucket exists but access denied"}
        except: pass
        return None

    def check_firebase(perm):
        url = f"https://{perm}.firebaseio.com/.json"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200 and r.text != "null":
                return {"type": "Firebase DB (PUBLIC)", "url": url, "severity": "CRITICAL", "evidence": "Database readable"}
        except: pass
        return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        s3_futures = {executor.submit(check_s3, p): p for p in permutations}
        fb_futures = {executor.submit(check_firebase, p): p for p in permutations}
        
        for future in as_completed(s3_futures):
            res = future.result()
            if res: exposed_assets.append(res)
        for future in as_completed(fb_futures):
            res = future.result()
            if res: exposed_assets.append(res)

    if exposed_assets: print(f"[+] WARNING: Found {len(exposed_assets)} exposed cloud assets!")
    else: print(f"[+] Cloud assets secure.")
    return exposed_assets

def stage_1_5_osint(target):
    """Run all passive OSINT checks"""
    return {
        "github_leaks": github_secret_dorking(target),
        "cloud_assets": discover_cloud_assets(target)
    }

# ==========================================
# STAGE 2: WEB AUDIT
# ==========================================
def check_path(base_url, path):
    try:
        r = requests.get(f"{base_url}{path}", timeout=4, verify=False, allow_redirects=False)
        if r.status_code in [200, 403, 401, 405]:
            return {"path": path, "status": r.status_code, "size": len(r.content)}
    except: pass
    return None

def check_open_redirect(base_url, param):
    try:
        r = requests.get(f"{base_url}/?{param}=https://evil.com", timeout=4, verify=False, allow_redirects=False)
        if r.status_code in [301, 302, 303, 307, 308] and "evil.com" in r.headers.get('Location', ''):
            return {"parameter": param, "redirect_url": r.headers['Location']}
    except: pass
    return None

def check_error_leaks(base_url):
    leaks = []
    for p in ["'", "{{7*7}}"]:
        try:
            r = requests.get(f"{base_url}/?id={p}", timeout=4, verify=False)
            text = r.text.lower()
            if "sql syntax" in text or "mysql_" in text: leaks.append({"type": "SQL Error Leak", "payload": p})
            elif "49" in r.text and p == "{{7*7}}": leaks.append({"type": "SSTI Detected", "payload": p})
        except: pass
    return leaks

def stage_2_web_audit(assets):
    print(f"[+] Starting Advanced Vulnerability Audit...")
    for asset in assets:
        if not asset["http_status"]: continue
        base_url = f"https://{asset['host']}"
        
        all_paths = SENSITIVE_PATHS + ADVANCED_ENDPOINTS
        found_files = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_path, base_url, path): path for path in all_paths}
            for future in as_completed(futures):
                res = future.result()
                if res: found_files.append(res)
        asset["sensitive_files"] = found_files
        
        open_redirects = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_open_redirect, base_url, param): param for param in REDIRECT_PARAMS}
            for future in as_completed(futures):
                res = future.result()
                if res: open_redirects.append(res)
        asset["open_redirects"] = open_redirects
        
        asset["data_leaks"] = check_error_leaks(base_url)
    return assets

# ==========================================
# STAGE 3: PORT SCANNING
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
# AI STAGES
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

def stage_4_ai_analysis(data, osint_data):
    print("[+] Running AI Stage 1: Vulnerability & OSINT Extraction...")
    prompt = f"""You are a Tier-1 Red Team Operator. Analyze this raw scan data AND OSINT data for '{TARGET}':

    --- NETWORK & WEB DATA ---
    {json.dumps(data, indent=2)}

    --- OSINT & LEAK DATA ---
    {json.dumps(osint_data, indent=2)}
    
    STRICT RULES:
    1. DO NOT GUESS. Base everything on the provided evidence.
    2. If GitHub leaks are found, treat them as CRITICAL. Explain exactly what was leaked (e.g., "Hardcoded database credentials found in .env file").
    3. If public Cloud assets (S3/Firebase) are found, treat them as CRITICAL.
    4. For web findings, explain What, Why, and How to exploit.
    5. Map ONLY proven risks to MITRE ATT&CK and OWASP Top 10.
    
    Output strictly as JSON array:
    [
        {{
            "asset": "subdomain.target.com or GitHub/Cloud",
            "what_was_found": "Exact description",
            "why_its_vulnerable": "Technical flaw",
            "how_to_exploit": "Brief scenario",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
            "owasp_category": "e.g., A01:2021",
            "mitre_technique": "e.g., T1190"
        }}
    ]"""
    return call_gemini_with_retry(prompt)

def stage_5_ai_report(intel):
    print("[+] Running AI Stage 2: Final Report Generation...")
    prompt = f"""You are a CISO reporting assistant. Take this red team intelligence for '{TARGET}':
    {intel}
    
    Write a highly detailed, professional Markdown report. Include:
    1. 🎯 **Executive Summary:** (Risk score out of 100, highlight OSINT/Leaks immediately).
    2. ☣️ **OSINT & Leaks (CRITICAL):** Detail any GitHub code leaks or exposed Cloud buckets first. These are the highest priority.
    3. 🗺️ **Attack Surface Map:** Web assets, CDN protection, open ports.
    4. 🚨 **Vulnerable Endpoints:** Web misconfigurations, API exposures, Open Redirects.
    5. 🛡️ **OWASP & MITRE Mapping:** Group findings.
    6. 🔧 **Remediation Steps:** Specific, actionable fixes."""
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
    print(f"=== OMNISCIENCE ENGINE v2.0 STARTED ===")
    
    # Stage 1: Web & Subdomain Recon
    assets = stage_1_recon(TARGET)
    
    # Stage 1.5: Passive OSINT (GitHub Leaks + Cloud Assets)
    osint_data = stage_1_5_osint(TARGET)
    
    # Stage 2: Web Security Audit
    assets = stage_2_web_audit(assets)
    
    # Stage 3: Network Origin Port Scan
    full_data = stage_3_network_scan(assets)
    
    with open('./cache/raw_data.json', 'w') as f:
        json.dump({"target": TARGET, "assets": full_data, "osint": osint_data}, f, indent=2)
    
    # Stage 4: AI Analysis (Now includes OSINT data!)
    intel = stage_4_ai_analysis(full_data, osint_data)
    with open('./cache/processed_intel.json', 'w') as f: f.write(intel)
        
    # Stage 5: AI Report
    report = stage_5_ai_report(intel)
    with open('./cache/final_report.md', 'w') as f: f.write(report)
        
    # Stage 6: Delivery
    stage_6_deliver(report)
    print(f"=== OMNISCIENCE ENGINE COMPLETE ===")
