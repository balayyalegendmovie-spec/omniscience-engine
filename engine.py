import os
import json
import random
import requests
import socket
import urllib3
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = os.environ.get('TARGET')
CHAT_ID = os.environ.get('CHAT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL')
API_KEYS = [os.environ.get(f'GEMINI_KEY_{i}') for i in range(1, 7)]
FALSE_PATTERNS = [p.strip().upper() for p in os.environ.get('FALSE_PATTERNS', '').split(',') if p.strip()]

# GITHUB ACTIONS SUMMARY LOGING
SUMMARY_FILE = os.environ.get('GITHUB_STEP_SUMMARY')
def log_summary(text):
    print(text) # Keep console logging too
    if SUMMARY_FILE:
        try:
            with open(SUMMARY_FILE, 'a') as f: f.write(text + "\n")
        except: pass

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
CDN_SERVERS = ['cloudflare', 'akamai', 'sucuri', 'incapsula', 'cloudfront', 'awselb', 'fastly']
SENSITIVE_PATHS = ['/.git/HEAD', '/.env', '/.svn/entries', '/wp-config.php', '/wp-login.php', '/phpinfo.php', '/admin', '/robots.txt', '/sitemap.xml', '/server-status', '/config.yml', '/package.json']
ADVANCED_ENDPOINTS = ['/api/v1', '/swagger-ui.html', '/swagger.json', '/openapi.json', '/graphql', '/actuator/health', '/actuator/env', '/wp-json/wp/v2/users', '/console']
REDIRECT_PARAMS = ['url', 'redirect', 'next', 'continue', 'return', 'dest', 'target']
SECURITY_HEADERS = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options']

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Private Key": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\s\"']+",
    "Generic Secret": r"(?:secret_key|api_key|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
}

TAKEOVER_FINGERPRINTS = {
    "aws_s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "heroku": ["No such app", "herokucdn"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "github": ["There isn't a GitHub Pages site here"],
    "pantheon": ["404 error unknown site", "Pantheon"],
    "zendesk": ["Help Center Closed", "zendesk.com"],
    "tumblr": ["Whatever you were looking for doesn't currently exist"],
    "wordpress": ["Do you want to register"]
}

# ==========================================
# STAGE 1: DEEP RECON
# ==========================================
def fetch_crtsh(t):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{t}&output=json", timeout=20)
        if r.status_code == 200:
            for e in r.json():
                for s in e.get('name_value', '').split('\n'):
                    s = s.strip().lower()
                    if not s.startswith('*') and s.endswith(t): subs.add(s)
    except: pass
    return subs

def fetch_hackertarget(t):
    subs = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={t}", timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            for l in r.text.splitlines():
                p = l.split(",")
                if len(p) == 2: subs.add(p[0].strip().lower())
    except: pass
    return subs

def resolve_dns(s):
    try: return socket.gethostbyname(s)
    except: return None

def probe_subdomain(sub):
    res = {
        "host": sub, "ip": None, "is_cdn": False, "http_status": None, 
        "title": None, "server": None, "technologies": [], "missing_headers": [], 
        "sensitive_files": [], "hidden_api_endpoints": [], "js_files": [], 
        "cookie_issues": [], "data_leaks": [], "open_redirects": [], "cors_issue": None
    }
    ip = resolve_dns(sub)
    if not ip: return res
    res["ip"] = ip
    
    for scheme in ['https', 'http']:
        try:
            r = requests.get(f"{scheme}://{sub}", timeout=5, verify=False, allow_redirects=True)
            res["http_status"] = r.status_code
            if "<title>" in r.text.lower():
                s = r.text.lower().find("<title>") + 7; e = r.text.lower().find("</title>", s)
                res["title"] = r.text[s:e].strip()[:100]
            server = r.headers.get("Server", "Unknown")
            res["server"] = server
            if any(cdn in server.lower() for cdn in CDN_SERVERS): res["is_cdn"] = True
            techs = []
            if r.headers.get("X-Powered-By"): techs.append(f"X-Powered-By: {r.headers.get('X-Powered-By')}")
            if r.headers.get("X-AspNet-Version"): techs.append(f"ASP.NET: {r.headers.get('X-AspNet-Version')}")
            res["technologies"] = techs
            res["missing_headers"] = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in r.headers.keys()]]
            res["hidden_api_endpoints"] = list(set(re.findall(r'(?:["\'])(/(?:api|v[0-9]|graphql|rest|auth|admin)/[^"\']*)(?:["\'])', r.text)))[:10]
            res["js_files"] = [requests.compat.urljoin(f"{scheme}://{sub}", link) for link in re.findall(r'(?:src=["\'])([^"\']+\.js(?:\?[^"\']*)?)', r.text)[:5]]
            bad_cookies = []
            for cookie in r.cookies:
                if not cookie.secure: bad_cookies.append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr('httponly'): bad_cookies.append(f"Cookie '{cookie.name}' missing HttpOnly")
            res["cookie_issues"] = bad_cookies
            break
        except: continue
    return res

def stage_1_recon(target):
    log_summary(f"## 🔎 Stage 1: Deep Recon on `{target}`")
    subs = fetch_crtsh(target) | fetch_hackertarget(target)
    subs.add(target)
    log_summary(f"- 📡 Found **{len(subs)}** unique subdomains from APIs.")
    alive = []
    with ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(probe_subdomain, s): s for s in subs}
        for f in as_completed(futs):
            try:
                r = f.result()
                if r["ip"]: alive.append(r)
            except: pass
    log_summary(f"- ✅ **{len(alive)}** hosts alive and responding.")
    return alive

# ==========================================
# STAGE 1.5: OSINT
# ==========================================
def github_secret_dorking(t):
    leaks = []
    for q in [f'"{t}" password', f'"{t}" .env', f'"{t}" api_key']:
        try:
            r = requests.get("https://api.github.com/search/code", params={"q": q, "per_page": 3}, headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "OMNI"}, timeout=15)
            if r.status_code == 200 and r.json().get("total_count", 0) > 0:
                for i in r.json().get("items", []): leaks.append({"file": i["path"], "repo": i["repository"]["full_name"], "url": i["html_url"]})
            time.sleep(3)
        except: pass
    return leaks

def discover_cloud_assets(t):
    org = t.split('.')[0]
    perms = [f"{org}-backup", f"{org}-dev", f"{org}-staging", f"{org}-bucket", t.replace('.', '-')]
    exposed = []
    def check_s3(p):
        try:
            r = requests.get(f"http://{p}.s3.amazonaws.com", timeout=4)
            if r.status_code == 200: return {"type": "AWS S3 (PUBLIC)", "url": f"http://{p}.s3.amazonaws.com", "severity": "CRITICAL"}
            elif r.status_code == 403: return {"type": "AWS S3 (EXISTS)", "url": f"http://{p}.s3.amazonaws.com", "severity": "INFO"}
        except: pass
    def check_fb(p):
        try:
            r = requests.get(f"https://{p}.firebaseio.com/.json", timeout=4)
            if r.status_code == 200 and r.text != "null": return {"type": "Firebase (PUBLIC)", "url": f"https://{p}.firebaseio.com", "severity": "CRITICAL"}
        except: pass
    with ThreadPoolExecutor(max_workers=15) as ex:
        for f in as_completed([ex.submit(check_s3, p) for p in perms] + [ex.submit(check_fb, p) for p in perms]):
            res = f.result()
            if res: exposed.append(res)
    return exposed

def stage_1_5_osint(t):
    log_summary("## 🕵️ Stage 1.5: Passive OSINT")
    gh = github_secret_dorking(t)
    ca = discover_cloud_assets(t)
    log_summary(f"- GitHub Leaks: **{len(gh)}** found.")
    log_summary(f"- Cloud Assets: **{len(ca)}** discovered.")
    return {"github_leaks": gh, "cloud_assets": ca}

def stage_1_8_dns_txt(target):
    log_summary("## 📜 Stage 1.8: DNS TXT Intelligence")
    txts = []
    try:
        r = requests.get(f"https://dns.google/resolve?name={target}&type=TXT", timeout=5)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                txts.append(ans.get("data", ""))
    except: pass
    log_summary(f"- Extracted **{len(txts)}** TXT records (SPF, Domain Verifications, etc.).")
    return txts

# ==========================================
# STAGE 2: WEB AUDIT (FIXED)
# ==========================================
def check_path(u, p):
    try:
        r = requests.get(f"{u}{p}", timeout=4, verify=False, allow_redirects=False)
        if r.status_code in [200, 403, 401]: return {"path": p, "status": r.status_code}
    except: pass

def check_redirect(u, p):
    try:
        r = requests.get(f"{u}/?{p}=https://evil.com", timeout=4, verify=False, allow_redirects=False)
        if r.status_code in [301, 302, 303] and "evil.com" in r.headers.get('Location', ''): return {"parameter": p}
    except: pass

def check_cors(u):
    try:
        r = requests.get(u, headers={"Origin": "https://evil.com"}, timeout=4, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if "evil.com" in acao and r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
            return {"issue": "CORS Misconfiguration"}
    except: pass

def check_error_leaks(u):
    leaks = []
    for p in ["'", "{{7*7}}"]:
        try:
            r = requests.get(f"{u}/?id={p}", timeout=4, verify=False)
            text = r.text.lower()
            if "sql syntax" in text or "mysql_" in text: leaks.append({"type": "SQL Error Leak", "payload": p})
            elif "49" in r.text and p == "{{7*7}}": leaks.append({"type": "SSTI Detected", "payload": p})
        except: pass
    return leaks

def stage_2_web_audit(assets):
    log_summary("## 🌐 Stage 2: Web Vulnerability Audit")
    total_paths = 0
    total_redirs = 0
    total_leaks = 0
    for a in assets:
        if not a["http_status"]: continue
        b = f"https://{a['host']}"
        found = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            for f in as_completed([ex.submit(check_path, b, p) for p in SENSITIVE_PATHS + ADVANCED_ENDPOINTS]):
                res = f.result()
                if res: found.append(res)
        a["sensitive_files"] = found
        total_paths += len(found)
        
        redirs = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            for f in as_completed([ex.submit(check_redirect, b, p) for p in REDIRECT_PARAMS]):
                res = f.result()
                if res: redirs.append(res)
        a["open_redirects"] = redirs
        total_redirs += len(redirs)
        
        a["cors_issue"] = check_cors(b)
        a["data_leaks"] = check_error_leaks(b)
        total_leaks += len(a["data_leaks"])
        
    # FIXED TYPO HERE: f"- ..." changed to f"..."
    log_summary(f"- Exposed Paths: **{total_paths}**")
    log_summary(f"- Open Redirects: **{total_redirs}**")
    log_summary(f"- Error/Injection Leaks: **{total_leaks}**")
    return assets

# ==========================================
# STAGE 2.5: HISTORY & JS SECRETS
# ==========================================
def fetch_wayback_urls(target):
    interesting_paths = set()
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original,timestamp,statuscode&limit=200", timeout=15)
        if r.status_code == 200:
            for entry in r.json()[1:]:
                path = urlparse(entry[0]).path
                if any(kw in path.lower() for kw in ['admin', 'api', 'config', 'login', 'dashboard', 'upload', 'db', 'user', 'env']):
                    interesting_paths.add(path)
    except: pass
    return list(interesting_paths)[:30]

def extract_js_secrets(js_urls):
    found_secrets = []
    for url in js_urls:
        try:
            r = requests.get(url, timeout=5, verify=False)
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, r.text)
                for m in matches: found_secrets.append({"file": url, "type": name, "value": m[:50] + "..." if len(m) > 50 else m})
        except: pass
    return found_secrets

def stage_2_5_history_and_secrets(assets, target):
    log_summary("## ⏳ Stage 2.5: Wayback History & JS Secrets")
    historical_paths = fetch_wayback_urls(target)
    log_summary(f"- Wayback Machine found **{len(historical_paths)}** interesting historical endpoints.")
    total_hist = 0
    total_js = 0
    for a in assets:
        if not a["http_status"]: continue
        b = f"https://{a['host']}"
        found_hist = []
        with ThreadPoolExecutor(max_workers=15) as ex:
            for f in as_completed([ex.submit(check_path, b, p) for p in historical_paths]):
                res = f.result()
                if res and res["status"] == 200: found_hist.append(res)
        a["historical_endpoints"] = found_hist
        total_hist += len(found_hist)
        
        a["js_secrets"] = extract_js_secrets(a.get("js_files", []))
        total_js += len(a["js_secrets"])
        
    log_summary(f"- Alive Historical Endpoints: **{total_hist}**")
    log_summary(f"- Hardcoded Secrets in JS: **{total_js}**")
    return assets

# ==========================================
# STAGE 2.8: SUBDOMAIN TAKEOVER
# ==========================================
def check_takeover(sub):
    try:
        r = requests.get(f"https://dns.google/resolve?name={sub}&type=CNAME", timeout=5)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                cname = ans.get("data", "").lower()
                if cname:
                    vulnerable_provider = None
                    if "s3.amazonaws.com" in cname: vulnerable_provider = "aws_s3"
                    elif "herokuapp.com" in cname: vulnerable_provider = "heroku"
                    elif "myshopify.com" in cname: vulnerable_provider = "shopify"
                    elif "github.io" in cname: vulnerable_provider = "github"
                    elif "zendesk.com" in cname: vulnerable_provider = "zendesk"
                    elif "tumblr.com" in cname: vulnerable_provider = "tumblr"
                    elif "wordpress.com" in cname: vulnerable_provider = "wordpress"
                    
                    if vulnerable_provider:
                        try:
                            web_r = requests.get(f"http://{sub}", timeout=5, verify=False)
                            for fp in TAKEOVER_FINGERPRINTS.get(vulnerable_provider, []):
                                if fp.lower() in web_r.text.lower():
                                    return {"subdomain": sub, "cname": cname, "provider": vulnerable_provider, "fingerprint": fp, "severity": "CRITICAL"}
                        except: pass
    except: pass
    return None

def stage_2_8_takeover_scan(assets):
    log_summary("## 💀 Stage 2.8: Subdomain Takeover Detection")
    takeovers = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(check_takeover, a["host"]): a["host"] for a in assets if a["ip"]}
        for f in as_completed(futs):
            res = f.result()
            if res: takeovers.append(res)
    log_summary(f"- Potential Takeovers: **{len(takeovers)}**")
    return takeovers

# ==========================================
# STAGE 3 & 3.5: PORTS & MEMORY
# ==========================================
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5)
        if s.connect_ex((ip, port)) == 0: return port
        s.close()
    except: pass

def stage_3_network_scan(assets):
    log_summary("## 🔌 Stage 3: Network Port Scanning")
    origins = [a for a in assets if not a["is_cdn"]]
    cdns = [a for a in assets if a["is_cdn"]]
    log_summary(f"- Scanning **{len(origins)}** Origin IPs (CDN skipped).")
    total_ports = 0
    for a in origins:
        ports = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            for f in as_completed([ex.submit(scan_port, a["ip"], p) for p in TOP_PORTS]):
                res = f.result()
                if res: ports.append(res)
        a["open_ports"] = sorted(ports) if ports else []
        total_ports += len(ports)
    for c in cdns: c["open_ports"] = ["CDN Protected"]
    log_summary(f"- Open Ports Found: **{total_ports}**")
    return origins + cdns

def apply_memory_filter(assets):
    if not FALSE_PATTERNS: return assets
    log_summary(f"## 🧠 Memory Filter Active: Ignoring `{FALSE_PATTERNS}`")
    for a in assets:
        a["sensitive_files"] = [f for f in a.get("sensitive_files", []) if not any(fp in json.dumps(f).upper() for fp in FALSE_PATTERNS)]
        a["data_leaks"] = [l for l in a.get("data_leaks", []) if not any(fp in json.dumps(l).upper() for fp in FALSE_PATTERNS)]
    return assets

# ==========================================
# AI & DELIVERY
# ==========================================
def call_gemini(prompt, key):
    r = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={key}", json={"contents": [{"parts":[{"text": prompt}]}], "generationConfig": {"temperature": 0.4, "maxOutputTokens": 8192}}, timeout=90)
    r.raise_for_status()
    return r.json()['candidates'][0]['content']['parts'][0]['text']

def call_gemini_retry(prompt):
    keys = [k for k in API_KEYS if k]; random.shuffle(keys)
    for i, k in enumerate(keys):
        try: log_summary(f"🤖 Gemini Key #{i+1} active..."); return call_gemini(prompt, k)
        except Exception as e: log_summary(f"❌ Key #{i+1} failed: {e}")
    raise Exception("Keys dead")

def stage_4_ai(data, osint, takeovers, txts):
    log_summary("## 🧠 Stage 4: AI Threat Analysis")
    prompt = f"""You are a Tier-1 Red Team Operator. Analyze this data for '{TARGET}':
    --- NETWORK & WEB --- {json.dumps(data, indent=2)}
    --- OSINT --- {json.dumps(osint, indent=2)}
    --- TAKEOVERS --- {json.dumps(takeovers, indent=2)}
    --- DNS TXT --- {json.dumps(txts, indent=2)}
    STRICT RULES: DO NOT GUESS. Takeovers -> CRITICAL. GitHub/Cloud/JS secrets -> CRITICAL. Historical endpoints -> HIGH. SSTI/SQLi -> Explain payload. Map to OWASP/MITRE.
    Output strictly as JSON array: [{{"asset": "...", "what_was_found": "...", "why_its_vulnerable": "...", "how_to_exploit": "...", "severity": "...", "owasp": "...", "mitre": "..."}}]"""
    intel = call_gemini_retry(prompt)
    log_summary("- ✅ Threat Extraction Complete.")
    return intel

def stage_5_report(intel):
    log_summary("## 📝 Stage 5: AI Report Generation")
    prompt = f"""You are a CISO assistant. Format this intel for '{TARGET}': {intel}
    Markdown report with: 1. 🎯 Exec Summary (Risk /100). 2. ☣️ OSINT/Leaks/JS Secrets. 3. 💀 Takeovers. 4. 🗺️ Attack Map. 5. 🚨 Vulns (History, SSTI, CORS, Cookies). 6. 🛡️ OWASP/MITRE. 7. 🔧 Fixes."""
    report = call_gemini_retry(prompt)
    log_summary("- ✅ Report Generated.")
    return report

def deliver(report):
    log_summary("## 🚀 Stage 6: Delivery")
    requests.post(CALLBACK_URL, json={"action": "delivery", "target": TARGET, "chat_id": CHAT_ID, "report": report}, timeout=30)
    log_summary("- ✅ Sent to Google Apps Script.")

if __name__ == "__main__":
    log_summary(f"# 🛡️ OMNISCIENCE v3.2.1 Scan: `{TARGET}`")
    log_summary(f"Started at: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n---")
    
    assets = stage_1_recon(TARGET)
    osint = stage_1_5_osint(TARGET)
    txts = stage_1_8_dns_txt(TARGET)
    assets = stage_2_web_audit(assets)
    assets = stage_2_5_history_and_secrets(assets, TARGET)
    takeovers = stage_2_8_takeover_scan(assets)
    full = stage_3_network_scan(assets)
    full = apply_memory_filter(full)
    
    with open('./cache/raw.json', 'w') as f: json.dump({"target": TARGET, "assets": full, "osint": osint, "takeovers": takeovers, "txts": txts}, f, indent=2)
    intel = stage_4_ai(full, osint, takeovers, txts)
    with open('./cache/intel.json', 'w') as f: f.write(intel)
    report = stage_5_report(intel)
    with open('./cache/report.md', 'w') as f: f.write(report)
    deliver(report)
    
    log_summary("\n---\n🟢 **SCAN COMPLETE**")
