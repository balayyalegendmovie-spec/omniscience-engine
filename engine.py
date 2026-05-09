import os
import json
import random
import requests
import socket
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
TARGET = os.environ.get('TARGET')
CHAT_ID = os.environ.get('CHAT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL')

API_KEYS = [
    os.environ.get('GEMINI_KEY_1'), os.environ.get('GEMINI_KEY_2'),
    os.environ.get('GEMINI_KEY_3'), os.environ.get('GEMINI_KEY_4'),
    os.environ.get('GEMINI_KEY_5'), os.environ.get('GEMINI_KEY_6')
]

# Top 50 critical ports to scan (No Nmap needed, pure Python sockets)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
    143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 27017, 11211,
    5000, 5001, 8000, 8001, 8181, 8500, 9000, 9443, 10000, 10443,
    2222, 22222, 4443, 6080, 7080, 7443, 8090, 8800, 9080, 16080
]

# ==========================================
# STAGE 1: RECON (Subdomains & Web)
# ==========================================
def fetch_crtsh_subdomains(target):
    print(f"[+] Querying crt.sh for {target}...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if not sub.startswith('*') and sub.endswith(target):
                        subdomains.add(sub)
        print(f"[+] crt.sh found {len(subdomains)} unique subdomains.")
    except Exception as e:
        print(f"[-] crt.sh lookup failed: {e}")
    return list(subdomains)

def resolve_dns(subdomain):
    try: return socket.gethostbyname(subdomain)
    except socket.gaierror: return None

def probe_subdomain(subdomain):
    result = {"host": subdomain, "ip": None, "http_status": None, "title": None, "server": None}
    ip = resolve_dns(subdomain)
    if not ip: return result
    result["ip"] = ip
    
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{subdomain}"
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            result["http_status"] = response.status_code
            if "<title>" in response.text.lower():
                start = response.text.lower().find("<title>") + 7
                end = response.text.lower().find("</title>", start)
                result["title"] = response.text[start:end].strip()[:100]
            result["server"] = response.headers.get("Server", "Unknown")
            result["scheme"] = scheme
            break
        except requests.RequestException: continue
    return result

def stage_1_recon(target):
    print(f"[+] Starting deep recon on {target}...")
    subdomains = fetch_crtsh_subdomains(target)
    if target not in subdomains: subdomains.append(target)
    
    print(f"[+] Probing {len(subdomains)} subdomains concurrently...")
    probed_data = []
    with ThreadPoolExecutor(max_workers=25) as executor:
        future_to_sub = {executor.submit(probe_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            try:
                result = future.result()
                if result["ip"]: probed_data.append(result)
            except: pass
    
    probed_data.sort(key=lambda x: (x['http_status'] or 999))
    print(f"[+] Web recon complete. {len(probed_data)} alive hosts found.")
    return probed_data

# ==========================================
# STAGE 2: NETWORK (Port Scanning)
# ==========================================
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5) # Fast timeout
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0: return port
        return None
    except: return None

def stage_2_network_scan(alive_assets):
    print(f"[+] Starting network port scanning on {len(alive_assets)} assets...")
    network_data = []
    
    for asset in alive_assets:
        ip = asset.get("ip")
        if not ip: continue
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in TOP_PORTS}
            for future in as_completed(future_to_port):
                try:
                    port = future.result()
                    if port: open_ports.append(port)
                except: pass
        
        if open_ports:
            open_ports.sort()
            asset["open_ports"] = open_ports
            network_data.append(asset)
            print(f"  -> {asset['host']} ({ip}): {len(open_ports)} open ports found {open_ports}")
        else:
            asset["open_ports"] = []
            network_data.append(asset)
            
    print(f"[+] Network scanning complete.")
    return network_data

# ==========================================
# STAGE 3 & 4: AI ANALYSIS & REPORTING
# ==========================================
def call_gemini(prompt, api_key):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    payload = {"contents": [{"parts":[{"text": prompt}]}], "generationConfig": { "temperature": 0.7, "maxOutputTokens": 8192 }}
    response = requests.post(url, json=payload, timeout=90)
    response.raise_for_status()
    return response.json()['candidates'][0]['content']['parts'][0]['text']

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

def stage_3_ai_analysis(recon_data):
    print("[+] Running AI Stage 1: Deep Threat Extraction...")
    prompt = f"""You are an expert Threat Intelligence Analyst. Analyze this combined recon and network data for '{TARGET}':
    {json.dumps(recon_data, indent=2)}
    
    Focus on:
    1. Exposed administrative ports (22, 3389, 5900, 3306, 6379, 27017) accessible to the internet.
    2. Dangerous service combinations (e.g., Web + FTP + Database open on same host).
    3. Outdated web technologies found in Stage 1.
    4. Map potential attack vectors to MITRE ATT&CK (Tactic, Technique).
    
    Output strictly as JSON array:
    [
        {{
            "asset": "subdomain.target.com",
            "ip": "x.x.x.x",
            "finding": "Description of the vulnerability/exposure",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
            "mitre_tactic": "Tactic (TA####)",
            "mitre_technique": "Technique (T####)",
            "evidence": "Ports open / Headers found / Reasoning"
        }}
    ]"""
    return call_gemini_with_retry(prompt)

def stage_4_ai_report(processed_intel):
    print("[+] Running AI Stage 2: Final Report Generation...")
    prompt = f"""You are a CISO reporting assistant. Take this threat intelligence JSON for '{TARGET}':
    {processed_intel}
    
    Write a clean, formatted Markdown report. Include:
    1. 🎯 **Executive Summary:** (Risk score out of 100, brief overview)
    2. 🗺️ **Attack Surface Map:** Summarize alive hosts, technologies, and exposed ports.
    3. 🚨 **Critical Findings:** A table of the highest severity items (include open ports in the table!).
    4. 🛡️ **MITRE ATT&CK Mapping:** Group findings by Tactic.
    5. 🔗 **Attack Paths:** Chain 1-2 realistic attack scenarios (e.g., "Open SSH -> Brute force -> Lateral movement to exposed DB").
    6. 🔧 **Remediation Steps:** Immediate actions to take.
    
    Make it look professional with emojis and clean Markdown."""
    return call_gemini_with_retry(prompt)

# ==========================================
# STAGE 5: DELIVERY
# ==========================================
def stage_5_deliver(report_markdown):
    print("[+] Delivering report to Cloudflare/GAS...")
    payload = {"action": "delivery", "target": TARGET, "chat_id": CHAT_ID, "report": report_markdown}
    try:
        resp = requests.post(CALLBACK_URL, json=payload, timeout=30)
        print(f"[+] Delivery response: {resp.status_code}")
    except Exception as e:
        print(f"[-] Delivery failed: {e}")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print(f"=== OMNISCIENCE ENGINE STARTED ===")
    print(f"Target: {TARGET}")
    
    # Stage 1: Web & Subdomain Recon
    alive_assets = stage_1_recon(TARGET)
    
    # Stage 2: Network Port Scanning
    full_recon_data = stage_2_network_scan(alive_assets)
    
    # Save full combined data to cache
    with open('./cache/raw_data.json', 'w') as f:
        json.dump({"target": TARGET, "assets": full_recon_data}, f, indent=2)
    
    # Stage 3: AI Analysis
    intel = stage_3_ai_analysis(full_recon_data)
    with open('./cache/processed_intel.json', 'w') as f:
        f.write(intel)
        
    # Stage 4: AI Reporting
    report = stage_4_ai_report(intel)
    with open('./cache/final_report.md', 'w') as f:
        f.write(report)
        
    # Stage 5: Delivery
    stage_5_deliver(report)
    
    print(f"=== OMNISCIENCE ENGINE COMPLETE ===")
