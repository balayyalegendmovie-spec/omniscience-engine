import os
import json
import random
import requests
import socket
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warnings for probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
TARGET = os.environ.get('TARGET')
CHAT_ID = os.environ.get('CHAT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL')

API_KEYS = [
    os.environ.get('GEMINI_KEY_1'),
    os.environ.get('GEMINI_KEY_2'),
    os.environ.get('GEMINI_KEY_3'),
    os.environ.get('GEMINI_KEY_4'),
    os.environ.get('GEMINI_KEY_5'),
    os.environ.get('GEMINI_KEY_6')
]

# ==========================================
# STAGE 1: REAL RECON ENGINE
# ==========================================
def fetch_crtsh_subdomains(target):
    """Pull subdomains from Certificate Transparency logs"""
    print(f"[+] Querying crt.sh for {target}...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '')
                # Filter out wildcards and clean up
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if not sub.startswith('*') and sub.endswith(target):
                        subdomains.add(sub)
        print(f"[+] crt.sh found {len(subdomains)} unique subdomains.")
    except Exception as e:
        print(f"[-] crt.sh lookup failed: {e}")
    return list(subdomains)

def resolve_dns(subdomain):
    """Resolve subdomain to IP"""
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None

def probe_subdomain(subdomain):
    """Probe subdomain for HTTP/HTTPS status, title, and server"""
    result = {"host": subdomain, "ip": None, "http_status": None, "title": None, "server": None}
    
    # Resolve DNS
    ip = resolve_dns(subdomain)
    if not ip:
        return result
    result["ip"] = ip
    
    # Probe HTTPS first, then HTTP
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{subdomain}"
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            result["http_status"] = response.status_code
            
            # Extract title
            if "<title>" in response.text.lower():
                start = response.text.lower().find("<title>") + 7
                end = response.text.lower().find("</title>", start)
                result["title"] = response.text[start:end].strip()[:100]
            
            # Extract server header
            result["server"] = response.headers.get("Server", "Unknown")
            result["scheme"] = scheme
            break # Stop if HTTPS works
        except requests.RequestException:
            continue
            
    return result

def stage_1_recon(target):
    """STAGE 1: Real Recon Execution"""
    print(f"[+] Starting deep recon on {target}...")
    
    # 1. Get subdomains
    subdomains = fetch_crtsh_subdomains(target)
    
    # Add the base domain just in case
    if target not in subdomains:
        subdomains.append(target)
    
    # 2. Probe subdomains concurrently (Speed!)
    print(f"[+] Probing {len(subdomains)} subdomains concurrently...")
    probed_data = []
    
    with ThreadPoolExecutor(max_workers=25) as executor:
        future_to_sub = {executor.submit(probe_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            try:
                result = future.result()
                # Only keep subdomains that resolved and responded
                if result["ip"] and result["http_status"]:
                    probed_data.append(result)
            except Exception as e:
                pass
    
    # Sort by status code for clean output
    probed_data.sort(key=lambda x: (x['http_status'] or 999))
    
    raw_data = {
        "target": target,
        "total_subdomains_found": len(subdomains),
        "alive_hosts": len(probed_data),
        "assets": probed_data
    }
    
    print(f"[+] Recon complete. {len(probed_data)} alive hosts found.")
    
    with open('./cache/raw_data.json', 'w') as f:
        json.dump(raw_data, f, indent=2)
    return raw_data

# ==========================================
# STAGE 2 & 3: AI ANALYSIS (Updated Prompts)
# ==========================================
def call_gemini(prompt, api_key):
    """Raw REST API call to Gemini"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts":[{"text": prompt}]}],
        "generationConfig": { "temperature": 0.7, "maxOutputTokens": 8192 }
    }
    response = requests.post(url, json=payload, timeout=90)
    response.raise_for_status()
    data = response.json()
    return data['candidates'][0]['content']['parts'][0]['text']

def call_gemini_with_retry(prompt):
    keys = [k for k in API_KEYS if k]
    random.shuffle(keys)
    for i, key in enumerate(keys):
        try:
            print(f"[+] Attempting API Key #{i+1}...")
            return call_gemini(prompt, key)
        except Exception as e:
            print(f"[-] Key #{i+1} failed: {str(e)}")
            continue
    raise Exception("All API keys exhausted.")

def stage_2_ai_analysis(raw_data):
    """STAGE 2: Gemini extracts signal from noise"""
    print("[+] Running AI Stage 1: Threat Extraction & Mapping...")
    
    prompt = f"""You are an expert Threat Intelligence Analyst. Analyze this raw recon data for '{TARGET}':
    {json.dumps(raw_data, indent=2)}
    
    Focus on:
    1. Identifying interesting subdomains (e.g., dev, staging, admin, api, internal, jenkins, jira).
    2. Technology fingerprinting based on the 'server' headers.
    3. Any hosts returning unusual status codes (e.g., 403, 500, 200 on internal-looking titles).
    4. Map potential attack vectors to MITRE ATT&CK (Tactic, Technique).
    
    Output strictly as JSON array:
    [
        {{
            "asset": "subdomain.target.com",
            "finding": "Description of what was found",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
            "mitre_tactic": "Tactic (TA####)",
            "mitre_technique": "Technique (T####)",
            "evidence": "Why this matters"
        }}
    ]"""
    
    response_text = call_gemini_with_retry(prompt)
    with open('./cache/processed_intel.json', 'w') as f:
        f.write(response_text)
    return response_text

def stage_3_ai_report(processed_intel):
    """STAGE 3: Gemini builds the final report"""
    print("[+] Running AI Stage 2: Report Generation...")
    
    prompt = f"""You are a CISO reporting assistant. Take this threat intelligence JSON for '{TARGET}':
    {processed_intel}
    
    Write a clean, formatted Markdown report. Include:
    1. 🎯 **Executive Summary:** (Risk score out of 100, brief overview)
    2. 🗺️ **Attack Surface Map:** Summarize the alive hosts and technologies found.
    3. 🚨 **Critical Findings:** A table of the highest severity items.
    4. 🛡️ **MITRE ATT&CK Mapping:** Group findings by Tactic.
    5. 🔧 **Remediation Steps:** Immediate actions to take.
    
    Make it look professional with emojis and clean Markdown."""
    
    response_text = call_gemini_with_retry(prompt)
    with open('./cache/final_report.md', 'w') as f:
        f.write(response_text)
    return response_text

# ==========================================
# STAGE 4: DELIVERY
# ==========================================
def stage_4_deliver(report_markdown):
    print("[+] Delivering report to Cloudflare/GAS...")
    payload = {
        "action": "delivery",
        "target": TARGET,
        "chat_id": CHAT_ID,
        "report": report_markdown
    }
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
    print(f"Chat ID: {CHAT_ID}")
    print(f"Callback: {CALLBACK_URL}")
    print(f"API Keys loaded: {sum(1 for k in API_KEYS if k)}")
    print(f"=================================")
    
    raw = stage_1_recon(TARGET)
    intel = stage_2_ai_analysis(raw)
    report = stage_3_ai_report(intel)
    stage_4_deliver(report)
    
    print(f"=== OMNISCIENCE ENGINE COMPLETE ===")
