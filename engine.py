import os
import json
import random
import requests

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

def call_gemini(prompt, api_key):
    """Raw REST API call to Gemini - Bulletproof method"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts":[{"text": prompt}]}]
    }
    response = requests.post(url, json=payload)
    response.raise_for_status() # Fail fast if error
    data = response.json()
    return data['candidates'][0]['content']['parts'][0]['text']

def stage_1_recon(target):
    """STAGE 1: Simulate raw recon"""
    print(f"[+] Running recon on {target}...")
    raw_data = {
        "target": target,
        "open_ports": [80, 443, 8080, 22],
        "headers": {
            "server": "Apache/2.4.49",
            "x-powered-by": "PHP/8.1.0",
            "strict-transport-security": "MISSING"
        },
        "subdomains": [f"www.{target}", f"api.{target}", f"dev.{target}"],
        "js_files": [f"https://{target}/app.js", f"https://{target}/vendor.js"]
    }
    
    with open('./cache/raw_data.json', 'w') as f:
        json.dump(raw_data, f, indent=2)
    return raw_data

def stage_2_ai_analysis(raw_data):
    """STAGE 2: Gemini extracts signal from noise & maps MITRE"""
    print("[+] Running AI Stage 1: Threat Extraction...")
    key = random.choice([k for k in API_KEYS if k]) # Pick a valid key
    
    prompt = f"""You are an expert Threat Intelligence Analyst. Analyze this raw recon data:
    {json.dumps(raw_data)}
    
    Extract ONLY legitimate vulnerabilities. Map each to MITRE ATT&CK (Tactic, Technique).
    Output strictly as JSON array:
    [
        {{
            "vuln": "Apache 2.4.49 Path Traversal",
            "severity": "CRITICAL",
            "mitre_tactic": "Initial Access (TA0001)",
            "mitre_technique": "Exploit Public-Facing Application (T1190)",
            "evidence": "Server header shows Apache/2.4.49"
        }}
    ]"""
    
    response_text = call_gemini(prompt, key)
    
    with open('./cache/processed_intel.json', 'w') as f:
        f.write(response_text)
    return response_text

def stage_3_ai_report(processed_intel):
    """STAGE 3: Gemini builds the final polished report"""
    print("[+] Running AI Stage 2: Report Generation...")
    keys = [k for k in API_KEYS if k]
    key = random.choice(keys)
    
    prompt = f"""You are a CISO reporting assistant. Take this threat intelligence JSON:
    {processed_intel}
    
    Write a clean, formatted Markdown report for the target '{TARGET}'.
    Include:
    1. Executive Summary (Risk score out of 100)
    2. Critical Findings Table
    3. MITRE ATT&CK Attack Path
    4. Immediate Remediation Steps"""
    
    response_text = call_gemini(prompt, key)
    
    with open('./cache/final_report.md', 'w') as f:
        f.write(response_text)
    return response_text

def stage_4_deliver(report_markdown):
    """STAGE 4: Send report back to GAS via Cloudflare"""
    print("[+] Delivering report to Cloudflare/GAS...")
    payload = {
        "action": "delivery",
        "target": TARGET,
        "chat_id": CHAT_ID,
        "report": report_markdown
    }
    
    try:
        requests.post(CALLBACK_URL, json=payload)
        print("[+] Delivery successful!")
    except Exception as e:
        print(f"[-] Delivery failed: {e}")

if __name__ == "__main__":
    raw = stage_1_recon(TARGET)
    intel = stage_2_ai_analysis(raw)
    report = stage_3_ai_report(intel)
    stage_4_deliver(report)
