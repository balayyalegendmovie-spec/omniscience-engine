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
    """Raw REST API call to Gemini using gemini-flash-latest"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    
    payload = {
        "contents": [{"parts":[{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 8192
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=90)
        
        if response.status_code == 200:
            data = response.json()
            if 'candidates' in data and len(data['candidates']) > 0:
                print("[+] Successfully used model: gemini-flash-latest")
                return data['candidates'][0]['content']['parts'][0]['text']
            else:
                raise Exception("API returned 200 but no candidates found.")
        elif response.status_code == 429:
            raise Exception("Rate limited (429). Need to rotate key.")
        else:
            raise Exception(f"API Error {response.status_code}: {response.text[:200]}")
            
    except requests.exceptions.Timeout:
        raise Exception("API request timed out.")
    except Exception as e:
        raise Exception(f"Request failed: {str(e)}")

def call_gemini_with_retry(prompt):
    """Try calling Gemini with key rotation on failure"""
    keys = [k for k in API_KEYS if k]
    random.shuffle(keys)  # Randomize key order so we don't always hit Key 1 first
    
    for i, key in enumerate(keys):
        try:
            print(f"[+] Attempting API Key #{i+1}...")
            return call_gemini(prompt, key)
        except Exception as e:
            print(f"[-] Key #{i+1} failed: {str(e)}")
            continue
    
    # If ALL keys failed
    raise Exception("All 6 API keys exhausted or failed. Check your keys and billing.")

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
    
    response_text = call_gemini_with_retry(prompt)
    
    with open('./cache/processed_intel.json', 'w') as f:
        f.write(response_text)
    return response_text

def stage_3_ai_report(processed_intel):
    """STAGE 3: Gemini builds the final polished report"""
    print("[+] Running AI Stage 2: Report Generation...")
    
    prompt = f"""You are a CISO reporting assistant. Take this threat intelligence JSON:
    {processed_intel}
    
    Write a clean, formatted Markdown report for the target '{TARGET}'.
    Include:
    1. Executive Summary (Risk score out of 100)
    2. Critical Findings Table
    3. MITRE ATT&CK Attack Path
    4. Immediate Remediation Steps"""
    
    response_text = call_gemini_with_retry(prompt)
    
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
        resp = requests.post(CALLBACK_URL, json=payload, timeout=30)
        print(f"[+] Delivery response: {resp.status_code}")
    except Exception as e:
        print(f"[-] Delivery failed: {e}")

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
