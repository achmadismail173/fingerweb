#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🕵️ FingerWeb — Web Tech Detective CLI
Versi 1.0
"""

import argparse
import requests
import re
import json
import sys
import hashlib
import mmh3
import base64
import ssl
import socket
import urllib3
import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_TIMEOUT = 10
DEFAULT_FAVICON_DB = "db_favicon.json"

# ────────────────────────────────
# Banner
# ────────────────────────────────
BANNER = f"""
{Fore.MAGENTA}╔══════════════════════════════════════════════════════════════╗
{Fore.MAGENTA}║ {Fore.YELLOW}  🕵️ FingerWeb — Web Tech Detective CLI (v1.0)             {Fore.MAGENTA}  ║
{Fore.MAGENTA}║ {Fore.CYAN}  ✨ Powered by X'1N73CT                                   {Fore.MAGENTA}  ║
{Fore.MAGENTA}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ────────────────────────────────
# JS Framework Signatures
# ────────────────────────────────
JS_FRAMEWORK_SIGNATURES = {
    "Next.js": [
        ("header", r"x-powered-by: next\\.js", 70),
        ("body", r"_next/static|_next/chunks", 50),
    ],
    "Nuxt.js": [
        ("body", r"__NUXT__|data-nuxt=", 60),
    ],
    "Gatsby": [
        ("body", r"/static/\\w+/.+\\.js", 40),
        ("meta_generator", r"gatsby", 40),
    ],
    "Angular": [
        ("body", r"ng-version|data-version=", 50), 
        ("script_src", r"angular", 40),            
    ],
    "React": [
        ("body", r"data-reactroot|reactroot", 40),
        ("script_src", r"react", 30),
    ],
    "Vue.js": [
        ("body", r"__VUE_DEVTOOLS_GLOBAL_HOOK__|vue-app", 40),
        ("script_src", r"vue", 30),
    ],
    "jQuery": [
        ("script_src", r"jquery", 20),
    ],
    "Bootstrap": [
        ("body", r"bootstrap", 20),
        ("script_src", r"bootstrap", 20),
    ],
}

# ────────────────────────────────
# CMS / Framework signatures
# ────────────────────────────────
SIGNATURES = {
    # ----------------------------------------------------
    # A. Content Management Systems (CMS)
    # ----------------------------------------------------
    "WordPress": [
        ("meta_generator", r"wordpress", 60),
        ("path", r"/wp-login.php", 60),
        ("body", r"wp-content", 20),
        ("script_src", r"wp-includes", 20),
    ],
    "Joomla": [
        ("meta_generator", r"joomla", 60),
        ("path", r"/administrator/", 50),
    ],
    "Drupal": [
        ("meta_generator", r"drupal", 60),
        ("body", r"sites/default", 30),
    ],
    "Typo3": [
        ("meta_generator", r"typo3", 60),
    ],
    "Ghost": [
        ("meta_generator", r"ghost", 60),
    ],

    # ----------------------------------------------------
    # B. Frameworks Backend
    # ----------------------------------------------------
    "Ruby on Rails": [
        ("header", r"x-powered-by: phusion passenger|server: passenger", 75),
        ("cookie", r"_session|_rails_session", 40),
        ("body", r"csrf-param|csrf-token", 10),
    ],
    "Laravel": [
        ("cookie", r"laravel_session", 70),
        ("body", r"csrf-token", 30),
    ],
    "Django": [
        ("cookie", r"csrftoken", 70),
        ("body", r"csrfmiddlewaretoken", 30),
    ],
    "Express": [
        ("header", r"x-powered-by: express", 70),
    ],
    "ASP.NET": [
        ("header", r"x-powered-by: asp\\.net|x-aspnet-version", 50),
        ("body", r"__VIEWSTATE|__EVENTVALIDATION", 30),
    ],
    "CodeIgniter": [
        ("cookie", r"ci_session", 70),
    ],
    "Yii": [
        ("cookie", r"yii", 50),
    ],
    "PHP": [
        ("header", r"x-powered-by: php", 20),
    ],

    # ----------------------------------------------------
    # D. E-Commerce
    # ----------------------------------------------------
    "Shopify": [
        ("body", r"cdn\\.shopify\\.com|shopify\\.js", 70),
        ("script_src", r"shopify", 50),
    ],
    "WooCommerce": [
        ("body", r"woocommerce", 50),
    ],
    "Magento": [
        ("meta_generator", r"magento", 60),
        ("path", r"/skin/frontend/", 50),
    ],
    "PrestaShop": [
        ("meta_generator", r"prestashop", 60),
    ],

    # ----------------------------------------------------
    # E. Server Web / Cache
    # ----------------------------------------------------
    "Apache": [
        ("header", r"server:.*apache", 10),
    ],
    "Nginx": [
        ("header", r"server:.*nginx", 10),
    ],
    "Varnish": [
        ("header", r"x-varnish|via:.*varnish", 40),
    ],
    "IIS": [
        ("header", r"server:.*iis", 20),
    ],
}


# ────────────────────────────────
# CI/CD indicators & Other Signatures
# ────────────────────────────────
CICD_PATHS = [
    ".gitlab-ci.yml", ".travis.yml", "bitbucket-pipelines.yml",
    "azure-pipelines.yml", "drone.yml",
    "jenkins/", "job/", "hudson/",
    "teamcity/", ".circleci/config.yml",
    ".github/workflows/", ".git/HEAD", ".svn/entries",
    "build/", "target/", "dist/",
    ".hg/store/",
    "web-inf/web.xml",
    "sitemap.xml", "robots.txt",
]

SECURITY_HEADERS = [
     "Strict-Transport-Security", 
    "Content-Security-Policy",
    "X-Frame-Options", 
    "X-Content-Type-Options", 
    "Referrer-Policy",
    "Permissions-Policy",
    "Expect-CT",
    "X-XSS-Protection",
]

INFRA_SIGNATURES = {
   "Cloudflare": ["cf-ray", "server: cloudflare"],
    "Amazon CloudFront": ["x-amz-cf-id", "server: cloudfront"],
    "Akamai": ["x-akamai-transformed", "server: akamai"],
    "Google Cloud/GWS": ["server: gws", "x-goog-stored-content-length"],
    "Varnish Cache": ["x-varnish", "via:.*varnish"],
    "F5 BIG-IP": ["set-cookie: bigip"],
    "Incapsula": ["x-iinfo"],
    "Fastly": ["fastly-request-id", "x-fastly-backend"],
    "Netlify": ["x-nf-request-id"],
    "Azure Front Door": ["x-azure-ref", "x-cache:.*azure"]
}


# ────────────────────────────────
# Helper Functions
# ────────────────────────────────
def fetch(url, timeout=DEFAULT_TIMEOUT):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) FingerWeb/2.2'}
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True, headers=headers)
        return r
    except Exception:
        return None

def _run_detection(url, resp, signature_db):
    """Fungsi pembantu untuk menjalankan logika deteksi pada DB tertentu"""
    detections = {}
    text = resp.text.lower() if resp else ""
    headers = {k.lower(): v for k, v in resp.headers.items()} if resp else {}
    cookies = resp.cookies.get_dict() if resp else {}

    for name, rules in signature_db.items():
        score = 0
        version = None 
        
        for (rtype, pattern, pts) in rules:
            try:
                # Logika deteksi skor (tetap sama)
                if rtype == "meta_generator":
                    m = re.search(r'<meta name="generator" content="([^"]+)"', text)
                    if m and re.search(pattern, m.group(1), re.I): 
                        score += pts
                        # Coba ekstrak versi dari meta_generator
                        if name == "WordPress":
                            m_v = re.search(r'wordpress\s*([^"]+)', m.group(1), re.I)
                            if m_v: version = m_v.group(1).strip()
                        elif name == "Joomla":
                            m_v = re.search(r'joomla!\s*-\s*([^"]+)', m.group(1), re.I)
                            if m_v: version = m_v.group(1).strip()
                            
                elif rtype == "body" and re.search(pattern, text, re.I): 
                    score += pts
                    # Coba ekstrak versi dari body
                    if name == "Angular":
                         m_v = re.search(r'ng-version="([\d\.]+)"', text, re.I)
                         if m_v: version = m_v.group(1).strip()

                elif rtype == "header":
                    for hk, hv in headers.items():
                        full_header = f"{hk}: {hv}"
                        if re.search(pattern, full_header, re.I): 
                            score += pts
                            # Coba ekstrak versi dari header
                            if name == "PHP" and hk == 'x-powered-by':
                                m_v = re.search(r'php/([\d\.]+)', hv, re.I)
                                if m_v: version = m_v.group(1).strip()
                                
                elif rtype == "cookie":
                    for ck in cookies.keys():
                        if re.search(pattern, ck, re.I): score += pts
                        
                elif rtype == "path":
                    test_url = url.rstrip("/") + pattern
                    r = fetch(test_url, timeout=5)
                    if r and r.status_code == 200: score += pts
                    
                elif rtype == "script_src":
                    if re.search(r'<script[^>]+src="[^"]*%s' % pattern, text, re.I): score += pts
            except:
                continue

        if score > 0:
            detections[name] = {"score": score, "version": version}
    
    return detections

def detect_cms(url, resp):
    raw_detections = _run_detection(url, resp, SIGNATURES)
    return {name: data for name, data in raw_detections.items() if data['score'] > 0}

def detect_js_frameworks(url, resp):
    raw_detections = _run_detection(url, resp, JS_FRAMEWORK_SIGNATURES)
    return {name: data for name, data in raw_detections.items() if data['score'] > 0}

def hash_favicon(url):
    try:
        fav_url = url.rstrip("/") + "/favicon.ico"
        r = fetch(fav_url)
        if not r or r.status_code != 200:
            return None
        b64 = base64.b64encode(r.content)
        return mmh3.hash(b64)
    except Exception:
        return None

def get_baseline_404(url):
    try:
        test_url = url.rstrip("/") + "/__alah_mbuh_lah_cok_pusingikipiye_validasine"
        r = requests.get(test_url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
        return hashlib.md5(r.text.encode(errors='ignore')).hexdigest(), len(r.text)
    except:
        return None, None

def is_false_positive(resp, baseline_hash, baseline_len, threshold=50):
    if not resp: return True
    resp_hash = hashlib.md5(resp.text.encode(errors='ignore')).hexdigest()
    if baseline_hash and resp_hash == baseline_hash: return True
    if baseline_len and abs(len(resp.text) - baseline_len) <= threshold: return True
    return False

def detect_cicd(url, baseline_hash, baseline_len):
    found = []
    for path in CICD_PATHS:
        test_url = url.rstrip("/") + "/" + path
        r = fetch(test_url)
        if r and r.status_code == 200:
            if not is_false_positive(r, baseline_hash, baseline_len):
                found.append(path)
    return found

def get_tls_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            
            subject = dict(cert.get('subject', []))
            issuer = dict(cert.get('issuer', []))
            
            cn = 'N/A'
            issuer_cn = 'N/A'
            for item in subject:
                if item[0][0] == 'commonName': cn = item[0][1]; break
            for item in issuer:
                if item[0][0] == 'commonName': issuer_cn = item[0][1]; break

            return {"subject_cn": cn, "issuer_cn": issuer_cn, "cert_serial": cert.get('serialNumber')}
    except Exception:
        return None

def detect_infrastructure(resp):
    found_infra = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = resp.cookies.get_dict()
    
    for infra, patterns in INFRA_SIGNATURES.items():
        for pattern in patterns:
            pattern_lower = pattern.lower()
            if pattern_lower.startswith("server:"):
                if 'server' in headers and pattern_lower.split(":")[1].strip() in headers['server'].lower():
                    found_infra.append(infra); break
            elif pattern_lower.startswith("set-cookie:"):
                cookie_name = pattern_lower.split(":")[1].strip()
                if cookie_name in cookies:
                     found_infra.append(infra); break
            else:
                if pattern_lower in headers:
                    found_infra.append(infra); break
    
    return list(dict.fromkeys(found_infra))

def check_security_headers(resp):
    results = {}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    
    for header in SECURITY_HEADERS:
        header_key = header.lower()
        if header_key in headers:
            results[header] = headers[header_key] 
        else:
            results[header] = "Missing"
    return results


# ────────────────────────────────
# Main Scan - UI Paling Rapi & Multi-Detection
# ────────────────────────────────
def scan_target(url, args, fav_db):
    results = {"url": url, "status_code": "N/A", "error": None}
    resp = fetch(url, timeout=args.timeout)
    
    SEP = "=" * 74
    def print_line(label, value, color=Fore.GREEN):
        
        if not args.json and not args.output:
            print(f"{color}[ {label:<15} ]{Style.RESET_ALL} : {value}")

    if not args.json and not args.output:
        print(f"\n{Fore.YELLOW}{SEP}")
        print(f"{Fore.CYAN}🎯 TARGET SCAN: {url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{SEP}{Style.RESET_ALL}")

    if not resp:
        results['error'] = "Failed to connect or received no response."
        if not args.json and not args.output:
            print(f"{Fore.RED}[x] Error: {results['error']}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}{SEP}{Style.RESET_ALL}")
        return results
        
    results["status_code"] = resp.status_code
    
    # ---------------------------
    # 2. TECHNOLOGY STACK (CMS/Backend)
    # ---------------------------
    if not args.json and not args.output:
        print(f"\n{Fore.CYAN}--- 💻 TECHNOLOGY STACK (Backend/CMS) {'-'*30}{Style.RESET_ALL}")
    
    all_cms_detections = detect_cms(url, resp)
    
    results["tech_stack"] = {}
    
    # Menyesuaikan struktur data untuk JSON output (skor tetap disimpan)
    results["tech_stack"]["cms_framework_all"] = {name: data['score'] for name, data in all_cms_detections.items()}
    
    if all_cms_detections:
        # Sortir berdasarkan skor
        sorted_detections = sorted(all_cms_detections.items(), key=lambda item: item[1]['score'], reverse=True)
        primary_tech_name = sorted_detections[0][0]
        primary_tech_data = sorted_detections[0][1]
        
        results["tech_stack"]["primary_tech"] = primary_tech_name
        results["tech_stack"]["primary_score"] = primary_tech_data['score']
        
        output_name = primary_tech_name
        if primary_tech_data['version']:
            output_name += f" ({primary_tech_data['version']})"
        
        print_line("CMS/Framework", output_name, Fore.GREEN)
        
    else:
        print_line("CMS/Framework", "None Found", Fore.YELLOW)
        
    # Server headers
    server = resp.headers.get("Server")
    powered = resp.headers.get("X-Powered-By")
    
    server_info = []
    if server: server_info.append(server)
    if powered: server_info.append(powered)
    
    results["tech_stack"]["server_powered"] = ", ".join(server_info) if server_info else "Unknown"

    if server_info:
        print_line("Server/Powered", f"{', '.join(server_info)}", Fore.GREEN)
    else:
        print_line("Server/Powered", "Unknown", Fore.YELLOW)


    # ---------------------------
    # 3. DIGITAL FOOTPRINT
    # ---------------------------
    if not args.json and not args.output:
        print(f"\n{Fore.CYAN}--- 👣 DIGITAL FOOTPRINT {'-'*44}{Style.RESET_ALL}")
    results["footprint"] = {}

    # JS Frameworks Detection
    js_frameworks = detect_js_frameworks(url, resp)
    # Menyesuaikan struktur data untuk JSON output
    results["footprint"]["js_frameworks"] = {name: data['score'] for name, data in js_frameworks.items()}
    
    if js_frameworks:
        # Sortir berdasarkan skor
        sorted_js = sorted(js_frameworks.items(), key=lambda item: item[1]['score'], reverse=True)
        
        all_js_names = []
        for name, data in sorted_js:
            display_name = name
            if data['version']:
                 display_name += f" ({data['version']})"
            all_js_names.append(display_name)
        
        print_line("JS Frameworks", f"{', '.join(all_js_names)}", Fore.CYAN)
    else:
        print_line("JS Frameworks", "None Found", Fore.YELLOW)


    # Infrastructure 
    infra = detect_infrastructure(resp)
    results["footprint"]["infrastructure"] = infra if infra else "None Found"
    if infra:
        print_line("Infrastructure", f"{', '.join(infra)}", Fore.MAGENTA)
    else:
        print_line("Infrastructure", "None Found", Fore.YELLOW)

    # Favicon hashing
    if args.favicon:
        hval = hash_favicon(url)
        results["footprint"]["favicon_hash"] = str(hval) if hval else "N/A"
        if hval:
            match_name = fav_db.get(str(hval), {}).get("name", "No Match")
            results["footprint"]["favicon_match"] = match_name
            color = Fore.GREEN if match_name != "No Match" else Fore.YELLOW
            print_line("Favicon Hash", f"{hval} ({color}Match: {match_name}{Style.RESET_ALL}{Fore.YELLOW})", color)
        else:
            print_line("Favicon Hash", "Not Found (/favicon.ico)", Fore.YELLOW)
    
    # 404 Baseline & CI/CD
    baseline_hash, baseline_len = get_baseline_404(url)
    results["footprint"]["baseline_404"] = {"hash": baseline_hash, "length": baseline_len}
    
    if baseline_hash:
        print_line("404 Baseline", f"{baseline_hash[:8]}... (Len: {baseline_len} bytes)", Fore.MAGENTA)
    
    cicd = detect_cicd(url, baseline_hash, baseline_len)
    results["footprint"]["cicd_indicators"] = cicd if cicd else "None Found"
    
    if cicd:
        print_line("CI/CD", f"{', '.join(cicd)}", Fore.MAGENTA)
    else:
        print_line("CI/CD", "None Found", Fore.YELLOW)


    # ---------------------------
    # 4. SECURITY INFO
    # ---------------------------
    if not args.json and not args.output:
        print(f"\n{Fore.CYAN}--- 🔒 SECURITY INFO {'-'*48}{Style.RESET_ALL}")
    results["security"] = {}
    
    sec_headers = check_security_headers(resp)
    results["security"]["headers"] = sec_headers
    for header, status in sec_headers.items():
        color = Fore.GREEN if status != "Missing" else Fore.RED
        header_label = header.replace('-', ' ')
        header_status = f"Status: {color}{'Present' if status != 'Missing' else 'Missing'}{Style.RESET_ALL}{Fore.YELLOW}"
        print_line(f"{header_label[:15]}", header_status, color)

    if args.tls:
        host = urlparse(url).hostname
        cert_info = get_tls_info(host)
        results["security"]["tls_info"] = cert_info if cert_info else "N/A"
        
        if cert_info:
            print_line("TLS Subject CN", cert_info['subject_cn'], Fore.BLUE)
            print_line("TLS Issuer CN", cert_info['issuer_cn'], Fore.BLUE)
        else:
            print_line("TLS Info", f"Failed to retrieve certificate for {host}", Fore.RED)

    if not args.json and not args.output:
        print(f"\n{Fore.YELLOW}{SEP}{Style.RESET_ALL}")
    
    return results


# ────────────────────────────────
# CLI
# ────────────────────────────────
def main():
    print(BANNER)

    p = argparse.ArgumentParser(description="🕵️ FingerWeb — Web Tech Detective CLI")
    scan = p.add_argument_group("scan")
    scan.add_argument("-u", "--url", help="Single target URL")
    scan.add_argument("-l", "--list", help="File with list of targets (one per line)")
    scan.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout seconds")
    scan.add_argument("--favicon", action="store_true", help="Enable favicon hashing & lookup")
    scan.add_argument("--fav-db", default=DEFAULT_FAVICON_DB, help="Path to favicon DB (JSON)")
    scan.add_argument("--tls", action="store_true", help="Fetch TLS certificate info")
    scan.add_argument("--json", action="store_true", help="Output JSON only (suppresses CLI output)")
    scan.add_argument("-o", "--output", help="Save output JSON to file")
    scan.add_argument("--threads", type=int, default=1, help="Number of threads for concurrent scanning") 

    args = p.parse_args()
    
    if args.json or args.output:
        global init
        init = lambda **kwargs: None 

    fav_db = {}
    if args.favicon:
        try:
            with open(args.fav_db, "r") as f:
                fav_db = json.load(f)
            if not args.json and not args.output:
                print(f"{Fore.GREEN}[+] Favicon DB loaded from {args.fav_db}{Style.RESET_ALL}")
        except FileNotFoundError:
            if not args.json and not args.output:
                print(f"{Fore.YELLOW}[!] Warning: Favicon DB file not found at {args.fav_db}. Skipping favicon lookup.{Style.RESET_ALL}")
        except Exception as e:
            if not args.json and not args.output:
                print(f"{Fore.RED}[x] Error loading Favicon DB: {e}{Style.RESET_ALL}")
            
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list) as f:
                targets += [x.strip() for x in f if x.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[x] Error: List file not found at {args.list}{Style.RESET_ALL}")
            sys.exit(1)
            
    if not targets:
        p.print_help()
        sys.exit(0)
        
    
    all_results = []
    
    for url in targets:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        result = scan_target(url, args, fav_db)
        all_results.append(result)

    final_output = all_results[0] if len(all_results) == 1 else all_results
    
    if args.json and not args.output:
        print(json.dumps(final_output, indent=4))
    
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(final_output, f, indent=4)
            if not args.json:
                print(f"\n{Fore.GREEN}[+] Results saved successfully to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[x] Error saving JSON file: {e}{Style.RESET_ALL}")


if __name__ == "__main__":

    main()

