#!/usr/bin/env python3
import argparse
import json
import logging
import socket
import ssl
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse
import random
import string
import requests
logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)

def normalize_base(url):
    """Return normalized base URL (scheme://host[:port])."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname
    port = parsed.port
    if host is None:
        raise ValueError("Could not parse host from URL: " + url)
    base = f"{scheme}://{host}"
    if port:
        base = f"{base}:{port}"
    return base, scheme, host, port
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def fetch_home(url, timeout=10):
    """GET the base URL (no heavy crawling). Returns response or raises."""
    headers = {"User-Agent": "Passive-Security-Scanner/3.0"}
    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
    return resp

def analyze_headers(resp):
    """Check presence/values of important security headers."""
    hdrs = {}
    missing = []
    for h in SECURITY_HEADERS:
        val = resp.headers.get(h)
        if val:
            hdrs[h] = val
        else:
            hdrs[h] = "Missing"
            missing.append(h)
    return hdrs, missing

def analyze_cookies(resp):
    """Inspect cookies for Secure and HttpOnly flags."""
    cookies_info = []
    for cookie in resp.cookies:
        http_only = "httponly" in [k.lower() for k in getattr(cookie, "_rest", {})]
        cookies_info.append({
            "name": cookie.name,
            "value_sample": cookie.value[:8] + "..." if cookie.value else "",
            "secure": bool(getattr(cookie, "secure", False)),
            "httpOnly": http_only
        })
    return cookies_info
def tls_info_for_host(host, port=None, timeout=8):
    """Perform TLS handshake and extract basic certificate, cipher, protocol and expiry."""
    if port is None:
        port = 443
    info = {}
    target = (host, port)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(target, timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                info["cipher"] = cipher[0] if cipher else None
                info["protocol"] = ssock.version()
                cert = ssock.getpeercert() or {}
                info.update(parse_cert(cert))
                info["trusted"] = True
    except Exception as e:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection(target, timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    info["cipher"] = cipher[0] if cipher else None
                    info["protocol"] = ssock.version()
                    cert = ssock.getpeercert() or {}
                    info.update(parse_cert(cert))
                    info["trusted"] = False
                    info["error"] = str(e)
        except Exception as e2:
            logging.warning(f"TLS handshake failed for {host}:{port} -> {e2}")
            return {"error": str(e2)}
    return info

def parse_cert(cert):
    """Extract human-friendly fields from certificate dict returned by getpeercert()."""
    out = {}
    if not cert:
        return out
    not_after = cert.get("notAfter")
    if not_after:
        try:
            # Handles single-space month like 'Oct  6'
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            # Handles double-space month like 'Oct  6'
            expiry = datetime.strptime(not_after, "%b  %d %H:%M:%S %Y %Z")
        if expiry:
            days_left = (expiry - datetime.utcnow()).days
            out["cert_expiry"] = expiry.strftime("%Y-%m-%d")
            out["days_to_expiry"] = days_left
            out["expired"] = days_left < 0
    subj = cert.get("subject")
    issuer = cert.get("issuer")
    if subj:
        out["subject"] = tuple(tuple(x) for x in subj)
    if issuer:
        out["issuer"] = tuple(tuple(x) for x in issuer)
    return out

# -----------------------
# Sensitive path checking (IMPROVED with Soft 404 detection)
# -----------------------
DEFAULT_PATHS = [
    "/admin", "/administrator", "/login", "/user/login", "/phpmyadmin", "/pma",
    "/config", "/backup", "/.git", "/.env", "/wp-admin", "/server-status", "/debug",
]

def probe_path(base, path, timeout=6, not_found_signature=None):
    """Probe path using GET and compare against a 'not found' signature."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    headers = {"User-Agent": "Passive-Security-Scanner/3.0"}
    try:
        r = requests.get(url, allow_redirects=False, timeout=timeout, headers=headers, verify=True)
    except Exception:
        return None

    status = r.status_code
    
    if status == 200:
        if not_found_signature:
            content_len = len(r.content)
            content_hash = hashlib.md5(r.content).hexdigest()
            if (content_len == not_found_signature["len"] and content_hash == not_found_signature["hash"]):
                return None  # It's a soft 404, ignore it

    if status == 200 or (300 <= status < 400):
        return {"path": path, "status": status, "url": url, "location": r.headers.get("Location")}
    return None

def probe_paths_concurrent(base, paths, concurrency=8, timeout=6):
    """Probe paths concurrently after establishing a 'soft 404' baseline."""
    found = []
    not_found_signature = None
    
    try:
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        random_url = base.rstrip("/") + "/" + rand_str
        r_base = requests.get(random_url, timeout=timeout, verify=True, headers={"User-Agent": "Passive-Security-Scanner/3.0"})
        if r_base.status_code == 200:
            not_found_signature = {
                "len": len(r_base.content),
                "hash": hashlib.md5(r_base.content).hexdigest()
            }
            logging.info(f"Established soft 404 baseline: len={not_found_signature['len']}, hash={not_found_signature['hash']}")
    except Exception as e:
        logging.warning(f"Could not establish a soft 404 baseline: {e}")

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(probe_path, base, p, timeout, not_found_signature): p for p in paths}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                logging.info(f"Exposed path found: {res['path']} -> {res['status']} ({res['url']})")
                found.append(res)
    return found

def compute_score(scan):
    """Calculates the final score based on a fairer, revised logic."""
    # Maximum points for each category
    max_points = {"headers": 30, "cookies": 15, "tls": 25, "paths": 20, "misc": 10}
    # Headers (30 points)
    header_score = 0.0
    for h in SECURITY_HEADERS:
        val = scan.get("headers", {}).get(h, "Missing")
        if val != "Missing":
            if h == "Content-Security-Policy" and ("'unsafe-inline'" in val or "data:" in val):
                header_score += 2.5
            else:
                header_score += 5.0

    # Cookies (15 points)
    cookies = scan.get("cookies", [])
    cookie_score = max_points["cookies"]
    if cookies:
        flags_total = sum((1 if c.get("secure") else 0) + (1 if c.get("httpOnly") else 0) for c in cookies)
        max_flags = 2 * len(cookies)
        cookie_score = max_points["cookies"] * (flags_total / max_flags) if max_flags else max_points["cookies"]

    # TLS (25 points - REVISED LOGIC)
    tls = scan.get("tls", {})
    tls_score = 0.0
    if tls and not tls.get("error"):
        # 15 points if trusted and not expired
        if tls.get("expired") is False and tls.get("trusted"):
            tls_score += 15.0
        
        # 5 points for being valid for at least 7 days (not about to expire)
        days = tls.get("days_to_expiry")
        if isinstance(days, int) and days > 7:
            tls_score += 5.0

        # 5 points for using a strong protocol
        proto = str(tls.get("protocol", "")).lower()
        if "1.2" in proto or "1.3" in proto:
            tls_score += 5.0
    
    # Sensitive paths (20 points)
    path_score = max_points["paths"] - 5.0 * len(scan.get("sensitive_paths", []))
    path_score = max(0.0, path_score)

    # Miscellaneous (10 points, for having any cookies at all)
    misc_score = max_points["misc"] if cookies else 0.0

    total = header_score + cookie_score + tls_score + path_score + misc_score
    return {
        "score": round(total, 1),
        "breakdown": {
            "headers": round(header_score, 1),
            "cookies": round(cookie_score, 1),
            "tls": round(tls_score, 1),
            "paths": round(path_score, 1),
            "misc": round(misc_score, 1)
        },
    }

def grade_scan(scan):
    """Assigns a letter grade and summary based on the final score."""
    score = scan.get("score", 0)
    grade = "F"
    summary = "Poor security posture with critical issues."
    if score >= 80:
        grade, summary = "A", "Excellent security posture."
    elif score >= 70:
        grade, summary = "B", "Good security posture with minor room for improvement."
    elif score >= 60:
        grade, summary = "C", "Average security posture. Key areas need attention."
    elif score >= 50:
        grade, summary = "D", "Below average. Significant improvements are needed."
    
    return {"grade": grade, "summary": summary}

def run_scan(target_url, extra_paths=None, timeout=10, concurrency=8):
    """Executes the full scan sequence."""
    base, scheme, host, port = normalize_base(target_url)
    result = {"url": base, "fetched_at": datetime.utcnow().isoformat() + "Z"}

    try:
        resp = fetch_home(base, timeout=timeout)
    except Exception as e:
        logging.error(f"Failed to fetch {base}: {e}")
        return {"error": str(e)}

    result["headers"], result["missing_headers"] = analyze_headers(resp)
    result["cookies"] = analyze_cookies(resp)
    result["tls"] = tls_info_for_host(host, port if port else 443, timeout=timeout) if scheme == "https" else {}
    
    paths_to_check = list(dict.fromkeys((extra_paths or []) + DEFAULT_PATHS))
    result["sensitive_paths"] = probe_paths_concurrent(base, paths_to_check, concurrency=concurrency, timeout=timeout)

    score_obj = compute_score(result)
    result.update(score_obj)
    
    result["grade"] = grade_scan(result)
    
    return result
def main():
    """Parses arguments and runs the scanner."""
    parser = argparse.ArgumentParser(description="Passive Security Scanner (v3 - Final)")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("-p", "--paths", nargs="*", default=[], help="Extra paths to probe")
    parser.add_argument("--timeout", type=int, default=10, help="Network timeout seconds")
    parser.add_argument("--concurrency", type=int, default=8, help="Concurrency for path probes")
    parser.add_argument("-o", "--outfile", help="Optional file to write JSON output")
    args = parser.parse_args()

    scan = run_scan(args.target, extra_paths=args.paths, timeout=args.timeout, concurrency=args.concurrency)
    out = json.dumps(scan, indent=2)

    if args.outfile:
        with open(args.outfile, "w") as fh:
            fh.write(out)
        logging.info(f"Wrote JSON output to {args.outfile}")
    else:
        print(out)

if __name__ == "__main__":
    main()