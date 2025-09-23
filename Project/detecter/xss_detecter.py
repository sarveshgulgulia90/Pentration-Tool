# detector/xss_detector.py
"""
Reflected XSS detector (conservative).
Reads data/crawl_results.json and writes data/xss_findings.json
Requires --lab flag or LAB_MODE=1 environment variable to run.
"""

import json
import argparse
import os
import logging
import requests
import time
from urllib.parse import urlsplit, urlencode, parse_qs

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

XSS_MARKER = "<!--XSS_TEST_12345-->"
SCRIPT_MARKER = "<script>alert('xss')</script>"  # only used if explicit PoC mode enabled (lab mode still required)

def is_lab_mode(args):
    return args.lab or os.environ.get("LAB_MODE") == "1"

def load_crawl(path="data/crawl_results.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_findings(findings, filename="data/xss_findings.json"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    logging.info("Saved XSS findings to %s", filename)

def reflect_check_get(url, param, orig_val, session):
    parsed = urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    qs = dict(parse_qs(parsed.query))
    qs[param] = orig_val + XSS_MARKER
    test_url = base + "?" + urlencode(qs, doseq=True)
    resp = session.get(test_url, timeout=10)
    time.sleep(0.3)
    if XSS_MARKER in resp.text:
        return {
            "type": "reflected",
            "param": param,
            "test_url": test_url,
            "status": resp.status_code,
            "evidence_snippet": resp.text[:500]
        }
    return None

def test_forms(forms, session):
    findings = []
    for form in forms:
        method = form.get("method", "get").lower()
        action = form.get("action")
        inputs = form.get("inputs", [])
        # for each input, try inject marker into one field and send
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            data = {}
            for i in inputs:
                n = i.get("name")
                if not n:
                    continue
                if n == name:
                    data[n] = (i.get("value") or "test") + XSS_MARKER
                else:
                    data[n] = i.get("value") or "test"
            try:
                if method == "post":
                    logging.info("Testing form (POST) %s param %s", action, name)
                    resp = session.post(action, data=data, timeout=10)
                    time.sleep(0.3)
                    if XSS_MARKER in resp.text:
                        findings.append({
                            "type": "reflected (form)",
                            "action": action,
                            "param": name,
                            "status": resp.status_code,
                            "evidence_snippet": resp.text[:500]
                        })
            except Exception as e:
                logging.debug("Form test failed: %s", e)
    return findings

def scan_pages(pages, session):
    findings = []
    for p in pages:
        url = p.get("url")
        parsed = urlsplit(url)
        qs = dict(parse_qs(parsed.query))
        if not qs:
            continue
        for param in qs.keys():
            try:
                res = reflect_check_get(url, param, qs[param][0] if isinstance(qs[param], list) else qs[param], session)
                if res:
                    res['page'] = url
                    findings.append(res)
            except Exception as e:
                logging.debug("Reflect test failed for %s param %s: %s", url, param, e)
    return findings

def main():
    parser = argparse.ArgumentParser(description="XSS Detector (lab-only, conservative).")
    parser.add_argument("--lab", action="store_true", help="Enable lab mode (required).")
    parser.add_argument("--crawl", default="data/crawl_results.json", help="Path to crawler output JSON.")
    args = parser.parse_args()

    if not is_lab_mode(args):
        print("This detector will only run in LAB mode. Start with --lab or set LAB_MODE=1 environment variable.")
        return

    data = load_crawl(args.crawl)
    pages = data.get("pages", [])
    forms = data.get("forms", [])

    session = requests.Session()
    session.headers.update({"User-Agent": "CustomScanner/XSSDetector/1.0"})

    findings = []
    findings.extend(scan_pages(pages, session))
    findings.extend(test_forms(forms, session))

    save_findings(findings)

if __name__ == "__main__":
    main()