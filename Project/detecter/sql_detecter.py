# detector/sql_detector.py
"""
Non-destructive SQL Injection detector.
Reads data/crawl_results.json produced by crawler.py
Saves findings to data/sql_findings.json
Requires --lab flag or LAB_MODE=1 environment variable to run.
"""

import requests
import json
import argparse
import os
import logging
import time
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlsplit

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "sql syntax",
    "mysql_fetch",
    "syntax error",
    "pg_query",
    "odbc"
]

# conservative boolean payloads for detection (non-destructive)
PAYLOAD_TRUE = "' OR '1'='1"
PAYLOAD_FALSE = "' AND '1'='2"

def is_lab_mode(args):
    return args.lab or os.environ.get("LAB_MODE") == "1"

def load_crawl(path="data/crawl_results.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_findings(findings, filename="data/sql_findings.json"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    logging.info("Saved SQL findings to %s", filename)

def contains_sql_error(text):
    if not text:
        return False
    low = text.lower()
    for sig in SQL_ERROR_SIGNS:
        if sig in low:
            return True
    return False

def test_param_boolean(url, param, original_value, session, method="get"):
    """
    Send two requests: one with TRUE payload and one with FALSE payload and compare responses.
    Return dict with evidence if suspicious.
    """
    parsed = urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    findings = None

    if method.lower() == "get":
        # build query params
        qs = dict(parse_qs(parsed.query))
        qs[param] = original_value + PAYLOAD_TRUE
        url_true = base + "?" + urlencode(qs, doseq=True)
        resp_true = session.get(url_true, timeout=10)
        time.sleep(0.3)

        qs[param] = original_value + PAYLOAD_FALSE
        url_false = base + "?" + urlencode(qs, doseq=True)
        resp_false = session.get(url_false, timeout=10)
        time.sleep(0.3)

        if resp_true.status_code != resp_false.status_code or resp_true.text != resp_false.text:
            findings = {
                "type": "boolean-difference",
                "param": param,
                "url_true": url_true,
                "url_false": url_false,
                "status_true": resp_true.status_code,
                "status_false": resp_false.status_code,
                "len_true": len(resp_true.text),
                "len_false": len(resp_false.text)
            }
    else:
        # POST handling: build a shallow POST test
        # For simplicity we won't do POST boolean tests here in auto mode
        findings = None

    return findings

def test_param_error(url, param, original_value, session, method="get"):
    parsed = urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    findings = None

    if method.lower() == "get":
        qs = dict(parse_qs(parsed.query))
        qs[param] = original_value + "'"
        url_test = base + "?" + urlencode(qs, doseq=True)
        resp = session.get(url_test, timeout=10)
        time.sleep(0.3)
        if contains_sql_error(resp.text):
            findings = {
                "type": "error-based",
                "param": param,
                "url_test": url_test,
                "status": resp.status_code,
                "evidence_snippet": resp.text[:500]
            }
    return findings

def scan_forms(forms, session):
    findings = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        # We'll attempt a conservative error check by filling first text input with a trailing quote
        for inp in inputs:
            name = inp.get("name")
            itype = inp.get("type", "")
            if not name:
                continue
            if itype in ("submit", "button") :
                continue
            # prepare a data dict with original/default values
            data = {}
            for i in inputs:
                n = i.get("name")
                if not n:
                    continue
                if n == name:
                    data[n] = (i.get("value") or "test") + "'"
                else:
                    data[n] = i.get("value") or "test"
            try:
                # only POST forms: conservative test - look for error patterns
                if method == "post":
                    logging.info("Testing form (POST) %s param %s", action, name)
                    resp = session.post(action, data=data, timeout=10)
                    time.sleep(0.3)
                    if contains_sql_error(resp.text):
                        findings.append({
                            "type": "error-based (form)",
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
        # check query parameters
        parsed = urlsplit(url)
        qs = dict(parse_qs(parsed.query))
        if not qs:
            continue
        for param, values in qs.items():
            orig = values[0] if isinstance(values, list) else str(values)
            try:
                logging.info("Testing %s param %s", url, param)
                # error-based
                err = test_param_error(url, param, orig, session, method="get")
                if err:
                    err["page"] = url
                    findings.append(err)
                # boolean-based only if not error-based
                boolr = test_param_boolean(url, param, orig, session, method="get")
                if boolr:
                    boolr["page"] = url
                    findings.append(boolr)
            except Exception as e:
                logging.debug("Param test failed for %s: %s", url, e)
    return findings

def main():
    parser = argparse.ArgumentParser(description="SQLi Detector (lab-only, conservative tests).")
    parser.add_argument("--lab", action="store_true", help="Enable lab mode (required for running tests).")
    parser.add_argument("--crawl", default="data/crawl_results.json", help="Path to crawler output JSON.")
    args = parser.parse_args()

    if not is_lab_mode(args):
        print("This detector will only run in LAB mode. Start with --lab or set LAB_MODE=1 environment variable.")
        return

    data = load_crawl(args.crawl)
    pages = data.get("pages", [])
    forms = data.get("forms", [])

    session = requests.Session()
    session.headers.update({"User-Agent": "CustomScanner/SQLDetector/1.0"})

    findings = []
    # scan forms (POST) conservatively
    findings.extend(scan_forms(forms, session))
    # scan pages with query params
    findings.extend(scan_pages(pages, session))

    save_findings(findings)

if __name__ == "__main__":
    main()
    