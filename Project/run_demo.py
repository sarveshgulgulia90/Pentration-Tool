# run_demo.py
"""
Single-file demo runner:
 - starts a tiny Flask demo app (XSS + simulated SQLi + login form)
 - crawls the demo site (crawler)
 - runs simple SQLi and XSS detectors (conservative)
 - generates a simple HTML report and opens it in your browser
 - stops the demo server cleanly
Run: python run_demo.py
"""

import threading
import time
import requests
import json
import os
import webbrowser
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlsplit
from collections import deque
from bs4 import BeautifulSoup
from flask import Flask, request, render_template_string
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# ------------------------------
# 1) Simple demo Flask app
# ------------------------------
def create_demo_app():
    app = Flask(__name__)

    @app.route('/')
    def index():
        return """
        <h2>Demo Vulnerable App (Local)</h2>
        <ul>
          <li><a href="/search?q=test">Reflected XSS demo ( /search )</a></li>
          <li><a href="/item?id=1">SQLi-like demo ( /item )</a></li>
          <li><a href="/login">Login (form)</a></li>
        </ul>
        <p>Scanner demo target: <strong>http://127.0.0.1:5000</strong></p>
        """

    @app.route('/search')
    def search():
        q = request.args.get('q', '')
        # intentionally reflect user input (for demo only)
        html = f"""
        <h3>Search results for: {q}</h3>
        <p>This page reflects the query param directly (for demo)</p>
        <form method="get" action="/search">
          <input name="q" value="{q}">
          <input type="submit" value="Search">
        </form>
        """
        return render_template_string(html)

    @app.route('/item')
    def item():
        item_id = request.args.get('id', '')
        # Simulate an SQL error message when quotes present (detector looks for such patterns)
        if "'" in item_id or '"' in item_id:
            return f"You have an error in your SQL syntax near '{item_id}'", 200
        return f"<h3>Item page for id = {item_id}</h3><p>Normal content.</p>", 200

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            u = request.form.get('username','')
            # harmless echo
            return f"<p>Attempted login for {u}</p>"
        return '''
        <h3>Login</h3>
        <form method="post" action="/login">
          <input name="username" type="text" value="">
          <input name="password" type="password" value="">
          <input type="submit" value="Login">
        </form>
        '''

    @app.route('/shutdown', methods=['POST'])
    def shutdown():
        # stops Flask server
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()
        return 'Server shutting down...'

    return app

# ------------------------------
# 2) Simple crawler (same-domain, respects basic checks)
# ------------------------------
class SimpleCrawler:
    def __init__(self, base_url, delay=0.2, max_pages=100):
        self.base_url = base_url.rstrip('/')
        self.base_netloc = urlparse(self.base_url).netloc
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DemoScanner/1.0"})
        self.visited = set()
        self.to_visit = deque()
        self.results = {"pages": [], "forms": []}
        self.max_pages = max_pages

    def normalize_link(self, link, current_url):
        if not link:
            return None
        link = link.strip()
        if link.startswith("javascript:") or link.startswith("mailto:"):
            return None
        abs_link = urljoin(current_url, link)
        abs_link = abs_link.split('#')[0].rstrip('/')
        return abs_link

    def fetch(self, url):
        try:
            r = self.session.get(url, timeout=5)
            time.sleep(self.delay)
            return r
        except Exception as e:
            logging.debug("Fetch failed %s: %s", url, e)
            return None

    def extract_forms(self, soup, page_url):
        forms = []
        for f in soup.find_all("form"):
            action = f.get('action') or page_url
            method = (f.get('method') or 'get').lower()
            inputs = []
            for inp in f.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                itype = inp.get('type') if inp.name == 'input' else inp.name
                value = inp.get('value') or ''
                inputs.append({"name": name, "type": itype, "value": value})
            forms.append({"page": page_url, "action": action, "method": method, "inputs": inputs})
        return forms

    def parse_and_collect(self, url, resp):
        page_info = {
            "url": url,
            "status_code": resp.status_code,
            "content_length": len(resp.content) if resp.content else 0,
            "title": None,
            "links": []
        }
        try:
            soup = BeautifulSoup(resp.text, "lxml")
            tt = soup.find("title")
            if tt: page_info["title"] = tt.get_text(strip=True)
            forms = self.extract_forms(soup, url)
            for f in forms:
                f['action'] = self.normalize_link(f['action'], url) or url
                self.results['forms'].append(f)
            links = set()
            for a in soup.find_all("a", href=True):
                norm = self.normalize_link(a['href'], url)
                if norm:
                    links.add(norm)
            page_info['links'] = list(links)
        except Exception as e:
            logging.debug("Parse error %s: %s", url, e)
        self.results['pages'].append(page_info)
        return page_info.get('links', [])

    def same_domain(self, url):
        p = urlparse(url)
        return p.netloc == self.base_netloc and p.scheme in ('http','https')

    def crawl(self, start_path="/", max_depth=3):
        start_url = urljoin(self.base_url, start_path)
        self.to_visit.append((start_url, 0))
        while self.to_visit and len(self.visited) < self.max_pages:
            url, depth = self.to_visit.popleft()
            if url in self.visited: continue
            if depth > max_depth: continue
            if not self.same_domain(url): continue
            logging.info("Crawling %s (depth=%d)", url, depth)
            resp = self.fetch(url)
            if resp is None:
                self.visited.add(url)
                continue
            links = self.parse_and_collect(url, resp)
            self.visited.add(url)
            for l in links:
                if l not in self.visited and self.same_domain(l):
                    self.to_visit.append((l, depth+1))
        return self.results

# ------------------------------
# 3) Simple detectors
# ------------------------------
SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "mysql",
    "syntax error",
    "sql syntax",
    "pg_query"
]

XSS_MARKER = "<!--XSS_TEST-123-->"
PAYLOAD_TRUE = "' OR '1'='1"
PAYLOAD_FALSE = "' AND '1'='2"

def contains_sql_error(text):
    if not text: return False
    low = text.lower()
    return any(sig in low for sig in SQL_ERROR_SIGNS)

def sqli_tests(pages, forms, base_session):
    findings = []
    # test query params in pages
    for p in pages:
        url = p.get("url")
        parsed = urlsplit(url)
        qs = dict(parse_qs(parsed.query))
        if not qs:
            continue
        for param, vals in qs.items():
            orig = vals[0] if isinstance(vals, list) else str(vals)
            # error-based test
            qs_true = dict(qs)
            qs_true[param] = orig + "'"
            true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs_true, doseq=True)}"
            try:
                r = base_session.get(true_url, timeout=5)
                if contains_sql_error(r.text):
                    findings.append({"type":"error-based","page":url,"param":param,"test_url":true_url,"evidence":r.text[:300]})
                    continue
            except Exception:
                pass
            # boolean-diff
            qs_t = dict(qs); qs_f = dict(qs)
            qs_t[param] = orig + PAYLOAD_TRUE
            qs_f[param] = orig + PAYLOAD_FALSE
            t_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs_t, doseq=True)}"
            f_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs_f, doseq=True)}"
            try:
                rt = base_session.get(t_url, timeout=5)
                rf = base_session.get(f_url, timeout=5)
                if rt.status_code != rf.status_code or rt.text != rf.text:
                    findings.append({"type":"boolean-diff","page":url,"param":param,"true_url":t_url,"false_url":f_url,"len_true":len(rt.text),"len_false":len(rf.text)})
            except Exception:
                pass

    # test basic POST forms for error-like strings (non-destructive)
    for form in forms:
        method = form.get("method","get").lower()
        action = form.get("action")
        if method != "post":
            continue
        inputs = form.get("inputs",[])
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            data = {}
            for i in inputs:
                n = i.get("name")
                if not n:
                    continue
                data[n] = (i.get("value") or "test")
            # inject quote into the tested input
            data[name] = data.get(name,"test") + "'"
            try:
                r = base_session.post(action, data=data, timeout=5)
                if contains_sql_error(r.text):
                    findings.append({"type":"error-based-form","action":action,"param":name,"evidence":r.text[:300]})
            except Exception:
                pass
    return findings

def xss_tests(pages, forms, base_session):
    findings = []
    # GET reflected
    for p in pages:
        url = p.get("url")
        parsed = urlsplit(url)
        qs = dict(parse_qs(parsed.query))
        if not qs:
            continue
        for param in qs.keys():
            orig = qs[param][0] if isinstance(qs[param], list) else qs[param]
            qs[param] = orig + XSS_MARKER
            t_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs, doseq=True)}"
            try:
                r = base_session.get(t_url, timeout=5)
                if XSS_MARKER in r.text:
                    findings.append({"type":"reflected","page":url,"param":param,"test_url":t_url,"evidence":r.text[:300]})
            except Exception:
                pass
    # POST forms: inject marker into each input
    for form in forms:
        method = form.get("method","get").lower()
        action = form.get("action")
        inputs = form.get("inputs", [])
        if method != "post":
            continue
        for inp in inputs:
            name = inp.get("name")
            if not name: continue
            data = {}
            for i in inputs:
                n = i.get("name")
                if not n: continue
                data[n] = (i.get("value") or "test")
            data[name] = data.get(name,"test") + XSS_MARKER
            try:
                r = base_session.post(action, data=data, timeout=5)
                if XSS_MARKER in r.text:
                    findings.append({"type":"reflected-form","action":action,"param":name,"evidence":r.text[:300]})
            except Exception:
                pass
    return findings

# ------------------------------
# 4) Simple report generator (HTML)
# ------------------------------
def generate_report(crawl_results, sql_findings, xss_findings, outpath="data/demo_report.html"):
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'><title>Demo Scan Report</title></head><body>")
    html.append(f"<h1>Demo Vulnerability Scanner Report</h1><p>Generated: {now}</p>")
    html.append("<h2>Summary</h2>")
    html.append(f"<ul><li>Pages discovered: {len(crawl_results.get('pages',[]))}</li><li>Forms discovered: {len(crawl_results.get('forms',[]))}</li></ul>")

    html.append("<h2>SQL Findings</h2>")
    if sql_findings:
        for f in sql_findings:
            html.append(f"<pre>{json.dumps(f, indent=2)[:2000]}</pre>")
    else:
        html.append("<p>No SQL findings.</p>")

    html.append("<h2>XSS Findings</h2>")
    if xss_findings:
        for f in xss_findings:
            html.append(f"<pre>{json.dumps(f, indent=2)[:2000]}</pre>")
    else:
        html.append("<p>No XSS findings.</p>")

    html.append("<h2>Pages (sample)</h2><ul>")
    for p in crawl_results.get("pages", [])[:50]:
        html.append(f"<li>{p.get('url')} (status {p.get('status_code')})</li>")
    html.append("</ul>")

    html.append("</body></html>")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    logging.info("Report written to %s", outpath)
    return outpath

# ------------------------------
# 5) Orchestration: start Flask, run pipeline, stop Flask
# ------------------------------
def run_pipeline():
    base = "http://127.0.0.1:5000"
    session = requests.Session()
    session.headers.update({"User-Agent":"DemoScanner/1.0"})

    # Crawl
    crawler = SimpleCrawler(base, delay=0.1, max_pages=100)
    results = crawler.crawl("/", max_depth=3)
    with open("data/crawl_results.json","w",encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logging.info("Crawl done. Pages: %d, Forms: %d", len(results.get("pages",[])), len(results.get("forms",[])))

    # Detectors
    sql = sqli_tests(results.get("pages",[]), results.get("forms",[]), session)
    xss = xss_tests(results.get("pages",[]), results.get("forms",[]), session)
    with open("data/sql_findings.json","w",encoding="utf-8") as f:
        json.dump(sql, f, indent=2)
    with open("data/xss_findings.json","w",encoding="utf-8") as f:
        json.dump(xss, f, indent=2)
    logging.info("Detectors finished. SQL findings: %d, XSS findings: %d", len(sql), len(xss))

    # Report
    report_path = generate_report(results, sql, xss, outpath="data/demo_report.html")
    webbrowser.open_new_tab(os.path.abspath(report_path))

# Start Flask in a thread
def start_demo_server():
    app = create_demo_app()
    # run Flask in thread
    thr = threading.Thread(target=lambda: app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False), daemon=True)
    thr.start()
    # wait for server to be ready
    for i in range(20):
        try:
            r = requests.get("http://127.0.0.1:5000", timeout=1)
            if r.status_code == 200:
                logging.info("Demo server ready")
                return thr
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("Demo server did not start")

def stop_demo_server():
    try:
        requests.post("http://127.0.0.1:5000/shutdown", timeout=2)
    except Exception:
        pass

if __name__ == "__main__":
    logging.info("Starting demo server...")
    thr = start_demo_server()
    try:
        run_pipeline()
        logging.info("Pipeline completed. Report opened in browser.")
    except Exception as e:
        logging.exception("Error during pipeline: %s", e)
    finally:
        logging.info("Stopping demo server...")
        stop_demo_server()
        time.sleep(0.5)
        logging.info("Done. You can delete the data/ folder if you want to reset.")
