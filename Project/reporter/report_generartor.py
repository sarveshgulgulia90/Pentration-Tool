# reporter/report_generator.py
"""
Simple HTML report generator that reads crawl + findings JSON files and produces data/report.html
"""

import json
import os
import argparse
from datetime import datetime

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_html(crawl, sql_findings, xss_findings, outpath="data/report.html"):
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    now = datetime.utcnow().isoformat() + "Z"
    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'><title>Scan Report</title></head><body>")
    html.append(f"<h1>Custom Vulnerability Scanner - Report</h1>")
    html.append(f"<p>Generated: {now}</p>")

    html.append("<h2>Summary</h2>")
    num_pages = len(crawl.get("pages", [])) if crawl else 0
    num_forms = len(crawl.get("forms", [])) if crawl else 0
    html.append(f"<ul><li>Pages discovered: {num_pages}</li><li>Forms discovered: {num_forms}</li></ul>")

    html.append("<h2>SQL Injection Findings</h2>")
    if sql_findings:
        html.append("<ol>")
        for f in sql_findings:
            html.append("<li>")
            html.append("<pre>{}</pre>".format(json.dumps(f, indent=2)[:2000]))
            html.append("</li>")
        html.append("</ol>")
    else:
        html.append("<p>No SQLi findings.</p>")

    html.append("<h2>XSS Findings</h2>")
    if xss_findings:
        html.append("<ol>")
        for f in xss_findings:
            html.append("<li>")
            html.append("<pre>{}</pre>".format(json.dumps(f, indent=2)[:2000]))
            html.append("</li>")
        html.append("</ol>")
    else:
        html.append("<p>No XSS findings.</p>")

    html.append("<h2>Pages (sample)</h2>")
    if crawl and crawl.get("pages"):
        html.append("<ul>")
        for p in crawl.get("pages", [])[:30]:
            html.append(f"<li>{p.get('url')} (status {p.get('status_code')})</li>")
        html.append("</ul>")
    else:
        html.append("<p>No pages found.</p>")

    html.append("</body></html>")

    with open(outpath, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print("Report written to", outpath)

def main():
    parser = argparse.ArgumentParser(description="Generate HTML report from crawl + detectors")
    parser.add_argument("--crawl", default="data/crawl_results.json")
    parser.add_argument("--sql", default="data/sql_findings.json")
    parser.add_argument("--xss", default="data/xss_findings.json")
    parser.add_argument("--out", default="data/report.html")
    args = parser.parse_args()

    crawl = load_json(args.crawl) or {}
    sql = load_json(args.sql) or []
    xss = load_json(args.xss) or []

    generate_html(crawl, sql, xss, outpath=args.out)

if __name__ == "__main__":
    main()
