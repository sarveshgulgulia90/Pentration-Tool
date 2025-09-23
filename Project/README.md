# Custom Vulnerability Scanner (Mini-Nmap + Mini-SQLMap + Safe PoC)

## Overview
This project provides a simple, educational vulnerability scanning pipeline for lab use only:
- `crawler.py` — crawl target and extract pages & forms → `data/crawl_results.json`
- `detector/sql_detector.py` — conservative SQLi checks → `data/sql_findings.json`
- `detector/xss_detector.py` — conservative reflected XSS checks → `data/xss_findings.json`
- `reporter/report_generator.py` — generate `data/report.html` report

## Safety / Legal
**DO NOT** run these tools against systems you do not own or have written permission to test. All tests are intentionally conservative, but still potentially disruptive. Detectors require `--lab` flag (or environment variable `LAB_MODE=1`) to run.

## Running (example)
1. Create a Python virtual env and install deps:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
