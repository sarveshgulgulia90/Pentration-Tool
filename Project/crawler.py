# crawler.py
"""
Simple polite crawler for lab targets.
Saves results to data/crawl_results.json
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlsplit
import time
import json
import logging
from collections import deque
import urllib.robotparser as robotparser
import os
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class SimpleCrawler:
    def __init__(self, base_url, user_agent="CustomScanner/1.0", delay=0.5, max_pages=200, allow_subdomain=False):
        self.base_url = base_url.rstrip('/')
        self.parsed_base = urlparse(self.base_url)
        self.base_netloc = self.parsed_base.netloc
        self.user_agent = user_agent
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.visited = set()
        self.to_visit = deque()
        self.max_pages = max_pages
        self.results = {"pages": [], "forms": []}
        self.allow_subdomain = allow_subdomain

        # robots.txt parser
        self.rp = robotparser.RobotFileParser()
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            self.rp.set_url(robots_url)
            self.rp.read()
            logging.info(f"Loaded robots.txt from {robots_url}")
        except Exception as e:
            logging.warning("Could not fetch robots.txt; continuing without it. Error: %s", e)

    def is_allowed_by_robots(self, url):
        try:
            return self.rp.can_fetch(self.user_agent, url)
        except Exception:
            return True

    def same_domain(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if self.allow_subdomain:
            return parsed.netloc.endswith(self.base_netloc)
        return parsed.netloc == self.base_netloc

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
            resp = self.session.get(url, timeout=10, allow_redirects=True)
            time.sleep(self.delay)
            return resp
        except requests.RequestException as e:
            logging.debug("Request failed for %s: %s", url, e)
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
            title_tag = soup.find("title")
            if title_tag:
                page_info["title"] = title_tag.get_text(strip=True)
            # forms
            forms = self.extract_forms(soup, url)
            for f in forms:
                f['action'] = self.normalize_link(f['action'], url) or url
                self.results['forms'].append(f)
            # links
            links = set()
            for a in soup.find_all("a", href=True):
                norm = self.normalize_link(a['href'], url)
                if norm:
                    links.add(norm)
            page_info['links'] = list(links)
        except Exception as e:
            logging.debug("Parse error for %s: %s", url, e)
        self.results['pages'].append(page_info)
        return page_info.get('links', [])

    def crawl(self, start_path="/", max_depth=3):
        start_url = urljoin(self.base_url, start_path)
        self.to_visit.append((start_url, 0))

        while self.to_visit and len(self.visited) < self.max_pages:
            url, depth = self.to_visit.popleft()
            if url in self.visited:
                continue
            if depth > max_depth:
                continue
            if not self.same_domain(url):
                continue
            if not self.is_allowed_by_robots(url):
                logging.debug("Blocked by robots.txt: %s", url)
                continue

            logging.info("Fetching: %s (depth=%d)", url, depth)
            resp = self.fetch(url)
            if resp is None:
                self.visited.add(url)
                continue

            links = self.parse_and_collect(url, resp)
            self.visited.add(url)

            for link in links:
                if link not in self.visited:
                    if self.same_domain(link):
                        self.to_visit.append((link, depth + 1))

    def save_results(self, filename="data/crawl_results.json"):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        logging.info("Saved results to %s", filename)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple crawler for lab targets (DVWA/Juice Shop).")
    parser.add_argument("--target", required=True, help="Base target URL (e.g. http://192.168.56.101:8080)")
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--allow-subdomain", action="store_true")
    args = parser.parse_args()

    crawler = SimpleCrawler(base_url=args.target, delay=args.delay, max_pages=args.max_pages, allow_subdomain=args.allow_subdomain)
    crawler.crawl("/", max_depth=args.max_depth)
    crawler.save_results("data/crawl_results.json")
    print("Crawl finished. Results -> data/crawl_results.json")
