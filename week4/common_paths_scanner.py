# common_paths_scanner.py
"""
Common Paths Scanner
Discovers common files, directories, and endpoints for penetration testing
"""

import requests
import json
import os
import logging
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple, Optional
import concurrent.futures
from threading import Lock

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class CommonPathsScanner:
    def __init__(self, session=None, max_threads=10):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "CommonPathsScanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        # Configure session for better connection management
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.max_threads = max_threads
        self.findings = {
            "discovered_paths": [],
            "sensitive_files": [],
            "admin_panels": [],
            "backup_files": [],
            "config_files": [],
            "development_files": [],
            "api_endpoints": [],
            "error_pages": []
        }
        
        # Common paths to test
        self.common_paths = {
            "admin_panels": [
                "/admin", "/administrator", "/admin.php", "/admin.html",
                "/admin/login", "/admin/dashboard", "/admin/index.php",
                "/wp-admin", "/phpmyadmin", "/pma", "/mysql",
                "/admincp", "/controlpanel", "/cp", "/panel",
                "/manager", "/management", "/control", "/dashboard"
            ],
            "backup_files": [
                "/backup", "/backups", "/backup.sql", "/database.sql",
                "/db_backup.sql", "/site_backup.sql", "/backup.tar.gz",
                "/backup.zip", "/backup.rar", "/backup.7z",
                "/old", "/archive", "/archives", "/old_site",
                "/backup_old", "/backup_new", "/backup_latest"
            ],
            "config_files": [
                "/.env", "/config.php", "/config.ini", "/config.json",
                "/config.xml", "/configuration.php", "/settings.php",
                "/wp-config.php", "/wp-config-sample.php",
                "/database.yml", "/database.yaml", "/.htaccess",
                "/.htpasswd", "/web.config", "/application.properties"
            ],
            "development_files": [
                "/test.php", "/test.html", "/test.js", "/test.py",
                "/debug.php", "/debug.html", "/info.php", "/phpinfo.php",
                "/status.php", "/status.html", "/health.php",
                "/ping.php", "/version.php", "/version.html",
                "/changelog.txt", "/readme.txt", "/readme.md"
            ],
            "sensitive_directories": [
                "/.git", "/.svn", "/.hg", "/.bzr", "/.cvs",
                "/logs", "/log", "/tmp", "/temp", "/cache",
                "/uploads", "/files", "/documents", "/private",
                "/secret", "/hidden", "/internal", "/dev",
                "/staging", "/test", "/demo", "/beta"
            ],
            "api_endpoints": [
                "/api", "/api/v1", "/api/v2", "/api/v3",
                "/rest", "/rest/api", "/graphql", "/soap",
                "/xmlrpc", "/rpc", "/service", "/services",
                "/endpoint", "/endpoints", "/webhook", "/webhooks"
            ],
            "common_files": [
                "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
                "/favicon.ico", "/apple-touch-icon.png",
                "/humans.txt", "/security.txt", "/.well-known",
                "/.well-known/security.txt", "/.well-known/robots.txt"
            ],
            "error_pages": [
                "/404", "/500", "/error", "/errors", "/error.php",
                "/error.html", "/notfound", "/forbidden", "/403",
                "/401", "/unauthorized", "/maintenance", "/offline"
            ]
        }
        
        # File extensions to test
        self.file_extensions = [
            ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl",
            ".sh", ".bat", ".cmd", ".exe", ".dll", ".so",
            ".sql", ".db", ".sqlite", ".mdb", ".accdb",
            ".txt", ".log", ".bak", ".old", ".tmp", ".temp"
        ]

    def scan_common_paths(self, base_url: str) -> Dict:
        """
        Scan for common paths and files
        """
        logging.info(f"Scanning common paths for: {base_url}")
        
        # Flatten all paths into a single list
        all_paths = []
        for category, paths in self.common_paths.items():
            for path in paths:
                all_paths.append((path, category))
        
        # Add file extensions to common paths
        for path, category in all_paths.copy():
            if not path.endswith(('.php', '.html', '.txt', '.xml', '.ico', '.png')):
                for ext in self.file_extensions:
                    all_paths.append((path + ext, category))
        
        print(f"🔍 Testing {len(all_paths)} paths with {self.max_threads} threads...")
        
        # Test paths concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for path, category in all_paths:
                future = executor.submit(self._test_path, base_url, path, category)
                futures.append(future)
            
            # Collect results
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._categorize_finding(result)
                    completed += 1
                    if completed % 50 == 0:
                        print(f"   Progress: {completed}/{len(all_paths)} paths tested")
                except Exception as e:
                    logging.debug(f"Path test failed: {e}")
        
        return self.findings

    def _test_path(self, base_url: str, path: str, category: str) -> Optional[Dict]:
        """Test a single path"""
        try:
            url = urljoin(base_url, path)
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            # Small delay to be respectful to the server
            time.sleep(0.1)
            
            # Check for interesting responses
            if response.status_code in [200, 301, 302, 403, 500]:
                return {
                    "url": url,
                    "path": path,
                    "status_code": response.status_code,
                    "category": category,
                    "content_length": len(response.content),
                    "content_type": response.headers.get('Content-Type', ''),
                    "server": response.headers.get('Server', ''),
                    "response_time": response.elapsed.total_seconds()
                }
        
        except Exception as e:
            logging.debug(f"Failed to test {path}: {e}")
        
        return None

    def _categorize_finding(self, result: Dict):
        """Categorize findings based on type and content"""
        url = result["url"]
        path = result["path"]
        status_code = result["status_code"]
        content_length = result["content_length"]
        
        # Basic discovery
        self.findings["discovered_paths"].append(result)
        
        # Categorize by status code
        if status_code == 200:
            # Check for sensitive content
            if any(keyword in path.lower() for keyword in ['admin', 'login', 'dashboard', 'panel']):
                self.findings["admin_panels"].append(result)
            
            elif any(keyword in path.lower() for keyword in ['backup', 'old', 'archive', 'sql']):
                self.findings["backup_files"].append(result)
            
            elif any(keyword in path.lower() for keyword in ['config', 'env', 'settings']):
                self.findings["config_files"].append(result)
            
            elif any(keyword in path.lower() for keyword in ['test', 'debug', 'info', 'phpinfo']):
                self.findings["development_files"].append(result)
            
            elif any(keyword in path.lower() for keyword in ['api', 'rest', 'graphql', 'service']):
                self.findings["api_endpoints"].append(result)
        
        elif status_code in [403, 401]:
            # Forbidden/Unauthorized - might be protected sensitive content
            if any(keyword in path.lower() for keyword in ['admin', 'config', 'backup', 'private']):
                self.findings["sensitive_files"].append(result)
        
        elif status_code in [500, 502, 503]:
            # Server errors - might reveal information
            self.findings["error_pages"].append(result)

    def scan_directory_traversal(self, base_url: str) -> List[Dict]:
        """Scan for directory traversal vulnerabilities"""
        logging.info("Scanning for directory traversal vulnerabilities")
        
        traversal_paths = [
            "../", "../../", "../../../", "../../../../",
            "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\",
            "%2e%2e%2f", "%2e%2e%5c", "..%252f", "..%255c",
            "....//", "....\\\\", "%2e%2e%2f%2e%2e%2f"
        ]
        
        sensitive_files = [
            "etc/passwd", "etc/shadow", "etc/hosts", "etc/group",
            "windows/system32/drivers/etc/hosts", "boot.ini",
            "windows/win.ini", "windows/system.ini"
        ]
        
        findings = []
        
        for traversal in traversal_paths:
            for file_path in sensitive_files:
                test_path = traversal + file_path
                try:
                    url = urljoin(base_url, test_path)
                    response = self.session.get(url, timeout=5)
                    
                    # Check for file content indicators
                    content_indicators = [
                        'root:', 'bin:', 'daemon:', 'nobody:', 'localhost',
                        '127.0.0.1', 'windows', 'microsoft', 'system32',
                        '[boot loader]', '[operating systems]'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in content_indicators):
                        findings.append({
                            "type": "Directory Traversal",
                            "url": url,
                            "path": test_path,
                            "status_code": response.status_code,
                            "evidence": response.text[:200],
                            "severity": "Critical"
                        })
                
                except Exception as e:
                    logging.debug(f"Directory traversal test failed: {e}")
        
        return findings

    def scan_common_files(self, base_url: str) -> List[Dict]:
        """Scan for common files that might reveal information"""
        logging.info("Scanning for common information disclosure files")
        
        common_files = [
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/.well-known/security.txt", "/.well-known/robots.txt",
            "/humans.txt", "/security.txt", "/.htaccess",
            "/web.config", "/phpinfo.php", "/info.php",
            "/test.php", "/debug.php", "/status.php"
        ]
        
        findings = []
        
        for file_path in common_files:
            try:
                url = urljoin(base_url, file_path)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    # Analyze content for sensitive information
                    content = response.text.lower()
                    sensitive_keywords = [
                        'password', 'secret', 'key', 'token', 'api',
                        'database', 'mysql', 'postgresql', 'oracle',
                        'admin', 'root', 'user', 'config'
                    ]
                    
                    found_keywords = [kw for kw in sensitive_keywords if kw in content]
                    
                    if found_keywords:
                        findings.append({
                            "type": "Information Disclosure",
                            "url": url,
                            "file": file_path,
                            "status_code": response.status_code,
                            "sensitive_keywords": found_keywords,
                            "content_preview": response.text[:300],
                            "severity": "Medium"
                        })
            
            except Exception as e:
                logging.debug(f"Common file scan failed for {file_path}: {e}")
        
        return findings

    def generate_paths_report(self, output_file: str = "common_paths_scan.json"):
        """Generate comprehensive paths scan report"""
        
        # Only create directory if output_file has a directory path
        if os.path.dirname(output_file):
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2)
        
        logging.info(f"Common paths scan report saved to {output_file}")
        return self.findings

    def get_scan_summary(self) -> Dict:
        """Get summary of scan results"""
        summary = {
            "total_discovered": len(self.findings["discovered_paths"]),
            "admin_panels": len(self.findings["admin_panels"]),
            "backup_files": len(self.findings["backup_files"]),
            "config_files": len(self.findings["config_files"]),
            "development_files": len(self.findings["development_files"]),
            "api_endpoints": len(self.findings["api_endpoints"]),
            "sensitive_files": len(self.findings["sensitive_files"]),
            "error_pages": len(self.findings["error_pages"])
        }
        
        return summary

    def print_summary(self):
        """Print a summary of scan results"""
        print("\n" + "="*60)
        print("🔍 COMMON PATHS SCAN SUMMARY")
        print("="*60)
        
        summary = self.get_scan_summary()
        
        print(f"📊 Total Paths Discovered: {summary['total_discovered']}")
        print(f"🔐 Admin Panels: {summary['admin_panels']}")
        print(f"💾 Backup Files: {summary['backup_files']}")
        print(f"⚙️  Config Files: {summary['config_files']}")
        print(f"🛠️  Development Files: {summary['development_files']}")
        print(f"🔌 API Endpoints: {summary['api_endpoints']}")
        print(f"🔒 Sensitive Files: {summary['sensitive_files']}")
        print(f"❌ Error Pages: {summary['error_pages']}")
        
        # Show most interesting findings
        interesting_findings = []
        for category in ['admin_panels', 'backup_files', 'config_files', 'development_files']:
            for finding in self.findings[category][:3]:  # Show first 3 of each
                interesting_findings.append(finding)
        
        if interesting_findings:
            print(f"\n🎯 INTERESTING FINDINGS:")
            for finding in interesting_findings[:10]:  # Show top 10
                status_emoji = "✅" if finding['status_code'] == 200 else "🔒" if finding['status_code'] in [403, 401] else "❌"
                print(f"   {status_emoji} {finding['url']} ({finding['status_code']})")
        
        print("="*60)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Common Paths Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--output", default="common_paths_scan.json", help="Output file")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    args = parser.parse_args()
    
    scanner = CommonPathsScanner(max_threads=args.threads)
    findings = scanner.scan_common_paths(args.url)
    scanner.generate_paths_report(args.output)
    scanner.print_summary()
