# passive_header_analyzer.py
"""
Passive Header Security Analyzer
Analyzes HTTP headers for security vulnerabilities and misconfigurations
"""

import requests
import json
import logging
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class PassiveHeaderAnalyzer:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.findings = {
            "security_headers": [],
            "missing_headers": [],
            "misconfigured_headers": [],
            "information_disclosure": [],
            "cookies_analysis": [],
            "server_analysis": []
        }
        
        # Security headers that should be present
        self.required_security_headers = {
            "Strict-Transport-Security": {
                "description": "Forces HTTPS connections",
                "severity": "High",
                "recommended_value": "max-age=31536000; includeSubDomains; preload"
            },
            "Content-Security-Policy": {
                "description": "Prevents XSS attacks",
                "severity": "High", 
                "recommended_value": "default-src 'self'"
            },
            "X-Frame-Options": {
                "description": "Prevents clickjacking",
                "severity": "High",
                "recommended_value": "DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "description": "Prevents MIME type sniffing",
                "severity": "Medium",
                "recommended_value": "nosniff"
            },
            "X-XSS-Protection": {
                "description": "Enables XSS filtering",
                "severity": "Medium",
                "recommended_value": "1; mode=block"
            },
            "Referrer-Policy": {
                "description": "Controls referrer information",
                "severity": "Low",
                "recommended_value": "strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "description": "Controls browser features",
                "severity": "Medium",
                "recommended_value": "geolocation=(), microphone=(), camera=()"
            }
        }
        
        # Dangerous header values
        self.dangerous_values = {
            "Server": ["Apache/2.2.0", "nginx/1.0", "IIS/6.0", "IIS/7.0"],
            "X-Powered-By": ["PHP/4.0", "PHP/5.0", "ASP.NET/2.0"],
            "X-AspNet-Version": ["2.0", "3.0", "4.0"]
        }
        
        # Information disclosure patterns
        self.info_disclosure_patterns = [
            r"Server: (.+)",
            r"X-Powered-By: (.+)",
            r"X-AspNet-Version: (.+)",
            r"X-AspNetMvc-Version: (.+)",
            r"X-Runtime: (.+)",
            r"X-Version: (.+)",
            r"X-Backend: (.+)",
            r"X-Served-By: (.+)"
        ]

    def analyze_headers(self, url: str) -> Dict:
        """
        Analyze HTTP headers for security issues
        """
        logging.info(f"Analyzing headers for: {url}")
        
        try:
            # Send HEAD request to get headers
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            # Analyze security headers
            self._check_security_headers(headers, url)
            
            # Check for missing headers
            self._check_missing_headers(headers, url)
            
            # Check for misconfigured headers
            self._check_misconfigured_headers(headers, url)
            
            # Check for information disclosure
            self._check_information_disclosure(headers, url)
            
            # Analyze cookies
            self._analyze_cookies(headers, url)
            
            # Analyze server information
            self._analyze_server_info(headers, url)
            
            return self.findings
            
        except Exception as e:
            logging.error(f"Header analysis failed for {url}: {e}")
            return self.findings

    def _check_security_headers(self, headers: Dict, url: str):
        """Check for presence and configuration of security headers"""
        for header_name, config in self.required_security_headers.items():
            if header_name in headers:
                value = headers[header_name]
                self.findings["security_headers"].append({
                    "type": "Security Header Present",
                    "header": header_name,
                    "value": value,
                    "url": url,
                    "description": config["description"],
                    "severity": config["severity"],
                    "status": "Present"
                })
            else:
                self.findings["missing_headers"].append({
                    "type": "Missing Security Header",
                    "header": header_name,
                    "url": url,
                    "description": config["description"],
                    "severity": config["severity"],
                    "recommended_value": config["recommended_value"],
                    "status": "Missing"
                })

    def _check_missing_headers(self, headers: Dict, url: str):
        """Check for missing critical security headers"""
        critical_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy", 
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]
        
        for header in critical_headers:
            if header not in headers:
                self.findings["missing_headers"].append({
                    "type": "Critical Header Missing",
                    "header": header,
                    "url": url,
                    "severity": "High",
                    "status": "Missing"
                })

    def _check_misconfigured_headers(self, headers: Dict, url: str):
        """Check for misconfigured security headers"""
        misconfigurations = []
        
        # Check HSTS configuration
        if "Strict-Transport-Security" in headers:
            hsts_value = headers["Strict-Transport-Security"]
            if "max-age" not in hsts_value:
                misconfigurations.append({
                    "header": "Strict-Transport-Security",
                    "issue": "Missing max-age directive",
                    "severity": "High"
                })
            elif "max-age=0" in hsts_value:
                misconfigurations.append({
                    "header": "Strict-Transport-Security", 
                    "issue": "max-age=0 disables HSTS",
                    "severity": "High"
                })
        
        # Check CSP configuration
        if "Content-Security-Policy" in headers:
            csp_value = headers["Content-Security-Policy"]
            if "default-src" not in csp_value:
                misconfigurations.append({
                    "header": "Content-Security-Policy",
                    "issue": "Missing default-src directive",
                    "severity": "Medium"
                })
            if "'unsafe-inline'" in csp_value:
                misconfigurations.append({
                    "header": "Content-Security-Policy",
                    "issue": "unsafe-inline allows inline scripts",
                    "severity": "Medium"
                })
        
        # Check X-Frame-Options
        if "X-Frame-Options" in headers:
            xfo_value = headers["X-Frame-Options"]
            if xfo_value.upper() not in ["DENY", "SAMEORIGIN"]:
                misconfigurations.append({
                    "header": "X-Frame-Options",
                    "issue": f"Invalid value: {xfo_value}",
                    "severity": "Medium"
                })
        
        for misconfig in misconfigurations:
            self.findings["misconfigured_headers"].append({
                "type": "Misconfigured Header",
                "url": url,
                **misconfig
            })

    def _check_information_disclosure(self, headers: Dict, url: str):
        """Check for information disclosure in headers"""
        import re
        
        for header_name, header_value in headers.items():
            # Check for version information
            if any(keyword in header_name.lower() for keyword in ['version', 'powered', 'server']):
                self.findings["information_disclosure"].append({
                    "type": "Version Information Disclosure",
                    "header": header_name,
                    "value": header_value,
                    "url": url,
                    "severity": "Low",
                    "description": "Server version information exposed"
                })
            
            # Check for debug information
            if any(keyword in header_value.lower() for keyword in ['debug', 'test', 'dev', 'development']):
                self.findings["information_disclosure"].append({
                    "type": "Debug Information Disclosure",
                    "header": header_name,
                    "value": header_value,
                    "url": url,
                    "severity": "Medium",
                    "description": "Debug information exposed in headers"
                })
            
            # Check for internal IPs or domains
            internal_patterns = [
                r'192\.168\.\d+\.\d+',
                r'10\.\d+\.\d+\.\d+',
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
                r'localhost',
                r'127\.0\.0\.1',
                r'\.local',
                r'\.internal'
            ]
            
            for pattern in internal_patterns:
                if re.search(pattern, header_value):
                    self.findings["information_disclosure"].append({
                        "type": "Internal Information Disclosure",
                        "header": header_name,
                        "value": header_value,
                        "url": url,
                        "severity": "Medium",
                        "description": "Internal network information exposed"
                    })

    def _analyze_cookies(self, headers: Dict, url: str):
        """Analyze cookie security settings"""
        cookie_header = headers.get('Set-Cookie', '')
        if not cookie_header:
            return
        
        cookies = cookie_header.split(',') if isinstance(cookie_header, str) else [cookie_header]
        
        for cookie in cookies:
            cookie_analysis = {
                "type": "Cookie Analysis",
                "url": url,
                "cookie": cookie.strip(),
                "issues": []
            }
            
            cookie_lower = cookie.lower()
            
            # Check for missing security flags
            if 'secure' not in cookie_lower:
                cookie_analysis["issues"].append({
                    "issue": "Missing Secure flag",
                    "severity": "High",
                    "description": "Cookie can be transmitted over HTTP"
                })
            
            if 'httponly' not in cookie_lower:
                cookie_analysis["issues"].append({
                    "issue": "Missing HttpOnly flag", 
                    "severity": "Medium",
                    "description": "Cookie accessible via JavaScript"
                })
            
            if 'samesite' not in cookie_lower:
                cookie_analysis["issues"].append({
                    "issue": "Missing SameSite attribute",
                    "severity": "Medium", 
                    "description": "Cookie vulnerable to CSRF attacks"
                })
            
            if cookie_analysis["issues"]:
                self.findings["cookies_analysis"].append(cookie_analysis)

    def _analyze_server_info(self, headers: Dict, url: str):
        """Analyze server information for security issues"""
        server_header = headers.get('Server', '')
        powered_by_header = headers.get('X-Powered-By', '')
        
        if server_header:
            self.findings["server_analysis"].append({
                "type": "Server Information",
                "header": "Server",
                "value": server_header,
                "url": url,
                "severity": "Low",
                "description": "Server version information exposed"
            })
        
        if powered_by_header:
            self.findings["server_analysis"].append({
                "type": "Technology Information",
                "header": "X-Powered-By",
                "value": powered_by_header,
                "url": url,
                "severity": "Low",
                "description": "Technology stack information exposed"
            })
        
        # Check for dangerous server versions
        for header_name, dangerous_versions in self.dangerous_values.items():
            if header_name in headers:
                header_value = headers[header_name]
                for dangerous_version in dangerous_versions:
                    if dangerous_version in header_value:
                        self.findings["server_analysis"].append({
                            "type": "Dangerous Server Version",
                            "header": header_name,
                            "value": header_value,
                            "url": url,
                            "severity": "High",
                            "description": f"Potentially vulnerable server version: {dangerous_version}"
                        })

    def generate_header_report(self, output_file: str = "data/header_analysis.json"):
        """Generate comprehensive header analysis report"""
        import os
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2)
        
        logging.info(f"Header analysis report saved to {output_file}")
        return self.findings

    def get_security_score(self) -> Tuple[int, str]:
        """Calculate security score based on header analysis"""
        total_checks = 0
        passed_checks = 0
        
        # Count security headers present
        total_checks += len(self.required_security_headers)
        passed_checks += len(self.findings["security_headers"])
        
        # Deduct points for missing critical headers
        critical_missing = len([f for f in self.findings["missing_headers"] 
                              if f.get("severity") == "High"])
        passed_checks -= critical_missing
        
        # Deduct points for misconfigurations
        misconfig_count = len(self.findings["misconfigured_headers"])
        passed_checks -= misconfig_count
        
        # Deduct points for information disclosure
        info_disclosure = len(self.findings["information_disclosure"])
        passed_checks -= info_disclosure // 2
        
        # Calculate percentage
        if total_checks <= 0:
            score = 0
        else:
            score = max(0, min(100, (passed_checks / total_checks) * 100))
        
        # Determine grade
        if score >= 90:
            grade = "A+ (Excellent)"
        elif score >= 80:
            grade = "A (Good)"
        elif score >= 70:
            grade = "B (Fair)"
        elif score >= 60:
            grade = "C (Poor)"
        else:
            grade = "F (Critical)"
        
        return int(score), grade

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Passive Header Security Analyzer")
    parser.add_argument("--url", required=True, help="Target URL to analyze")
    parser.add_argument("--output", default="data/header_analysis.json", help="Output file")
    args = parser.parse_args()
    
    analyzer = PassiveHeaderAnalyzer()
    findings = analyzer.analyze_headers(args.url)
    analyzer.generate_header_report(args.output)
    
    score, grade = analyzer.get_security_score()
    print(f"Security Score: {score}/100 ({grade})")
    print(f"Total findings: {sum(len(f) for f in findings.values())}")
