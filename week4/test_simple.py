#!/usr/bin/env python3
"""
Simple test script for passive security scanning
"""

import sys
import os
from passive_header_analyzer import PassiveHeaderAnalyzer
from common_paths_scanner import CommonPathsScanner

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_simple.py <target_url>")
        print("Example: python test_simple.py https://httpbin.org")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print("🔍 PASSIVE SECURITY SCANNER")
    print("=" * 50)
    print(f"🎯 Target: {target_url}")
    print("=" * 50)
    
    try:
        # Run header analysis
        print("\n📊 Running Header Analysis...")
        print("-" * 30)
        header_analyzer = PassiveHeaderAnalyzer()
        header_findings = header_analyzer.analyze_headers(target_url)
        header_analyzer.generate_header_report("header_analysis.json")
        header_analyzer.print_summary()
        
        # Run common paths scan with fewer threads
        print("\n🔍 Running Common Paths Scan...")
        print("-" * 30)
        paths_scanner = CommonPathsScanner(max_threads=3)  # Very conservative
        paths_findings = paths_scanner.scan_common_paths(target_url)
        paths_scanner.generate_paths_report("common_paths_scan.json")
        paths_scanner.print_summary()
        
        print("\n✅ SCAN COMPLETED!")
        print("=" * 50)
        print("📁 Files generated:")
        print("   • header_analysis.json - Header security analysis")
        print("   • common_paths_scan.json - Common paths discovery")
        
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        print("Try running individual tools:")
        print("python passive_header_analyzer.py --url", target_url)
        print("python common_paths_scanner.py --url", target_url, "--threads 3")

if __name__ == "__main__":
    main()
