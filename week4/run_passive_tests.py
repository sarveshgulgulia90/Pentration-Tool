#!/usr/bin/env python3
"""
Simple runner script for passive header checks and common paths scanning
"""

import sys
import os
from passive_header_analyzer import PassiveHeaderAnalyzer
from common_paths_scanner import CommonPathsScanner

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_passive_tests.py <target_url>")
        print("Example: python run_passive_tests.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print("🔍 PASSIVE SECURITY SCANNER")
    print("=" * 50)
    print(f"🎯 Target: {target_url}")
    print("=" * 50)
    
    # Run header analysis
    print("\n📊 Running Header Analysis...")
    print("-" * 30)
    header_analyzer = PassiveHeaderAnalyzer()
    header_findings = header_analyzer.analyze_headers(target_url)
    header_analyzer.generate_header_report("header_analysis.json")
    header_analyzer.print_summary()
    
    # Run common paths scan
    print("\n🔍 Running Common Paths Scan...")
    print("-" * 30)
    paths_scanner = CommonPathsScanner(max_threads=5)  # Reduced threads to prevent connection issues
    paths_findings = paths_scanner.scan_common_paths(target_url)
    paths_scanner.generate_paths_report("common_paths_scan.json")
    paths_scanner.print_summary()
    
    # Generate combined report
    print("\n📝 Generating Combined Report...")
    print("-" * 30)
    
    import json
    from datetime import datetime
    
    combined_report = {
        "scan_info": {
            "target": target_url,
            "scan_type": "Passive Security Scan",
            "timestamp": datetime.now().isoformat()
        },
        "header_analysis": header_findings,
        "common_paths": paths_findings,
        "summary": {
            "header_findings": sum(len(v) for v in header_findings.values()),
            "paths_findings": sum(len(v) for v in paths_findings.values())
        }
    }
    
    with open("combined_passive_scan.json", "w") as f:
        json.dump(combined_report, f, indent=2)
    
    print("\n✅ SCAN COMPLETED!")
    print("=" * 50)
    print("📁 Files generated:")
    print("   • header_analysis.json - Header security analysis")
    print("   • common_paths_scan.json - Common paths discovery")
    print("   • combined_passive_scan.json - Combined report")
    
    # Final summary
    total_findings = combined_report["summary"]["header_findings"] + combined_report["summary"]["paths_findings"]
    print(f"\n📊 Total Findings: {total_findings}")
    
    if total_findings > 0:
        print("🔍 Review the JSON files for detailed results!")
    else:
        print("🎉 No security issues found in passive analysis!")

if __name__ == "__main__":
    main()
