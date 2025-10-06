#!/usr/bin/env python3
"""
Test script for header analysis only
"""

import sys
from passive_header_analyzer import PassiveHeaderAnalyzer

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_headers_only.py <target_url>")
        print("Example: python test_headers_only.py https://httpbin.org")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print("🔍 HEADER ANALYSIS TEST")
    print("=" * 40)
    print(f"🎯 Target: {target_url}")
    print("=" * 40)
    
    try:
        analyzer = PassiveHeaderAnalyzer()
        findings = analyzer.analyze_headers(target_url)
        analyzer.generate_header_report("header_analysis.json")
        analyzer.print_summary()
        
        print("\n✅ Header analysis completed!")
        print("📁 Results saved to: header_analysis.json")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
