#!/usr/bin/env python3
"""
Demo and Explanation Script
Shows you exactly what each tool does with examples
"""

def main():
    print("🔍 PASSIVE SECURITY SCANNER - COMPLETE EXPLANATION")
    print("=" * 60)
    
    print("\n📋 WHAT EACH FILE DOES:")
    print("-" * 30)
    
    print("\n1️⃣ passive_header_analyzer.py")
    print("   🎯 Purpose: Checks website security headers")
    print("   🔍 What it finds:")
    print("      • Missing security headers (like missing locks)")
    print("      • Misconfigured headers (like broken locks)")
    print("      • Information disclosure (like leaving keys visible)")
    print("      • Cookie security issues")
    print("   📊 Output: Security score (A+ to F) and detailed findings")
    
    print("\n2️⃣ common_paths_scanner.py")
    print("   🎯 Purpose: Finds common files and directories")
    print("   🔍 What it finds:")
    print("      • Admin panels (/admin, /wp-admin)")
    print("      • Backup files (/backup.sql, /database.sql)")
    print("      • Config files (/.env, /config.php)")
    print("      • Development files (/test.php, /debug.php)")
    print("      • API endpoints (/api, /rest)")
    print("   📊 Output: List of discovered paths with status codes")
    
    print("\n3️⃣ web_gui.py")
    print("   🎯 Purpose: Beautiful web interface")
    print("   🌐 Features:")
    print("      • Easy-to-use web form")
    print("      • Real-time scan progress")
    print("      • Beautiful results display")
    print("      • Security score visualization")
    print("      • Detailed findings with severity levels")
    
    print("\n4️⃣ start_web_gui.py")
    print("   🎯 Purpose: Easy startup script")
    print("   🚀 What it does:")
    print("      • Installs required packages automatically")
    print("      • Starts the web server")
    print("      • Opens browser to localhost:5000")
    
    print("\n" + "=" * 60)
    print("🌐 HOW TO USE THE WEB GUI:")
    print("=" * 60)
    
    print("\n1️⃣ Start the Web Interface:")
    print("   python start_web_gui.py")
    
    print("\n2️⃣ Open Your Browser:")
    print("   Go to: http://localhost:5000")
    
    print("\n3️⃣ Use the Interface:")
    print("   • Enter target URL (e.g., https://example.com)")
    print("   • Choose scan type:")
    print("     - Full Scan: Both headers and paths")
    print("     - Headers Only: Just security analysis")
    print("     - Paths Only: Just file discovery")
    print("   • Click 'Start Security Scan'")
    print("   • Wait for results (30 seconds to 3 minutes)")
    print("   • View beautiful results with charts!")
    
    print("\n" + "=" * 60)
    print("📊 EXAMPLE OUTPUTS:")
    print("=" * 60)
    
    print("\n🔍 HEADER ANALYSIS EXAMPLE:")
    print("   Security Score: 75/100 (B - Fair)")
    print("   ✅ Security Headers Present: 3")
    print("   ❌ Missing Headers: 2")
    print("   ⚠️  Misconfigured Headers: 1")
    print("   🔍 Information Disclosure: 1")
    
    print("\n📁 COMMON PATHS EXAMPLE:")
    print("   📊 Total Paths Discovered: 15")
    print("   🔐 Admin Panels: 2")
    print("   💾 Backup Files: 1")
    print("   ⚙️  Config Files: 3")
    print("   🛠️  Development Files: 2")
    print("   🔌 API Endpoints: 1")
    
    print("\n" + "=" * 60)
    print("🎯 WHAT YOU'LL SEE IN THE WEB GUI:")
    print("=" * 60)
    
    print("\n📱 Beautiful Interface Features:")
    print("   • Modern, responsive design")
    print("   • Real-time progress indicators")
    print("   • Security score with color-coded circles")
    print("   • Detailed findings with severity levels")
    print("   • Statistics and charts")
    print("   • Mobile-friendly design")
    
    print("\n🔍 Security Score Colors:")
    print("   🟢 A+ (90-100): Excellent (Green)")
    print("   🔵 A (80-89): Good (Blue)")
    print("   🟡 B (70-79): Fair (Yellow)")
    print("   🟠 C (60-69): Poor (Orange)")
    print("   🔴 F (0-59): Critical (Red)")
    
    print("\n" + "=" * 60)
    print("🚀 QUICK START COMMANDS:")
    print("=" * 60)
    
    print("\n🌐 Web GUI (Recommended):")
    print("   python start_web_gui.py")
    print("   # Then open http://localhost:5000")
    
    print("\n💻 Command Line:")
    print("   # Test headers only")
    print("   python test_headers_only.py https://httpbin.org")
    print("   ")
    print("   # Test both tools")
    print("   python test_simple.py https://httpbin.org")
    print("   ")
    print("   # Individual tools")
    print("   python passive_header_analyzer.py --url https://httpbin.org")
    print("   python common_paths_scanner.py --url https://httpbin.org --threads 3")
    
    print("\n" + "=" * 60)
    print("🎉 READY TO SCAN!")
    print("=" * 60)
    print("Choose your preferred method and start scanning!")
    print("Remember: Only scan websites you own or have permission to test!")

if __name__ == "__main__":
    main()
