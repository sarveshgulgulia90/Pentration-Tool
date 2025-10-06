#!/usr/bin/env python3
"""
Beautiful Web GUI for Passive Security Scanner
Run this and open http://localhost:5000 in your browser
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import os
from datetime import datetime
from passive_header_analyzer import PassiveHeaderAnalyzer
from common_paths_scanner import CommonPathsScanner
import threading
import time

app = Flask(__name__)

# Global variables to store scan results
scan_results = {
    'header_analysis': None,
    'common_paths': None,
    'scan_status': 'ready',
    'target_url': '',
    'scan_time': None
}

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    global scan_results
    
    target_url = request.form.get('target_url', '').strip()
    scan_type = request.form.get('scan_type', 'both')
    
    if not target_url:
        return jsonify({'error': 'Please enter a target URL'})
    
    # Reset results
    scan_results = {
        'header_analysis': None,
        'common_paths': None,
        'scan_status': 'running',
        'target_url': target_url,
        'scan_time': None
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(target_url, scan_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'scan_started', 'message': 'Scan started successfully!'})

@app.route('/status')
def get_status():
    """Get current scan status"""
    return jsonify(scan_results)

@app.route('/results')
def show_results():
    """Show scan results page"""
    return render_template('results.html')

def run_scan(target_url, scan_type):
    """Run the actual scan"""
    global scan_results
    
    try:
        print(f"🔍 Starting scan for: {target_url}")
        
        # Header Analysis
        if scan_type in ['headers', 'both']:
            print("📊 Running header analysis...")
            header_analyzer = PassiveHeaderAnalyzer()
            header_findings = header_analyzer.analyze_headers(target_url)
            scan_results['header_analysis'] = {
                'findings': header_findings,
                'summary': {
                    'security_headers': len(header_findings.get('security_headers', [])),
                    'missing_headers': len(header_findings.get('missing_headers', [])),
                    'misconfigured_headers': len(header_findings.get('misconfigured_headers', [])),
                    'information_disclosure': len(header_findings.get('information_disclosure', [])),
                    'cookies_analysis': len(header_findings.get('cookies_analysis', [])),
                    'server_analysis': len(header_findings.get('server_analysis', []))
                },
                'security_score': header_analyzer.get_security_score()
            }
            print("✅ Header analysis completed")
        
        # Common Paths Scan
        if scan_type in ['paths', 'both']:
            print("🔍 Running common paths scan...")
            paths_scanner = CommonPathsScanner(max_threads=3)
            paths_findings = paths_scanner.scan_common_paths(target_url)
            scan_results['common_paths'] = {
                'findings': paths_findings,
                'summary': paths_scanner.get_scan_summary()
            }
            print("✅ Common paths scan completed")
        
        scan_results['scan_status'] = 'completed'
        scan_results['scan_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print("🎉 Scan completed successfully!")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        scan_results['scan_status'] = 'error'
        scan_results['error'] = str(e)

if __name__ == '__main__':
    print("🚀 Starting Passive Security Scanner Web GUI")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
