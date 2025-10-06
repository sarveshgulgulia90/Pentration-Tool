#!/usr/bin/env python3
"""
Start the beautiful web GUI for Passive Security Scanner
"""

import subprocess
import sys
import os

def main():
    print("🚀 Starting Passive Security Scanner Web GUI")
    print("=" * 50)
    
    # Check if Flask is installed
    try:
        import flask
        print("✅ Flask is installed")
    except ImportError:
        print("❌ Flask not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "flask"])
        print("✅ Flask installed successfully")
    
    # Check if requests is installed
    try:
        import requests
        print("✅ Requests is installed")
    except ImportError:
        print("❌ Requests not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        print("✅ Requests installed successfully")
    
    print("\n🌐 Starting web server...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("=" * 50)
    
    # Start the web GUI
    from web_gui import app
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()
