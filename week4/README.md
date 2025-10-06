# 🔍 Passive Security Scanner - Week 4

This directory contains standalone passive security scanning tools with a beautiful web GUI for easy use.

## 📁 Files

- `passive_header_analyzer.py` - HTTP header security analysis
- `common_paths_scanner.py` - Common files and directories discovery
- `web_gui.py` - Beautiful web interface
- `start_web_gui.py` - Easy startup script
- `run_passive_tests.py` - Command line runner
- `requirements.txt` - Required Python packages

## 🌐 **BEAUTIFUL WEB GUI (RECOMMENDED)**

### 1. Start the Web Interface
```bash
python start_web_gui.py
```

### 2. Open Your Browser
Go to: **http://localhost:5000**

### 3. Use the Beautiful Interface
- Enter target URL
- Choose scan type (Full/Headers/Paths)
- Click "Start Security Scan"
- View beautiful results with charts and graphs!

## 🚀 Command Line Usage

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Both Tools Together
```bash
python run_passive_tests.py https://example.com
```

### 3. Run Individual Tools

**Header Analysis Only:**
```bash
python passive_header_analyzer.py --url https://example.com
```

**Common Paths Only:**
```bash
python common_paths_scanner.py --url https://example.com --threads 10
```

## 📊 What You Get

### Header Analysis Results:
- Security headers present/missing
- Header misconfigurations
- Information disclosure
- Cookie security issues
- Security score (A+ to F)

### Common Paths Results:
- Admin panels discovered
- Backup files found
- Config files exposed
- API endpoints detected
- Sensitive directories
- Development files

## 📁 Output Files

- `header_analysis.json` - Detailed header analysis
- `common_paths_scan.json` - Paths discovery results
- `combined_passive_scan.json` - Combined report

## ⚠️ Important Notes

- **Only scan websites you own or have permission to test**
- These are passive tools (no aggressive testing)
- Results are saved as JSON files
- Use responsibly and ethically

## 🎯 Example Usage

```bash
# Test your own website
python run_passive_tests.py https://mywebsite.com

# Test with more threads for faster scanning
python common_paths_scanner.py --url https://mywebsite.com --threads 20

# Get detailed header analysis
python passive_header_analyzer.py --url https://mywebsite.com --output detailed_headers.json
```

## 🔍 Understanding Results

### Security Score Grades:
- **A+ (90-100)**: Excellent security posture
- **A (80-89)**: Good security posture
- **B (70-79)**: Fair security posture
- **C (60-69)**: Poor security posture
- **F (0-59)**: Critical security issues

### Common Findings:
- **Status 200**: File/directory accessible
- **Status 403**: Forbidden (might be protected)
- **Status 401**: Unauthorized (authentication required)
- **Status 500**: Server error (might reveal info)
