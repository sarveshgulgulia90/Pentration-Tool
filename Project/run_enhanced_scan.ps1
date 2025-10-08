# run_enhanced_scan.ps1
# Enhanced comprehensive vulnerability scanner
# Scans for 10+ different vulnerability types

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    [int]$MaxPages = 30,
    [int]$MaxDepth = 1,
    [double]$Delay = 0.3,
    [switch]$AllowSubdomain,
    [switch]$Force
)

Write-Host "Enhanced Penetration Testing Scanner" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""

# Safety warning
if (-not $Force) {
    Write-Host "WARNING: You are about to perform a comprehensive security scan!" -ForegroundColor Red
    Write-Host "Target: $Target" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This scanner will test for 10+ vulnerability types:" -ForegroundColor Yellow
    Write-Host "• SQL Injection" -ForegroundColor Gray
    Write-Host "• Cross-Site Scripting (XSS)" -ForegroundColor Gray
    Write-Host "• CSRF Vulnerabilities" -ForegroundColor Gray
    Write-Host "• Directory Traversal" -ForegroundColor Gray
    Write-Host "• Command Injection" -ForegroundColor Gray
    Write-Host "• Open Redirect" -ForegroundColor Gray
    Write-Host "• Information Disclosure" -ForegroundColor Gray
    Write-Host "• File Inclusion" -ForegroundColor Gray
    Write-Host "• XXE (XML External Entity)" -ForegroundColor Gray
    Write-Host "• SSRF (Server-Side Request Forgery)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Only scan websites you own or have explicit permission to test." -ForegroundColor Yellow
    Write-Host ""
    
    $response = Read-Host "Continue with enhanced scan? (yes/no)"
    if ($response -notmatch "^(yes|y)$") {
        Write-Host "Enhanced scan cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "Starting ENHANCED scan of: $Target" -ForegroundColor Cyan
Write-Host "Settings: MaxPages=$MaxPages, MaxDepth=$MaxDepth, Delay=${Delay}s" -ForegroundColor Gray
Write-Host ""

# Set environment variable for detectors
$env:LAB_MODE="1"

# Step 1: Fast crawling
Write-Host "Step 1: Crawling target for reconnaissance..." -ForegroundColor Yellow
$startTime = Get-Date
$crawlerCmd = "python fast_live_crawler.py --target `"$Target`" --max-pages $MaxPages --max-depth $MaxDepth --delay $Delay"
if ($AllowSubdomain) {
    $crawlerCmd += " --allow-subdomain"
}
if ($Force) {
    $crawlerCmd += " --force"
}

Invoke-Expression $crawlerCmd
$crawlTime = (Get-Date) - $startTime

if ($LASTEXITCODE -ne 0) {
    Write-Host "Crawler failed. Stopping." -ForegroundColor Red
    exit 1
}

Write-Host "Crawl completed in $($crawlTime.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Green

# Step 2: Enhanced vulnerability scanning
Write-Host "Step 2: Running enhanced vulnerability detection..." -ForegroundColor Yellow
$startTime = Get-Date
python enhanced_scanner.py --crawl data/crawl_results.json --output data/enhanced_findings.json
$scanTime = (Get-Date) - $startTime
Write-Host "Enhanced scanning completed in $($scanTime.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Green

# Step 3: Generate comprehensive report
Write-Host "Step 3: Generating comprehensive report..." -ForegroundColor Yellow
python reporter/report_generartor.py --crawl data/crawl_results.json --sql data/sql_findings.json --xss data/xss_findings.json --out data/enhanced_scan_report.html

# Step 4: Generate detailed findings report
Write-Host "Step 4: Creating detailed findings report..." -ForegroundColor Yellow
python -c "
import json
import os
from datetime import datetime

# Load enhanced findings
with open('data/enhanced_findings.json', 'r') as f:
    findings = json.load(f)

# Generate detailed HTML report
html = []
html.append('<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Enhanced Security Scan Report</title>')
html.append('<style>body{font-family:Arial,sans-serif;margin:20px;} .vuln{background:#f9f9f9;padding:10px;margin:10px 0;border-left:4px solid #ff6b6b;} .info{background:#e3f2fd;padding:10px;margin:10px 0;border-left:4px solid #2196f3;} .success{background:#e8f5e8;padding:10px;margin:10px 0;border-left:4px solid #4caf50;}</style>')
html.append('</head><body>')
html.append(f'<h1>Enhanced Security Scan Report</h1>')
html.append(f'<p><strong>Generated:</strong> {datetime.now().strftime(\"%Y-%m-%d %H:%M:%S\")}</p>')
html.append(f'<p><strong>Target:</strong> {os.environ.get(\"TARGET\", \"Unknown\")}</p>')

# Summary
total_findings = sum(len(vulns) for vulns in findings.values())
html.append(f'<h2>Summary</h2>')
html.append(f'<div class=\"info\"><strong>Total Vulnerabilities Found:</strong> {total_findings}</div>')

# Detailed findings
for vuln_type, vulns in findings.items():
    if vulns:
        html.append(f'<h2>{vuln_type.replace(\"_\", \" \").title()} ({len(vulns)} findings)</h2>')
        for i, vuln in enumerate(vulns, 1):
            html.append(f'<div class=\"vuln\">')
            html.append(f'<h3>Finding #{i}</h3>')
            html.append(f'<p><strong>Type:</strong> {vuln.get(\"type\", \"Unknown\")}</p>')
            if \"url\" in vuln:
                html.append(f'<p><strong>URL:</strong> {vuln[\"url\"]}</p>')
            if \"parameter\" in vuln:
                html.append(f'<p><strong>Parameter:</strong> {vuln[\"parameter\"]}</p>')
            if \"payload\" in vuln:
                html.append(f'<p><strong>Payload:</strong> <code>{vuln[\"payload\"]}</code></p>')
            if \"evidence\" in vuln:
                html.append(f'<p><strong>Evidence:</strong></p><pre>{vuln[\"evidence\"][:500]}</pre>')
            html.append(f'</div>')

if total_findings == 0:
    html.append('<div class=\"success\"><h2>No Vulnerabilities Found</h2><p>Great! No security vulnerabilities were detected in this scan.</p></div>')

html.append('</body></html>')

# Save report
with open('data/enhanced_detailed_report.html', 'w', encoding='utf-8') as f:
    f.write(''.join(html))

print('Detailed findings report generated')
"

$totalTime = (Get-Date) - $startTime
Write-Host ""
Write-Host "Enhanced scan completed in $($totalTime.TotalSeconds.ToString('F1')) seconds!" -ForegroundColor Green
Write-Host ""
Write-Host "Reports generated:" -ForegroundColor Cyan
Write-Host "• Enhanced Report: data/enhanced_scan_report.html" -ForegroundColor Gray
Write-Host "• Detailed Findings: data/enhanced_detailed_report.html" -ForegroundColor Gray
Write-Host "• Raw Data: data/enhanced_findings.json" -ForegroundColor Gray
Write-Host ""

# Ask if user wants to open the report
$openReport = Read-Host "Open detailed report in browser? (yes/no)"
if ($openReport -match "^(yes|y)$") {
    Start-Process "data/enhanced_detailed_report.html"
}
