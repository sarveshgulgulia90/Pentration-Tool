# run_passive_scan.ps1
# PowerShell script to run passive header checks and common paths scanning

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    
    [string]$Output = "data/passive_scan_results.json",
    
    [int]$Threads = 10,
    
    [switch]$Force
)

Write-Host "🔍 Passive Security Scanner" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Check if target is provided
if (-not $Target) {
    Write-Host "❌ Error: Target URL is required" -ForegroundColor Red
    Write-Host "Usage: .\run_passive_scan.ps1 -Target 'https://example.com'" -ForegroundColor Yellow
    exit 1
}

# Safety check
if (-not $Force) {
    Write-Host "⚠️  WARNING: This tool will perform passive security scanning" -ForegroundColor Yellow
    Write-Host "Only use on websites you own or have explicit permission to test!" -ForegroundColor Yellow
    Write-Host ""
    $confirmation = Read-Host "Do you have permission to scan this target? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "❌ Scan cancelled. Only scan with proper authorization." -ForegroundColor Red
        exit 1
    }
}

Write-Host "🎯 Target: $Target" -ForegroundColor Green
Write-Host "📁 Output: $Output" -ForegroundColor Green
Write-Host "🧵 Threads: $Threads" -ForegroundColor Green
Write-Host ""

# Create data directory if it doesn't exist
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
}

Write-Host "🚀 Starting passive security scan..." -ForegroundColor Cyan

try {
    # Run passive header analysis
    Write-Host "📊 Analyzing HTTP headers..." -ForegroundColor Yellow
    python passive_header_analyzer.py --url $Target --output "data/header_analysis.json"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Header analysis failed" -ForegroundColor Red
        exit 1
    }
    
    # Run common paths scanning
    Write-Host "🔍 Scanning common paths and files..." -ForegroundColor Yellow
    python common_paths_scanner.py --url $Target --output "data/common_paths_scan.json" --threads $Threads
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Common paths scan failed" -ForegroundColor Red
        exit 1
    }
    
    # Generate combined report
    Write-Host "📝 Generating combined report..." -ForegroundColor Yellow
    python -c "
import json
import os

# Load results
header_results = {}
paths_results = {}

try:
    with open('data/header_analysis.json', 'r') as f:
        header_results = json.load(f)
except:
    pass

try:
    with open('data/common_paths_scan.json', 'r') as f:
        paths_results = json.load(f)
except:
    pass

# Combine results
combined_results = {
    'scan_info': {
        'target': '$Target',
        'scan_type': 'Passive Security Scan',
        'timestamp': str(__import__('datetime').datetime.now())
    },
    'header_analysis': header_results,
    'common_paths': paths_results,
    'summary': {
        'header_findings': sum(len(v) for v in header_results.values()) if header_results else 0,
        'paths_findings': sum(len(v) for v in paths_results.values()) if paths_results else 0
    }
}

# Save combined results
with open('$Output', 'w') as f:
    json.dump(combined_results, f, indent=2)

print('Combined report generated successfully')
"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Report generation failed" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "✅ Passive scan completed successfully!" -ForegroundColor Green
    Write-Host "📁 Results saved to: $Output" -ForegroundColor Green
    
    # Display summary
    Write-Host ""
    Write-Host "📊 Scan Summary:" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    
    # Count findings
    $headerCount = 0
    $pathsCount = 0
    
    if (Test-Path "data/header_analysis.json") {
        $headerData = Get-Content "data/header_analysis.json" | ConvertFrom-Json
        $headerCount = ($headerData.PSObject.Properties | ForEach-Object { $_.Value.Count } | Measure-Object -Sum).Sum
    }
    
    if (Test-Path "data/common_paths_scan.json") {
        $pathsData = Get-Content "data/common_paths_scan.json" | ConvertFrom-Json
        $pathsCount = ($pathsData.PSObject.Properties | ForEach-Object { $_.Value.Count } | Measure-Object -Sum).Sum
    }
    
    Write-Host "🔍 Header Analysis Findings: $headerCount" -ForegroundColor Yellow
    Write-Host "📁 Common Paths Findings: $pathsCount" -ForegroundColor Yellow
    Write-Host "📊 Total Findings: $($headerCount + $pathsCount)" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "📋 Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the detailed results in: $Output" -ForegroundColor White
    Write-Host "2. Check for critical security headers missing" -ForegroundColor White
    Write-Host "3. Investigate discovered sensitive files and directories" -ForegroundColor White
    Write-Host "4. Implement recommended security headers" -ForegroundColor White
    
} catch {
    Write-Host "❌ Error during scan: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🎉 Passive security scan completed!" -ForegroundColor Green
