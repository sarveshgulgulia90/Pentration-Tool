# run_all.ps1
$env:LAB_MODE="1"
python crawler.py --target https://89.117.188.225 --max-pages 200 --max-depth 3 --delay 0.5
python detecter/sql_detecter.py --lab --crawl data/crawl_results.json
python detecter/xss_detecter.py --lab --crawl data/crawl_results.json
python reporter/report_generartor.py --crawl data/crawl_results.json --sql data/sql_findings.json --xss data/xss_findings.json --out data/report.html
Write-Output "Done. Open data\report.html"
