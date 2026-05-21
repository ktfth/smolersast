# SmolerSAST Demo — Scan banking sample and open HTML dashboard
$ErrorActionPreference = 'Stop'

Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SmolerSAST — Demo: Banking Security Scan" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Build if needed
$cliDll = "src/SmolerSAST.Cli/bin/Release/net9.0/SmolerSAST.Cli.dll"
if (-not (Test-Path $cliDll)) {
    Write-Host "[1/3] Building..." -ForegroundColor Yellow
    dotnet build -c Release -q
} else {
    Write-Host "[1/3] Build up to date" -ForegroundColor Green
}

# Ensure output directory
if (-not (Test-Path "demo-output")) {
    New-Item -ItemType Directory -Path "demo-output" -Force | Out-Null
}

# Run scan
Write-Host "[2/3] Scanning fixtures/banking-sample..." -ForegroundColor Yellow
Write-Host ""

dotnet run --project src/SmolerSAST.Cli -c Release --no-build -- `
    scan --path fixtures/banking-sample --output demo-output/report.sarif --format html

Write-Host ""
Write-Host "[3/3] Dashboard generated: demo-output/report.html" -ForegroundColor Green
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Open demo-output/report.html in your browser" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

# Open in browser
Start-Process "demo-output/report.html"
