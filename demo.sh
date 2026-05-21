#!/usr/bin/env bash
# SmolerSAST Demo — Scan banking sample and open HTML dashboard
set -e

echo "═══════════════════════════════════════════════════"
echo "  SmolerSAST — Demo: Banking Security Scan"
echo "═══════════════════════════════════════════════════"
echo ""

# Build if needed
if [ ! -f "src/SmolerSAST.Cli/bin/Release/net9.0/SmolerSAST.Cli.dll" ]; then
    echo "[1/3] Building..."
    dotnet build -c Release -q
else
    echo "[1/3] Build up to date"
fi

# Run scan
echo "[2/3] Scanning fixtures/banking-sample..."
echo ""
dotnet run --project src/SmolerSAST.Cli -c Release --no-build -- \
    scan --path fixtures/banking-sample --output demo-output/report.sarif --format html

echo ""
echo "[3/3] Dashboard generated: demo-output/report.html"
echo ""
echo "═══════════════════════════════════════════════════"
echo "  Open demo-output/report.html in your browser"
echo "═══════════════════════════════════════════════════"

# Try to open in browser (cross-platform)
if command -v xdg-open &> /dev/null; then
    xdg-open demo-output/report.html
elif command -v open &> /dev/null; then
    open demo-output/report.html
elif command -v start &> /dev/null; then
    start demo-output/report.html
fi
