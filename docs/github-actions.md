# SmolerSAST — Integração com GitHub Actions

## Workflow básico

```yaml
name: SmolerSAST Security Scan
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '9.0.x'

      - name: Install SmolerSAST
        run: dotnet tool install --global SmolerSAST --version 0.2.0

      - name: Run security scan
        run: smolersast scan --path ./src --output results.sarif --format both

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Upload scan artifacts
        uses: actions/upload-artifact@v4
        with:
          name: smolersast-results
          path: |
            results.sarif
            results.md
            manifest.json
```

## Falhar o build em findings críticos

O CLI retorna exit code 1 quando há findings de severidade High ou Critical.
O step `Run security scan` falhará automaticamente nesse caso.

## Scan apenas em PRs

```yaml
on:
  pull_request:
    paths:
      - '**.cs'
      - '**.csproj'
```
