# Integração SmolerSAST + DefectDojo

## Visão Geral

O DefectDojo aceita upload de SARIF via API REST. O SmolerSAST pode alimentar o DefectDojo
automaticamente em pipelines CI/CD para gestão centralizada de vulnerabilidades.

## Upload Manual via API

```bash
# 1. Gerar SARIF
smolersast scan --path ./src --output results.sarif --format sarif

# 2. Upload para DefectDojo
curl -X POST "https://defectdojo.banco.com/api/v2/import-scan/" \
  -H "Authorization: Token ${DEFECTDOJO_TOKEN}" \
  -F "scan_type=SARIF" \
  -F "file=@results.sarif" \
  -F "product_name=MeuProduto" \
  -F "engagement_name=CI-Scan" \
  -F "auto_create_context=true" \
  -F "verified=true" \
  -F "active=true"
```

## Pipeline GitHub Actions

```yaml
name: Security Scan + DefectDojo
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '9.0'

      - name: Install SmolerSAST
        run: dotnet tool install --global SmolerSAST

      - name: Run SmolerSAST
        run: smolersast scan --path ./src --output results.sarif --format sarif

      - name: Upload to DefectDojo
        run: |
          curl -X POST "${{ secrets.DEFECTDOJO_URL }}/api/v2/import-scan/" \
            -H "Authorization: Token ${{ secrets.DEFECTDOJO_TOKEN }}" \
            -F "scan_type=SARIF" \
            -F "file=@results.sarif" \
            -F "product_name=${{ github.repository }}" \
            -F "engagement_name=CI-${{ github.sha }}" \
            -F "auto_create_context=true" \
            -F "verified=true"
```

## Mapeamento de Campos

| SmolerSAST SARIF | DefectDojo |
|-------------------|-----------|
| `ruleId` | Finding Title |
| `level` (error/warning/note) | Severity |
| `message.text` | Description |
| `locations[].physicalLocation` | File Path + Line |
| `properties.confidence` | Confidence |
| `properties.tags` | Tags |

## Reimport para Tracking de Tendências

Para acompanhar evolução ao longo do tempo, use `reimport-scan`:

```bash
curl -X POST "https://defectdojo.banco.com/api/v2/reimport-scan/" \
  -H "Authorization: Token ${DEFECTDOJO_TOKEN}" \
  -F "scan_type=SARIF" \
  -F "file=@results.sarif" \
  -F "test=123" \
  -F "auto_create_context=true"
```

O DefectDojo automaticamente marca findings anteriores como "mitigated" se não aparecerem no novo scan.
