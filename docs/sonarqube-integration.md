# Integração SmolerSAST + SonarQube

## Visão Geral

O SonarQube pode importar findings do SmolerSAST como **external issues** via formato SARIF.
Isso permite visualizar vulnerabilidades brasileiras (LGPD, Bacen, PCI-DSS, CVM) no dashboard SonarQube existente.

## Configuração

### 1. Gerar SARIF durante o scan

```bash
smolersast scan --path ./src --output smolersast-results.sarif --format sarif
```

### 2. Configurar `sonar-project.properties`

```properties
sonar.projectKey=meu-projeto
sonar.sources=src
sonar.language=cs

# Importar SARIF do SmolerSAST como external issues
sonar.sarifReportPaths=smolersast-results.sarif
```

### 3. Pipeline CI (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]

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
        run: smolersast scan --path ./src --output smolersast-results.sarif --format sarif

      - name: SonarQube Scan
        uses: SonarSource/sonarqube-scan-action@v2
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
```

### 4. Pipeline CI (Azure DevOps)

```yaml
steps:
  - task: DotNetCoreCLI@2
    inputs:
      command: 'custom'
      custom: 'tool'
      arguments: 'install --global SmolerSAST'

  - script: smolersast scan --path ./src --output $(Build.ArtifactStagingDirectory)/smolersast-results.sarif
    displayName: 'SmolerSAST Scan'

  - task: SonarQubeAnalyze@5
    inputs:
      extraProperties: |
        sonar.sarifReportPaths=$(Build.ArtifactStagingDirectory)/smolersast-results.sarif
```

## Visualização no SonarQube

Após a importação, os findings aparecem em:

- **Security Hotspots** → External issues
- **Issues** → Filter por "External Rule Engine: SmolerSAST"
- Tags: `lgpd`, `bacen`, `pci-dss`, `cvm`, `injection`, etc.

## Mapeamento de Severidade

| SmolerSAST | SonarQube |
|------------|-----------|
| Critical | BLOCKER |
| High | CRITICAL |
| Medium | MAJOR |
| Low | MINOR |
| Info | INFO |

## Scan Incremental no CI

Para acelerar scans em PRs, use o modo incremental:

```bash
# Analisar apenas arquivos alterados vs. main
smolersast scan --path ./src --output results.sarif --incremental origin/main
```
