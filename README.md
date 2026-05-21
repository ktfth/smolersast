# SmolerSAST

[![NuGet](https://img.shields.io/nuget/v/SmolerSAST?label=CLI)](https://www.nuget.org/packages/SmolerSAST)
[![NuGet](https://img.shields.io/nuget/v/SmolerSAST.Core?label=Core)](https://www.nuget.org/packages/SmolerSAST.Core)

Plataforma de análise estática de segurança (SAST) para .NET, construída sobre **Roslyn SemanticModel** com **taint analysis** e regras específicas para o mercado financeiro brasileiro.

## Por que existe

Ferramentas comerciais (Fortify, Checkmarx, SonarQube) usam regex ou AST pattern matching — não resolvem tipos. Uma classe chamada `BinaryFormatter` num namespace customizado é flagrada igual ao `System.Runtime.Serialization`. Além disso, nenhuma delas tem regras nativas para LGPD, Bacen 4.658, PCI-DSS em contexto brasileiro, ou Open Finance Brasil.

O SmolerSAST resolve isso com:
- **Symbol resolution real** via Roslyn `SemanticModel` — sabe o tipo, namespace, e hierarquia
- **Taint analysis intraprocedural** — rastreia dados de source (HttpRequest, DbReader) até sink (SqlCommand, Process.Start), com sanitizer modeling
- **22 regras regulatórias brasileiras** — LGPD, Bacen, PCI-DSS, CVM com referência legal exata
- **Policy-as-code** — quality gates, baseline, SLA por severidade, inline suppression

## Quick Start

```bash
# Instalar
dotnet tool install --global SmolerSAST

# Escanear
smolersast scan --path ./src --output report.sarif --format html

# Ver regras
smolersast rules

# Scan incremental (só arquivos alterados)
smolersast scan --path ./src --output report.sarif --incremental origin/main
```

## Demo: Banking Sample (31 findings)

```bash
smolersast scan --path fixtures/banking-sample --format html
```

Detecta em código bancário simulado:
- **Taint-aware SQL injection** — input de `[FromQuery]` flui até `ExecuteNonQuery` com path completo
- **PIX key em log** — Bacen Resolução 1/2020
- **CVV armazenado em entity** — PCI-DSS Req. 3.2
- **JWT sem validação** — Bacen Res. 4.658 / FAPI 1.0
- **Session timeout > 15min** — Bacen Res. 4.658
- **PAN sem mascaramento em log** — PCI-DSS Req. 3.4

Gera dashboard HTML interativo com Chart.js (severidade, top regras, filtros).

## 61 Regras de Segurança

### Base .NET (38 regras)

| Categoria | IDs | Exemplos |
|-----------|-----|----------|
| Injection | SMOL0001-0008 | SQL injection, command injection, LDAP, XPath, NoSQL |
| Injection (Taint-Aware) | SMOL0041-0042 | SQL/command injection com data flow analysis |
| Deserialization | SMOL0009-0016 | BinaryFormatter, Newtonsoft TypeNameHandling, YamlDotNet |
| Cryptography | SMOL0017-0024 | MD5/SHA1, ECB mode, hardcoded keys, weak TLS |
| ASP.NET | SMOL0025-0032 | CSRF, AllowAnonymous, insecure cookies |
| Configuration | SMOL0033-0040 | Hardcoded secrets, cert validation bypass, DI mismatch |

### Brasil — Regulatório (22 regras)

| Regulação | IDs | Exemplos |
|-----------|-----|----------|
| LGPD | SMOL1001-1006 | PII em log, exception, cache, cookie, URL, sem anotação |
| Bacen | SMOL1007-1016 | JWT, HSM, mTLS, audit tamper, PKCE, PIX key, session, idempotency |
| PCI-DSS | SMOL1017-1021 | PAN em log, CVV storage, weak crypto cards, TLS, MFA admin |
| CVM | SMOL1012-1024 | Dual control, audit trail, data integrity, digital signature |

## Taint Analysis Engine

Rastreia dados de fontes inseguras até sinks perigosos:

```
[FromQuery] string input  →  string sql = "..." + input  →  cmd.CommandText = sql  →  cmd.ExecuteNonQuery()
     SOURCE                    PROPAGATION                    ASSIGNMENT               SINK (flagged!)
```

- **Sources:** HttpRequest params, File.Read, DbReader, IConfiguration
- **Sinks:** SqlCommand.Execute*, Process.Start, Response.Write, Redirect
- **Sanitizers:** HtmlEncode, int.Parse, SqlParameter.AddWithValue, Validate
- **Confidence:** 0.95 (direct) → 0.75 (long paths)

Se o dado passa por sanitizer, o taint morre e o finding não é gerado.

## Policy-as-Code

```bash
# Inicializar política
smolersast policy --action init

# Criar baseline de findings aceitos
smolersast baseline --path ./src --action create --by "appsec@banco.com"

# Scan mostra apenas findings NOVOS vs baseline
smolersast scan --path ./src --output report.sarif
```

`.smolersast.json`:
```json
{
  "qualityGates": {
    "failOn": { "critical": 0, "high": 5, "medium": -1 },
    "blockMerge": true
  },
  "severitySla": {
    "criticalHours": 48,
    "highHours": 168
  }
}
```

## Integração Enterprise

| Plataforma | Tipo | Docs |
|------------|------|------|
| GitHub Actions | CI/CD + SARIF upload | [docs/github-actions.md](docs/github-actions.md) |
| Azure DevOps | Pipeline YAML | [docs/azure-devops.md](docs/azure-devops.md) |
| Jenkins | Warnings Next Gen | [docs/jenkins.md](docs/jenkins.md) |
| SonarQube | External issues via SARIF | [docs/sonarqube-integration.md](docs/sonarqube-integration.md) |
| DefectDojo | REST API upload | [docs/defectdojo-integration.md](docs/defectdojo-integration.md) |

## Arquitetura

```
                    ┌──────────────────────────────────────┐
                    │         SmolerSAST.Cli v0.4.0        │
                    │  scan, rules, verify, baseline,      │
                    │  policy, report, version             │
                    └──────────────────┬───────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
   ┌──────────▼──────┐     ┌──────────▼──────────┐  ┌──────────▼──────┐
   │  Compilation    │     │  Taint Engine       │  │  Policy Engine  │
   │  Acquirer       │     │  Source → Sink      │  │  Quality Gates  │
   │  (Roslyn)       │     │  + Sanitizer Model  │  │  + Baseline     │
   └─────────────────┘     └─────────────────────┘  └─────────────────┘
              │                        │
   ┌──────────▼──────────────────────────────────────────────────┐
   │                    Rule Registry (61)                         │
   ├─────────────────┬─────────────────┬─────────────────────────┤
   │ Rules.Base (38) │ Rules.BR (22)   │ Taint-Aware (2)         │
   │ Injection       │ LGPD            │ SQL Injection            │
   │ Deserialization │ Bacen           │ Command Injection        │
   │ Cryptography    │ PCI-DSS         │                         │
   │ ASP.NET         │ CVM             │                         │
   │ Configuration   │                 │                         │
   └─────────────────┴─────────────────┴─────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────┐
                    │           Reporting                   │
                    │  SARIF 2.1.0 │ Markdown │ HTML       │
                    │  + Manifest SHA-256                   │
                    └──────────────────────────────────────┘
```

## Princípios de Design

- **Symbol resolution, não regex** — toda detecção usa Roslyn `SemanticModel`
- **Taint-aware** — data flow tracking de source a sink com sanitizer modeling
- **Regras stateless** — sealed classes, nenhum campo mutável, thread-safe
- **Precision declarada** — cada regra declara High/Medium/Low precision (taxa de FP)
- **Determinismo** — mesmo input = mesmo output (testes de determinismo)
- **Imutabilidade** — Finding, FindingLocation, RuleId são records imutáveis
- **Zero warnings** — build com `TreatWarningsAsErrors=true`
- **Bilíngue** — mensagens pt-BR (primário) e en-US (secundário)
- **271 testes** — unitários, integração, determinismo

## Desenvolvimento

```bash
dotnet restore
dotnet build -c Release           # Zero warnings
dotnet test -c Release            # 271 testes
smolersast scan --path fixtures/banking-sample --format html
```

## Licença

MIT
