# SmolerSAST

[![NuGet](https://img.shields.io/nuget/v/SmolerSAST?label=CLI)](https://www.nuget.org/packages/SmolerSAST)
[![NuGet](https://img.shields.io/nuget/v/SmolerSAST.Core?label=Core)](https://www.nuget.org/packages/SmolerSAST.Core)

Plataforma modular de análise estática de segurança (SAST) para codebases .NET, voltada ao mercado financeiro brasileiro.

Diferencial: detecção baseada em **Roslyn symbol resolution** (não regex), com regras específicas para LGPD, Bacen 4.658 e CVM.

## Instalação

```bash
# Como dotnet tool global
dotnet tool install --global SmolerSAST

# Como library no seu projeto
dotnet add package SmolerSAST.Core
dotnet add package SmolerSAST.Rules.Base
dotnet add package SmolerSAST.Rules.BR
```

## Quick Start

```bash
# Escanear código C#
smolersast scan --path ./src --output report.sarif

# Gerar SARIF + relatório Markdown pt-BR
smolersast scan --path ./src --output report.sarif --format both

# Listar todas as 42 regras
smolersast rules

# Verificar integridade dos artefatos
smolersast verify --manifest manifest.json

# Versão e info
smolersast version
```

### Exemplo de output

```
SmolerSAST v0.3.0 — Scanning: ./src
Analysis complete: 13 finding(s) in 5509ms
  Rules executed: 42
  Syntax trees: 4
  SARIF report: report.sarif
  Markdown report: report.md
  [Critical] SMOL0009: Instanciação de BinaryFormatter detectada.
  [Critical] SMOL0033: Segredo hardcoded em 'ApiKey'.
  [High]     SMOL1001: PII (cpf) detectado em log statement. LGPD Art. 46.
  ...
```

## Pacotes NuGet

| Pacote | Descrição |
|--------|-----------|
| [SmolerSAST](https://www.nuget.org/packages/SmolerSAST) | CLI tool (`smolersast scan`, `rules`, `verify`) |
| [SmolerSAST.Core](https://www.nuget.org/packages/SmolerSAST.Core) | Analysis engine (Roslyn pipeline, rule framework) |
| [SmolerSAST.Rules.Base](https://www.nuget.org/packages/SmolerSAST.Rules.Base) | 36 regras .NET genéricas |
| [SmolerSAST.Rules.BR](https://www.nuget.org/packages/SmolerSAST.Rules.BR) | 6 regras brasileiras (LGPD/Bacen/CVM) |
| [SmolerSAST.Reporting](https://www.nuget.org/packages/SmolerSAST.Reporting) | SARIF 2.1.0 + Markdown emitter |
| [SmolerSAST.Analyzer](https://www.nuget.org/packages/SmolerSAST.Analyzer) | Roslyn analyzer para IDE (VS/Rider) |

## 42 Regras de Segurança

### Injection (SMOL0001-0008)

| ID | Descrição | CWE | Severidade |
|----|-----------|-----|------------|
| SMOL0001 | Raw SQL concatenation em SqlCommand | 89 | Critical |
| SMOL0002 | FormattableString.Invariant em SQL | 89 | High |
| SMOL0003 | LDAP injection em DirectoryEntry | 90 | High |
| SMOL0004 | XPath injection em XmlDocument | 643 | High |
| SMOL0005 | Command injection via Process.Start | 78 | Critical |
| SMOL0006 | LINQ-to-SQL string composition | 89 | High |
| SMOL0007 | NoSQL injection em MongoDB.Driver | 943 | High |
| SMOL0008 | Dapper string parameter abuse | 89 | Critical |

### Deserialization (SMOL0009-0016)

| ID | Descrição | CWE | Severidade |
|----|-----------|-----|------------|
| SMOL0009 | BinaryFormatter usage | 502 | Critical |
| SMOL0010 | NetDataContractSerializer / SoapFormatter | 502 | Critical |
| SMOL0011 | LosFormatter / ObjectStateFormatter | 502 | Critical |
| SMOL0012 | ViewState MAC validation disabled | 642 | Critical |
| SMOL0013 | Newtonsoft.Json TypeNameHandling != None | 502 | Critical |
| SMOL0014 | Unsafe JsonConverter com tipo dinâmico | 502 | High |
| SMOL0015 | YamlDotNet untyped deserialization | 502 | High |
| SMOL0016 | DataContractSerializer com KnownTypes dinâmico | 502 | High |

### Cryptography (SMOL0017-0024)

| ID | Descrição | CWE | Severidade |
|----|-----------|-----|------------|
| SMOL0017 | MD5/SHA1 para hashing | 328 | High |
| SMOL0018 | ECB cipher mode | 327 | High |
| SMOL0019 | Chave/IV hardcoded | 321 | Critical |
| SMOL0020 | RijndaelManaged (deprecated) | 327 | Medium |
| SMOL0021 | RSA com PKCS#1 v1.5 padding | 780 | Medium |
| SMOL0022 | System.Random em contexto de segurança | 338 | High |
| SMOL0023 | Implementação crypto customizada | 327 | Medium |
| SMOL0024 | TLS 1.0/1.1 explícito | 327 | High |

### ASP.NET (SMOL0025-0032)

| ID | Descrição | CWE | Severidade |
|----|-----------|-----|------------|
| SMOL0025 | [AllowAnonymous] em verbo sensível | 862 | High |
| SMOL0026 | POST sem [ValidateAntiForgeryToken] | 352 | High |
| SMOL0027 | EnableViewStateMac = false | 642 | Critical |
| SMOL0028 | Debug/Trace habilitado | 215 | Medium |
| SMOL0029 | UseDeveloperExceptionPage sem env check | 209 | Medium |
| SMOL0030 | Cookie sem Secure/HttpOnly | 614 | Medium |
| SMOL0031 | AddAuthentication sem esquema | 287 | High |
| SMOL0032 | IDistributedCache sem cifragem | 312 | Medium |

### Configuration & Secrets (SMOL0033-0040)

| ID | Descrição | CWE | Severidade |
|----|-----------|-----|------------|
| SMOL0033 | Segredo hardcoded no código | 798 | Critical |
| SMOL0036 | HttpClient sem validação de certificado TLS | 295 | Critical |
| SMOL0038 | DI lifetime mismatch (Scoped em Singleton) | 664 | High |
| SMOL0040 | Invocação dinâmica via reflection | 470 | High |

### Brasil — LGPD (SMOL1001-1006)

| ID | Descrição | CWE | Ref. Legal |
|----|-----------|-----|------------|
| SMOL1001 | PII (CPF/CNPJ/RG) em log statements | 532 | LGPD Art. 46 |
| SMOL1002 | PII em query string de URL | 598 | LGPD Art. 46 |
| SMOL1006 | PII sem anotação [PersonalData] | 359 | LGPD Art. 5 |

### Brasil — Bacen / CVM (SMOL1007-1012)

| ID | Descrição | CWE | Ref. Legal |
|----|-----------|-----|------------|
| SMOL1007 | JWT sem validação audience/issuer/lifetime | 287 | Bacen Res. 4.658 / FAPI 1.0 |
| SMOL1009 | Chave de assinatura sem HSM/KMS | 321 | Bacen Res. 4.658 Art. 3 |
| SMOL1012 | Ação privilegiada sem controle dual | 271 | CVM Res. 35 |

## Arquitetura

```
                    ┌──────────────────────┐
                    │   SmolerSAST.Cli     │  ← scan, rules, verify, report, version
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  AnalysisPipeline     │  ← Orquestrador paralelo
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
   ┌──────────▼──────┐ ┌──────▼──────┐ ┌───────▼───────┐
   │ Compilation     │ │ Symbol      │ │ Rule          │
   │ Acquirer        │ │ Index       │ │ Registry (42) │
   └─────────────────┘ └─────────────┘ └───────┬───────┘
                                                │
                              ┌─────────────────┼─────────────────┐
                              │                 │                 │
                    ┌─────────▼───┐   ┌─────────▼───┐   ┌────────▼────┐
                    │ Rules.Base  │   │ Rules.BR    │   │ Analyzer   │
                    │ 36 regras   │   │ 6 regras    │   │ IDE NuGet  │
                    └─────────────┘   └─────────────┘   └─────────────┘
                                                │
                                     ┌──────────▼──────────┐
                                     │ SARIF + Markdown     │
                                     │ + Manifest SHA-256   │
                                     └─────────────────────┘
```

## Estrutura do Projeto

```
src/
├── SmolerSAST.Core/              # Motor de análise (Roslyn)
│   ├── Compilation/              #   Aquisição de compilação
│   ├── Indexing/                 #   Indexação de símbolos
│   ├── Pipeline/                 #   Orquestrador do pipeline
│   └── Rules/                    #   Framework (SmolerRule, Finding, RuleId)
├── SmolerSAST.Rules.Base/       # 36 regras .NET
│   ├── Injection/                #   SMOL0001-0008
│   ├── Deserialization/          #   SMOL0009-0016
│   ├── Cryptography/             #   SMOL0017-0024
│   ├── AspNet/                   #   SMOL0025-0032
│   └── Configuration/            #   SMOL0033-0040
├── SmolerSAST.Rules.BR/         # 6 regras brasileiras
│   ├── Lgpd/                     #   SMOL1001-1006
│   ├── Bacen/                    #   SMOL1007-1010
│   └── Cvm/                      #   SMOL1011-1012
├── SmolerSAST.Reporting/        # SARIF 2.1.0 + Markdown + Manifest
├── SmolerSAST.Cli/              # CLI (scan, rules, verify, report, version)
└── SmolerSAST.Analyzer/         # Roslyn Analyzer NuGet (IDE squigglies)

tests/
├── SmolerSAST.Core.Tests/           # 34 testes core
├── SmolerSAST.Rules.Base.Tests/     # 126 testes de regras
└── SmolerSAST.Integration.Tests/    # 7 testes (determinismo + performance)

fixtures/
├── cli-scan-sample/             # Exemplo simples (5 findings)
└── banking-sample/              # Cenário bancário (13 findings)

docs/
├── github-actions.md            # Guia CI/CD GitHub Actions
├── azure-devops.md              # Guia CI/CD Azure DevOps
├── jenkins.md                   # Guia CI/CD Jenkins
└── rule-reference.txt           # Referência completa de regras
```

## Integração CI/CD

Guias prontos para:
- [GitHub Actions](docs/github-actions.md) — com upload SARIF para GitHub Security
- [Azure DevOps](docs/azure-devops.md) — pipeline YAML com artifacts
- [Jenkins](docs/jenkins.md) — Jenkinsfile com Warnings Next Generation

## Criando uma Nova Regra

```csharp
public sealed class MyRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0042");
    public override ImmutableArray<int> CweIds { get; } = [79];
    public override string OwaspCategory => "A03:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["xss"];
    public override string DescriptionPtBr => "XSS detectado...";
    public override string DescriptionEnUs => "XSS detected...";
    public override string RemediationGuidancePtBr => "Sanitize output...";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(Analyze, SyntaxKind.InvocationExpression);
    }

    private static void Analyze(SyntaxNodeAnalysisContext ctx)
    {
        // Usar ctx.SemanticModel para symbol resolution — NUNCA regex
    }
}
```

## Desenvolvimento

```bash
dotnet restore                    # Restaurar dependências
dotnet build -c Release           # Compilar (zero warnings)
dotnet test -c Release            # 167 testes
smolersast scan --path fixtures/banking-sample  # Testar
```

## Princípios de Design

- **Symbol resolution, não regex** — toda detecção usa `SemanticModel` do Roslyn
- **Regras stateless** — nenhum estado mutável em instâncias de `SmolerRule`
- **False positive rate como métrica** — cada regra declara sua precisão
- **Determinismo** — mesmo input = mesmo output (verificado por testes)
- **Imutabilidade** — `Finding`, `FindingLocation`, `RuleId` são records imutáveis
- **Zero warnings** — build com `TreatWarningsAsErrors=true`
- **Bilíngue** — mensagens pt-BR (primário) e en-US (secundário)

## Licença

MIT
