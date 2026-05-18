# SmolerSAST

Plataforma modular de análise estática de segurança (SAST) para codebases .NET, voltada ao mercado financeiro brasileiro.

Diferencial: detecção baseada em **Roslyn symbol resolution** (não regex), com regras específicas para LGPD, Bacen 4.658, CVM, e camada semântica com Claude para análise de exploitability.

## Status

| Phase | Descrição | Status |
|-------|-----------|--------|
| 1 | Skeleton & Core Engine | Concluída |
| 2 | Base Rule Pack (40 regras) | Pendente |
| 3 | Brazil Rule Pack & Semantic Layer | Pendente |
| 4 | Reporting, CLI, Analyzer NuGet | Pendente |
| 5 | Integration, Determinism, Docs | Pendente |

## Requisitos

- **.NET SDK 9.0+** (testado com 10.0)
- **Windows, Linux ou macOS**

Verificar instalação:

```bash
dotnet --version
```

## Quick Start

```bash
# 1. Restaurar dependências
dotnet restore

# 2. Compilar
dotnet build -c Release

# 3. Rodar testes
dotnet test -c Release

# 4. Escanear código C#
dotnet run --project src/SmolerSAST.Cli -- scan --path <caminho-para-arquivos-cs> --output resultado.sarif
```

### Exemplo com as fixtures incluídas

```bash
dotnet run --project src/SmolerSAST.Cli -- scan \
  --path fixtures/cli-scan-sample \
  --output scan-results.sarif
```

Output esperado:

```
SmolerSAST v0.1.0 — Scanning: fixtures/cli-scan-sample
Analysis complete: 5 finding(s) in ~8s
  [Critical] SMOL0009: Instanciação de BinaryFormatter detectada.
  [Critical] SMOL0009: Chamada a BinaryFormatter.Deserialize() detectada.
  ...
```

## Arquitetura

```
                    ┌──────────────────────┐
                    │   SmolerSAST.Cli     │  ← Ponto de entrada
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  AnalysisPipeline     │  ← Orquestrador
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
   ┌──────────▼──────┐ ┌──────▼──────┐ ┌───────▼───────┐
   │ Compilation     │ │ Symbol      │ │ Rule          │
   │ Acquirer        │ │ Index       │ │ Registry      │
   └─────────────────┘ └─────────────┘ └───────┬───────┘
                                                │
                                     ┌──────────▼──────────┐
                                     │ SmolerRule instances │
                                     │ (SMOL0009, ...)      │
                                     └──────────┬──────────┘
                                                │
                                     ┌──────────▼──────────┐
                                     │ Findings → SARIF     │
                                     └─────────────────────┘
```

### Pipeline de Análise

1. **Compilation Acquisition** — Carrega código C# em uma `CSharpCompilation` Roslyn
2. **Symbol Indexing** — Indexa tipos, métodos, propriedades e campos
3. **Rule Registration** — Cada `SmolerRule` registra callbacks (SyntaxNode, Symbol)
4. **Parallel Execution** — Regras executam em paralelo por syntax tree (stateless)
5. **Finding Collection** — Findings coletados via `ConcurrentBag` thread-safe
6. **SARIF Emission** — Output determinístico em SARIF 2.1.0

## Estrutura do Projeto

```
src/
├── SmolerSAST.Core/              # Motor de análise
│   ├── Compilation/              #   Aquisição de compilação (Roslyn)
│   ├── Indexing/                 #   Indexação de símbolos
│   ├── Pipeline/                 #   Orquestrador do pipeline
│   └── Rules/                    #   Framework de regras (base classes, Finding, etc.)
├── SmolerSAST.Rules.Base/       # Pack de regras .NET genéricas
│   └── Deserialization/          #   SMOL0009: BinaryFormatter
├── SmolerSAST.Rules.BR/         # Pack de regras brasileiras (LGPD/Bacen/CVM) [skeleton]
├── SmolerSAST.Semantic/         # Camada semântica com Claude [skeleton]
├── SmolerSAST.Reporting/        # Emissor SARIF 2.1.0
├── SmolerSAST.Cli/              # CLI (scan, version)
└── SmolerSAST.Analyzer/         # Roslyn Analyzer NuGet [skeleton]

tests/
├── SmolerSAST.Core.Tests/       # Testes do core (34 testes)
└── SmolerSAST.Rules.Base.Tests/ # Testes de regras (9 testes)

fixtures/
├── cli-scan-sample/             # Fixtures para scan via CLI
└── vulnerable-samples/          # Fixtures com código vulnerável (raw source)

phase1/                          # Artefatos de evidência Phase 1
```

## Regras Implementadas (Phase 1)

| ID | Nome | CWE | OWASP | Severidade | Precisão |
|----|------|-----|-------|------------|----------|
| SMOL0009 | BinaryFormatter Usage | CWE-502 | A08:2021 | Critical | High |

### Regras Planejadas (Phase 2-3)

**Injection** (SMOL0001-0008): SQL, LDAP, XPath, Command, LINQ, NoSQL, Dapper
**Deserialization** (SMOL0010-0016): NetDataContractSerializer, LosFormatter, ViewState, JSON TypeNameHandling, YamlDotNet
**Cryptography** (SMOL0017-0024): MD5/SHA1, ECB, hardcoded keys, RijndaelManaged, weak TLS
**ASP.NET** (SMOL0025-0032): AllowAnonymous, CSRF, Cookie config, DI lifetime
**Config/Secrets** (SMOL0033-0040): Hardcoded secrets, insecure HttpClient, DI mismatch
**LGPD** (SMOL1001-1006): PII em logs, URL, DB sem encryption, consent
**Bacen/CVM** (SMOL1007-1012): JWT validation, mTLS, HSM, audit trail

## Criando uma Nova Regra

1. Criar classe selada derivando de `SmolerRule` em `src/SmolerSAST.Rules.Base/`
2. Implementar propriedades de metadata (Id, CweIds, Severity, etc.)
3. Implementar `RegisterActions()` com callbacks de análise via Roslyn
4. Adicionar testes com ≥ 3 positivos e ≥ 3 negativos

```csharp
public sealed class MyRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0042");
    public override ImmutableArray<int> CweIds { get; } = [79]; // XSS
    public override string OwaspCategory => "A03:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    // ... demais propriedades ...

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeNode, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeNode(SyntaxNodeAnalysisContext ctx)
    {
        // Usar ctx.SemanticModel para symbol resolution
        // NUNCA usar regex para detecção
        // Reportar via ctx.ReportFinding(new Finding(...))
    }
}
```

## Output SARIF

O CLI emite relatórios SARIF 2.1.0, compatíveis com:
- GitHub Advanced Security
- Azure DevOps
- Microsoft Defender
- Qualquer ferramenta que consuma SARIF

```bash
dotnet run --project src/SmolerSAST.Cli -- scan --path ./my-app --output report.sarif
```

## Testes

```bash
# Todos os testes
dotnet test -c Release

# Com cobertura
dotnet test -c Release --collect:"XPlat Code Coverage"

# Testes de um projeto específico
dotnet test tests/SmolerSAST.Rules.Base.Tests -c Release
```

Requisito mínimo: **75% line coverage**.

## Princípios de Design

- **Symbol resolution, não regex**: Toda detecção usa `SemanticModel` do Roslyn
- **Regras stateless**: Nenhum estado mutável em instâncias de `SmolerRule`
- **False positive rate como métrica**: Cada regra declara sua precisão
- **Determinismo**: Mesmo input → mesmo output (sort keys, timestamps fixos)
- **Imutabilidade**: `Finding`, `FindingLocation`, `RuleId` são records imutáveis
- **Zero warnings**: Build com `TreatWarningsAsErrors=true`

## Licença

Proprietário — uso interno.
