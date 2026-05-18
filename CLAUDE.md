# SmolerSAST — Instruções para Claude Code

## Sobre o Projeto

SmolerSAST é uma plataforma SAST (Static Application Security Testing) para .NET, construída sobre Roslyn. O master prompt completo está em `assets/smolersast-master-prompt.md`.

## Stack

- **Linguagem**: C# 13, .NET 9 (target net9.0)
- **Análise**: Microsoft.CodeAnalysis.CSharp (Roslyn) 4.12+
- **Testes**: xUnit, Verify.Xunit, Coverlet
- **CLI**: System.CommandLine
- **Build**: dotnet CLI, MSBuild, Central Package Management

## Comandos Essenciais

```bash
# Build (DEVE passar com zero warnings)
dotnet build -c Release -warnaserror

# Testes (DEVE ter 75%+ coverage)
dotnet test -c Release

# Scan de exemplo
dotnet run --project src/SmolerSAST.Cli -- scan --path fixtures/cli-scan-sample --output scan.sarif

# Cobertura
dotnet test -c Release --collect:"XPlat Code Coverage"
```

## Regras Invioláveis

1. **NUNCA usar regex para detecção de vulnerabilidades** — usar Roslyn `SemanticModel`, `GetTypeInfo()`, `GetSymbolInfo()`
2. **NUNCA usar `dynamic`** em qualquer lugar do codebase
3. **Regras DEVEM ser stateless** — nenhum campo mutável em subclasses de `SmolerRule`
4. **Zero warnings** — build com `TreatWarningsAsErrors=true`
5. **Imutabilidade** — usar records, ImmutableArray, never mutate
6. **Symbol-aware** — pattern matching por nome de método sem symbol resolution é proibido
7. **Mensagens bilíngues** — `MessagePtBr` (primário) e `MessageEnUs` (secundário) em todo Finding
8. **Code identifiers em inglês** — nomes de classes, métodos, variáveis em English
9. **Relatórios/docs em pt-BR** — user-facing output em português brasileiro
10. **Cada regra nova DEVE ter ≥ 3 testes positivos e ≥ 3 testes negativos**

## Estrutura de Regras

Toda regra é uma sealed class que herda `SmolerRule`:

- `Id`: formato `SMOL{nnnn}`, nunca reutilizado
- `CweIds`: um ou mais CWE IDs
- `OwaspCategory`: e.g., "A08:2021"
- `Severity`: Critical/High/Medium/Low/Info
- `Precision`: High/Medium/Low (taxa de FP declarada)
- `Tags`: e.g., "deserialization", "lgpd"
- `RegisterActions()`: registra callbacks de análise no `AnalysisContext`

## Fase Atual

Phase 1 concluída. Phase 2 pendente: 39 regras restantes + taint engine.
Consultar `phase1/phase-1-report.md` e `assets/smolersast-master-prompt.md` para contexto completo.

## Padrões de Teste

```csharp
// Criar compilação in-memory para testar regras:
var acquirer = new InMemoryCompilationAcquirer([sourceCode], InMemoryCompilationAcquirer.GetRuntimeReferences());
var registry = new DefaultRuleRegistry();
registry.Register(new MinhaRegra());
var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
var result = await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
Assert.True(result.Findings.Length > 0);
```

## Slash Command

Use `/smolersast` para setup, build, teste e execução da ferramenta.
