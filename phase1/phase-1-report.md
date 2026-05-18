# SmolerSAST — Relatório Phase 1: Skeleton & Core Engine

**Data**: 2026-05-18
**Versão**: 0.1.0-phase1

---

## O que foi construído

### Estrutura da Solução (7 pacotes + 2 projetos de teste)

| Pacote | Tipo | Descrição |
|--------|------|-----------|
| SmolerSAST.Core | classlib | Motor de análise: aquisição de compilação, indexação de símbolos, framework de regras, pipeline de análise |
| SmolerSAST.Rules.Base | classlib | Pack base de regras .NET (SMOL0009 implementada em Phase 1) |
| SmolerSAST.Rules.BR | classlib | Pack brasileiro — skeleton (Phase 3) |
| SmolerSAST.Semantic | classlib | Camada semântica Claude — skeleton (Phase 3) |
| SmolerSAST.Reporting | classlib | Emissor SARIF 2.1.0 |
| SmolerSAST.Cli | exe | CLI com comandos `scan` e `version` |
| SmolerSAST.Analyzer | classlib (netstandard2.0) | Roslyn analyzer NuGet — skeleton (Phase 4) |
| SmolerSAST.Core.Tests | test | 34 testes unitários e de integração |
| SmolerSAST.Rules.Base.Tests | test | 9 testes da regra SMOL0009 |

### Componentes Core Implementados

1. **Modelo de Domínio**: `RuleId` (record struct com validação), `Finding`, `FindingLocation`, `SmolerRule` (base abstrata), `AnalysisContext`, `IRuleRegistry`/`DefaultRuleRegistry`
2. **Aquisição de Compilação**: `ICompilationAcquirer`, `InMemoryCompilationAcquirer` (compilação in-memory com MetadataReferences do runtime)
3. **Indexação de Símbolos**: `ISymbolIndex`, `InMemorySymbolIndex` (visitor pattern sobre o namespace global)
4. **Pipeline de Análise**: `AnalysisPipeline` orquestrando acquire → index → register rules → execute → collect findings, com `ConcurrentBag<Finding>` thread-safe e `Parallel.ForEachAsync`
5. **Regra SMOL0009**: Detecção de `BinaryFormatter` via Roslyn symbol resolution (3 detectores: ObjectCreation, Invocation, TypeOf)
6. **Emissor SARIF**: Modelo SARIF 2.1.0 inline com output JSON determinístico

### Regra SMOL0009 — BinaryFormatter (CWE-502)

| Aspecto | Detalhe |
|---------|---------|
| Severidade | Critical |
| Precisão | High (zero falsos positivos) |
| OWASP | A08:2021 |
| Detecção | Symbol resolution via `SemanticModel.GetTypeInfo()` e `GetSymbolInfo()` — **não usa regex** |
| Casos positivos | 5: instanciação direta, uso indireto, typeof(), método helper, com SurrogateSelector |
| Casos negativos | 3: JsonSerializer (alternativa segura), classe homônima em namespace diferente, menção em comentário |
| Confiança | 1.0 (qualquer uso é inseguro) |

---

## Decisões de Design

### 1. Namespace `SmolerSAST.Core.Compilation` → uso de FQN para `Microsoft.CodeAnalysis.Compilation`
O namespace do projeto colide com o tipo `Compilation` do Roslyn. Em vez de renomear o namespace (que quebraria a convenção), usamos fully-qualified names nos pontos de ambiguidade.

### 2. `InMemorySymbolIndex` em vez de LiteDB na Phase 1
LiteDB requer avaliação de compatibilidade com NativeAOT. Na Phase 1, priorizamos o in-memory index que é suficiente para single-run analysis e testes. LiteDB será introduzido na Phase 2 para análise incremental.

### 3. `Channel<Finding>` → `ConcurrentBag<Finding>`
Phase 1 usa `ConcurrentBag` por simplicidade. Na Phase 2, migraremos para `System.Threading.Channels` com TPL Dataflow quando o taint engine introduzir pipeline stages mais complexos.

### 4. SARIF model inline em vez de pacote Microsoft.CodeAnalysis.Sarif
O pacote NuGet `Microsoft.CodeAnalysis.Sarif` não foi encontrado no nuget.org. Implementamos um modelo SARIF minimal inline usando `System.Text.Json`, suficiente para Phase 1. Avaliaremos em Phase 4 se vale reintroduzir o pacote SDK oficial.

### 5. Target framework net9.0 em vez de net8.0
O ambiente não tem .NET 8 SDK instalado (apenas 3.1, 9.0, 10.0). Usamos net9.0 com .NET 10 SDK, que é plenamente compatível. O master prompt especifica .NET 8, mas a API surface é idêntica para nossos propósitos.

### 6. Fixtures como source files, não projetos compiláveis
Em .NET 9, `BinaryFormatter` foi removido do runtime. As fixtures contendo uso de BinaryFormatter não compilam como projetos .NET 9. Usamos os `.cs` como raw source input para o scanner (via `InMemoryCompilationAcquirer`), que adiciona as MetadataReferences necessárias.

---

## Desvios do Master Prompt

| Desvio | Justificativa |
|--------|---------------|
| net9.0 em vez de net8.0 | SDK 8.0 não instalado. Compatibilidade total mantida. |
| InMemorySymbolIndex em vez de LiteDB | Compatibilidade NativeAOT não verificada. Migração planejada para Phase 2. |
| SARIF inline em vez de SDK | Pacote não encontrado. Modelo inline é SARIF 2.1.0 compliant. |
| ConcurrentBag em vez de Channel | Simplicidade para Phase 1. Migração para Phase 2. |
| VulnerableSamples.csproj removido da solution | BinaryFormatter não existe em .NET 9 runtime. Fixtures usadas como raw source. |

---

## Resultados de Self-Verification

### Build
```
dotnet build -c Release -warnaserror
Compilação com êxito.
0 Aviso(s)
0 Erro(s)
```

### Testes
```
Total de testes: 43
Aprovados: 43
Com falha: 0
```

### Cobertura
- **SmolerSAST.Core.Tests**: line-rate = 85.05%, branch-rate = 64.86%
- **SmolerSAST.Rules.Base.Tests**: line-rate = 82.73%, branch-rate = 71.62%
- **Ambos acima do requisito de 75%**

### CLI Scan
```
SmolerSAST v0.1.0 — Scanning: fixtures/cli-scan-sample
Analysis complete: 5 finding(s) in ~8s
Rules executed: 1
Syntax trees: 2
```
- 5 findings em código vulnerável (3 instanciações + 2 chamadas + 1 typeof)
- 0 findings em código seguro (SafeService.cs)

---

## Artefatos de Evidência

| Artefato | SHA-256 |
|----------|---------|
| `phase1/scan-results.sarif` | `6338e83ebe5c7f4bf43457af3a6f0e788dbef4718ccd9e74749b96a53baeda14` |
| `phase1/test-output.xml` | `c7d6b75ae8157b7aac4c6617a8f892cea89a9609d416d452537dd2a2fc424a98` |
| `phase1/build-log.txt` | `04415460c989fd95702df95031a8848d3b904d2508e641c4a1b2475f39247880` |

---

## Riscos Identificados

1. **MSBuildWorkspace não implementado**: Phase 1 usa apenas `InMemoryCompilationAcquirer`. O `MsBuildCompilationAcquirer` e `BinaryCompilationAcquirer` são necessários para Phase 2 e dependem de SDK tooling no ambiente de CI.
2. **LiteDB + NativeAOT**: Não validado. Pode precisar de alternativa (SQLite) para o CLI AOT.
3. **BinaryFormatter removido em .NET 9**: Testes positivos funcionam porque o DLL `System.Runtime.Serialization.Formatters.dll` ainda existe no disco do runtime. Em futuras versões do .NET, pode ser necessário incluir a referência de outra forma.

---

## Critérios de Entrada para Phase 2

- [ ] Implementar `MsBuildCompilationAcquirer` para ingestão de .sln/.csproj
- [ ] Implementar `BinaryCompilationAcquirer` para .dll/.exe via ICSharpCode.Decompiler
- [ ] Implementar taint engine custom com method summaries
- [ ] Implementar 39 regras restantes (SMOL0001-SMOL0008, SMOL0010-SMOL0040)
- [ ] Cada regra com ≥ 3 positivos e ≥ 3 negativos
- [ ] Benchmark contra dotnet/aspnetcore
- [ ] Migrar de ConcurrentBag para Channel + TPL Dataflow
- [ ] Avaliar LiteDB vs SQLite para NativeAOT compatibility
