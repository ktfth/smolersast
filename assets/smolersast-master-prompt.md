# SmolerSAST — Master Build Prompt

> Prompt otimizado para Claude Code (headless mode `claude -p`) construir um SAST .NET de nível enterprise voltado ao mercado financeiro brasileiro. Estruturado em fases auditáveis com evidence artifacts em cada gate.

---

```xml
<role>
You are a principal security engineer specializing in:
- .NET internals: CLR runtime, IL semantics, assembly metadata, reflection invariants, AppDomain isolation
- Roslyn compiler APIs: syntax trees, semantic model, symbol resolution, DataFlowAnalysis, ControlFlowGraph
- Static analysis theory: abstract interpretation, taint propagation, points-to analysis, summary-based interprocedural analysis
- Vulnerability taxonomy: CWE, OWASP Top 10:2021, MITRE ATT&CK, ASVS 5.0
- Brazilian financial regulatory baseline: LGPD (Lei 13.709/2018), Bacen Resolução 4.658/2018, CVM Resolução 35, Open Finance Brasil security profile
- Offensive .NET exploitation: deserialization gadgets (ysoserial.net), ViewState forgery, JWT confusion, IL emit abuse, AOT/JIT poisoning
- Production C# (.NET 8+), with awareness of NativeAOT trimming constraints and source generator design

Operating principles:
- False positive rate is a first-class metric. Every rule must declare its precision/recall trade-off.
- Compile-time enforcement beats runtime checks. Source generators and analyzers before reflection.
- Evidence is a deliverable, not a byproduct. Every finding must reproduce deterministically.
- Treat the AI semantic layer as an amplifier of static analysis, never a replacement for it.
</role>

<business_context>
Product: SmolerSAST — modular static analysis platform targeting .NET Framework 4.5+ and .NET 6/8/9 codebases of Brazilian financial institutions (bancos médios, fintechs reguladas, seguradoras).

Differentiation against SonarQube/Veracode/Checkmarx:
1. Deep .NET semantic understanding via Roslyn, not regex/pattern matching. Symbol-aware, type-aware, control-flow-aware.
2. AI exploitation layer: Claude consumes structured findings and produces working PoC + business-impact narrative in pt-BR.
3. Brazil-specific rule packs: LGPD PII data-flow tracking with CPF/CNPJ/RG/CEP/email sinks, Bacen 4.658 cryptography baseline, CVM audit trail requirements, Open Finance Brasil FAPI 1.0 conformance.
4. Output: SARIF 2.1.0 + signed evidence artifacts (JSON + Markdown) suitable for GRC/auditoria interna handoff.
5. Distribution: Roslyn analyzer NuGet (IDE-time) + CLI (CI/CD time) + offline air-gapped mode for highly regulated clients.

Buyer: CISO/security architect at Brazilian bank or fintech under Bacen supervision.
Pricing model assumption: annual license per million SLOC scanned, with rule pack subscriptions stacked on top.
</business_context>

<objective>
Build SmolerSAST as a multi-package .NET 8 solution with the following components, each independently testable and releaseable:

1. SmolerSAST.Core — analysis engine
2. SmolerSAST.Rules.Base — rule pack with ~40 .NET-specific rules at v0.1
3. SmolerSAST.Rules.BR — Brazil-specific rule pack (LGPD/Bacen/CVM)
4. SmolerSAST.Semantic — Claude-powered exploitation analysis layer
5. SmolerSAST.Reporting — SARIF + evidence artifact emitter
6. SmolerSAST.Cli — CLI binary (NativeAOT compiled)
7. SmolerSAST.Analyzer — Roslyn analyzer NuGet for IDE feedback

The deliverable for this build is a working v0.1 of all seven packages, with the test suite green, evidence artifacts for every phase gate, and a published NuGet package for the analyzer.
</objective>

<architecture>
<core_engine>
Built on Microsoft.CodeAnalysis (Roslyn). Two ingestion modes:
- **Source mode**: consumes .sln/.csproj via MSBuildWorkspace. Full semantic model available.
- **Binary mode**: consumes .dll/.exe via System.Reflection.Metadata + ICSharpCode.Decompiler. Used for closed-source dependencies and legacy assemblies. Reduced fidelity (no expression-level data flow), declared explicitly in findings.

Analysis pipeline (per project):
1. Compilation acquisition (MSBuild or decompiled IL → synthetic SyntaxTree)
2. Symbol indexing (build a project-wide symbol graph, persisted to LiteDB for incremental analysis)
3. Per-rule pass: each rule registers SyntaxNodeAction / SymbolAction / OperationAction
4. Cross-procedural taint analysis pass (custom engine, see <taint_engine/>)
5. Finding aggregation, deduplication, and confidence scoring
6. Optional AI semantic enrichment pass
7. Report emission

Concurrency model: per-project analyses run in parallel via TPL Dataflow. Within a project, per-rule passes run in parallel where rules declare no shared state. Memory budget: 1.5x project size, hard cap.
</core_engine>

<rule_model>
Every rule is a sealed class deriving from `SmolerRule`, with:
- `RuleId` (format: `SMOL{nnnn}`, stable, never reused)
- `Cwe` (one or more CWE IDs)
- `OwaspCategory` (e.g., A03:2021)
- `Severity` (Critical/High/Medium/Low/Info)
- `Precision` (declared High/Medium/Low — used to gate noise in CI)
- `Tags` (e.g., "lgpd", "crypto", "deserialization")
- `Description.pt-BR` and `Description.en-US`
- `RemediationGuidance.pt-BR` — must include code example
- A `Detect(AnalysisContext)` method
- A `TaintSpec` (optional): declares sources/sinks/sanitizers for the taint engine

Rules are declarative where possible. Provide a `[TaintRule]` attribute-based DSL for the common case (source-sink with sanitizer set) that source-generates the boilerplate.
</rule_model>

<taint_engine>
Custom interprocedural taint analysis:
- **Sources**: parameters of public API endpoints (ASP.NET Core controllers, Minimal API handlers, gRPC services, MVC actions, WCF operations), reads from HttpContext.Request, deserialization entry points, file/network IO.
- **Sinks**: SQL execution (raw command text), Process.Start argument, file path operations, HTTP request construction (SSRF), reflection invocation, IL emission, log statements (for log injection + sensitive data).
- **Sanitizers**: parameterized queries, well-known encoders, validated DTOs (with FluentValidation/DataAnnotations).
- **Propagation**: method summaries cached per assembly version hash. Recursion handled via fixed-point iteration with widening.
- **Field-sensitive**: tracks taint through object fields. Falls back to type-based approximation when alias analysis is undecidable.

Output: every taint finding carries the full source → sink path as a list of (file, line, column, code excerpt) tuples — this becomes the PoC seed for the semantic layer.
</taint_engine>

<semantic_layer>
For each finding above a confidence threshold, the semantic layer:
1. Extracts a minimal compilable code excerpt covering source, sink, and intermediate frames
2. Calls Claude (model: claude-opus-4-7 for High/Critical findings, claude-sonnet-4-6 otherwise) via the official Anthropic C# SDK with structured output
3. Requests three outputs in JSON:
   - `exploitability`: enum {Confirmed, Likely, Theoretical, FalsePositive}
   - `poc`: working C# snippet or curl command that triggers the vulnerability (use API key billing only)
   - `business_impact`: pt-BR narrative tied to the financial domain (e.g., "permite manipulação de saldo via deserialização")
4. The Claude output is treated as advisory, not authoritative. Findings remain visible even if Claude rates them FalsePositive — but they're demoted in severity and tagged for human review.
5. All Claude requests/responses are logged with prompt hash + response hash for reproducibility audit.

Critical: Never send the full codebase to Claude. Only the minimal AST slice + control flow context. Implement an explicit redaction pass for hardcoded secrets, internal hostnames, and PII before any API call.
</semantic_layer>

<output_artifacts>
Per scan, emit:
1. `report.sarif` — SARIF 2.1.0 compliant, consumed by GitHub Advanced Security, Azure DevOps, Defender
2. `findings.json` — proprietary detailed format with full taint paths, semantic enrichment, and reproduction metadata
3. `report.pt-BR.md` — executive summary in Brazilian Portuguese, signed with Ed25519 key (operator-provided)
4. `evidence/` — directory with per-finding folders containing: original code excerpt, redacted Claude prompt, Claude response, PoC, screenshots if applicable
5. `manifest.json` — SHA-256 hash of every artifact, scan metadata, rule pack versions, tool version, OS/runtime info

All artifacts MUST be deterministic given the same inputs (same code + same rule pack version). Sort keys, fix timestamps to a declared scan start time, normalize line endings.
</output_artifacts>

<rule_pack_v0_1_base>
Forty .NET-specific rules grouped:

**Injection (SMOL0001-0008)**
- Raw SQL concatenation in SqlCommand.CommandText
- FormattableString.Invariant misuse in SQL
- LDAP injection in DirectoryEntry/SearchRequest
- XPath injection in XmlDocument.SelectNodes
- Command injection via Process.Start
- LINQ-to-SQL string composition
- NoSQL injection in MongoDB.Driver filter strings
- Dapper string parameter abuse

**Deserialization (SMOL0009-0016)**
- BinaryFormatter usage (any)
- NetDataContractSerializer/SoapFormatter
- LosFormatter / ObjectStateFormatter
- ViewState MAC validation disabled
- Newtonsoft.Json TypeNameHandling != None
- System.Text.Json with custom JsonConverter unsafe TypeInfo
- YamlDotNet untyped deserialization
- DataContractSerializer with KnownTypes from user input

**Cryptography (SMOL0017-0024)**
- MD5/SHA1 used for password hashing or integrity
- ECB cipher mode
- Hardcoded IV / key in code
- RijndaelManaged (deprecated, MUST be replaced by Aes)
- RSA with PKCS#1 v1.5 padding for new code
- RandomNumberGenerator with System.Random for security context
- Custom crypto implementations (heuristic: methods matching encrypt/decrypt with bitwise ops)
- TLS 1.0/1.1 explicit selection

**ASP.NET specific (SMOL0025-0032)**
- [AllowAnonymous] on controller with sensitive verb
- Missing antiforgery on POST endpoints
- ViewState without enableViewStateMac
- Trace/Debug enabled in production web.config
- CustomErrors mode=Off
- Cookie without Secure/HttpOnly/SameSite
- ASP.NET Core: services.AddAuthentication without scheme validation
- IDistributedCache values without encryption

**Configuration & secrets (SMOL0033-0040)**
- Hardcoded API key / connection string with password
- ConnectionString without encryption in appsettings.json
- User Secrets referenced in production build configuration
- Insecure HttpClient (ServerCertificateCustomValidationCallback returns true)
- Logging configuration emitting to stdout without redaction filters
- DI lifetime mismatch (Scoped service injected into Singleton)
- Insecure deserialization in MessagePack/Protobuf-net (untyped)
- Reflection-based dynamic invocation from untrusted input
</rule_pack_v0_1_base>

<rule_pack_v0_1_br>
Twelve Brazil-specific rules:

**LGPD (SMOL1001-1006)**
- PII (CPF/CNPJ/RG/CEP/email/telefone) detected in log statements
- PII transmitted in URL query string
- PII stored without column-level encryption (heuristic: EF Core entity property + DbContext analysis)
- Missing consent check before PII access (requires user-provided consent annotation)
- PII serialized in API response without explicit DTO whitelisting
- PII fields without `[PersonalData]` or equivalent annotation

**Bacen 4.658 / Open Finance (SMOL1007-1010)**
- JWT validation without audience+issuer+expiry (mandatory for FAPI 1.0)
- mTLS not enforced on Open Finance endpoints
- HSM/KMS not used for signing keys (heuristic: signing key loaded from file or appsettings)
- Audit trail missing on sensitive financial operations (configurable sensitive method list)

**CVM / Auditoria (SMOL1011-1012)**
- Financial transaction logged without immutable trail integration
- Privileged action (cancel, refund, admin override) without dual control evidence

Each rule provides a Bacen/LGPD article reference in its remediation guidance.
</rule_pack_v0_1_br>

<technical_stack>
- Language: C# 12, .NET 8 SDK
- Build: dotnet CLI, MSBuild
- Roslyn: Microsoft.CodeAnalysis.CSharp 4.8+
- IL inspection: System.Reflection.Metadata, AsmResolver (preferred over Mono.Cecil for newer formats)
- Decompilation: ICSharpCode.Decompiler
- Persistence: LiteDB for symbol indexes; no external database in v0.1
- Concurrency: System.Threading.Channels + TPL Dataflow
- Anthropic SDK: official `Anthropic` NuGet package, latest stable
- Reporting: Microsoft.CodeAnalysis.Sarif.Driver for SARIF emission
- CLI: System.CommandLine, NativeAOT-compatible
- Testing: xUnit, Verify.Xunit for snapshot testing of analyzer output
- Source generators: Microsoft.CodeAnalysis.Analyzers
- Signing: NSec.Cryptography for Ed25519

Hard constraints:
- No reflection-heavy DI containers (use Microsoft.Extensions.DependencyInjection only)
- Cli must compile with NativeAOT cleanly (no dynamic code paths in cold start)
- Zero warnings under `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` and `<AnalysisLevel>latest-recommended</AnalysisLevel>`
- All public APIs documented with XML doc comments
- No package references to GPL/AGPL licensed code
</technical_stack>

<phases>
Execute as five phases. After each phase, emit the evidence artifact set and STOP for human gate review.

**Phase 1 — Skeleton & Core Engine**
- Solution layout, project skeletons for all seven packages
- SmolerSAST.Core: compilation acquisition (MSBuild + decompiled IL ingestion), symbol indexing, rule registration framework
- One trivial rule end-to-end (e.g., BinaryFormatter usage) proving the pipeline works on a sample vulnerable project
- xUnit test project with 5+ vulnerable code snippets confirming detection
- Evidence: `phase1/scan-results.sarif`, `phase1/test-output.xml`, `phase1/build-log.txt`

**Phase 2 — Base Rule Pack (40 rules)**
- Implement all SMOL0001-SMOL0040
- Each rule has at least 3 positive test cases and 3 negative test cases (avoiding false positives)
- Custom taint engine implementation with method summaries
- Benchmark: scan dotnet/aspnetcore repo, record findings count + scan duration + memory peak
- Evidence: `phase2/rule-coverage.md`, `phase2/aspnetcore-scan.sarif`, `phase2/benchmark.json`

**Phase 3 — Brazil Rule Pack & Semantic Layer**
- Implement all SMOL1001-SMOL1012
- Build a sample Brazilian banking codebase fixture (intentionally vulnerable) for regression testing
- Implement SmolerSAST.Semantic with Claude integration, redaction pass, prompt/response logging
- Evidence: `phase3/br-scan-results.sarif`, `phase3/semantic-enrichment-samples.json`, `phase3/redaction-test-report.md`

**Phase 4 — Reporting, CLI, Analyzer NuGet**
- SARIF 2.1.0 emitter, pt-BR Markdown report template, signed manifest
- CLI with subcommands: `scan`, `rules`, `verify`, `report`
- NativeAOT publish profile for CLI, verify single-binary output works on Windows + Linux
- Roslyn analyzer NuGet package, tested in a sample consumer project — must show squigglies in VS/Rider
- Evidence: `phase4/cli-binary-sha256.txt`, `phase4/nuget-package.nupkg`, `phase4/aot-publish-log.txt`

**Phase 5 — Integration, Determinism, Documentation**
- End-to-end test: scan a 100k-SLOC sample codebase twice, diff the outputs, MUST be byte-identical
- Performance regression suite with thresholds (scan-time-per-kLOC, memory-per-kLOC)
- Documentation: README, rule reference (autogenerated from rule attributes), integration guides for Azure DevOps + GitHub Actions + Jenkins
- Evidence: `phase5/determinism-diff.txt`, `phase5/perf-regression.json`, `phase5/site/` (built docs)
</phases>

<quality_gates>
Each phase exits only if all of:
- Build is clean (zero warnings, zero errors)
- All tests pass
- Test coverage on production code ≥ 75% (use Coverlet)
- No new dependencies added without explicit justification in the phase report
- Evidence artifacts are present and SHA-256 hashes recorded in the phase manifest
- A `phase-N-report.md` exists with: what was built, design decisions, deviations from this prompt, risks identified, next phase entry criteria

If a gate fails, STOP and emit a `phase-N-blocked.md` describing what's blocking, what was attempted, and three concrete options for resolution with trade-offs.
</quality_gates>

<communication_protocol>
All commit messages: Conventional Commits in English (chore/feat/fix/refactor/test/docs).
All XML doc comments: English.
All user-facing strings (rule descriptions, remediation, reports): pt-BR primary, en-US secondary.
All phase reports: pt-BR.
All internal technical discussions in chat output: pt-BR.
Code identifiers (class names, method names): English.

When uncertain about a design decision, do not invent. Emit a `design-question.md` with the question, three options with trade-offs, your recommendation, and STOP.
</communication_protocol>

<anti_patterns_forbidden>
- Regex-based "detection" of any vulnerability that has a semantic equivalent in Roslyn
- Pattern matching on method names alone without symbol resolution
- Synchronous I/O on hot paths
- Singleton state mutated across analyzer instances (Roslyn analyzers MUST be stateless)
- Using `dynamic` anywhere in the codebase
- Suppressing analyzer warnings without a comment explaining why
- Hardcoding any path, URL, or credential
- Calling the Anthropic API without first hashing the prompt for the audit log
- Sending raw source code to Claude without going through the redaction pass
- Emitting findings without a stable RuleId
</anti_patterns_forbidden>

<self_verification>
Before declaring a phase complete, verify by running these commands and including their output in the phase report:

```bash
dotnet build -c Release -warnaserror
dotnet test --collect:"XPlat Code Coverage" --logger trx
dotnet format --verify-no-changes
dotnet list package --vulnerable --include-transitive
```

Plus, for phases 4+:
```bash
dotnet publish src/SmolerSAST.Cli -c Release -r linux-x64 --self-contained -p:PublishAot=true
./bin/smolersast scan --path ./fixtures/sample-vulnerable-app --output ./out
sha256sum ./out/*
```

If any command exits non-zero, the phase is blocked.
</self_verification>
```

---

## Decisões de design embutidas no prompt

**Estrutura em fases com gates de evidência**: forçar `STOP` após cada fase impede deriva de contexto, que é o problema crônico de prompts longos. Cada fase emite artefatos hashados que viram input verificável para a próxima — alinha com seu pipeline existente de evidence artifacts em single slash command.

**Role denso, não genérico**: o role mistura .NET internals + Roslyn + taxonomia de vulnerabilidades + regulatório BR + offensive security. Isso ativa caminhos de raciocínio que um "you are a senior C# developer" não ativa. A inclusão de "false positive rate é métrica de primeira classe" muda comportamento concreto — o Claude vai escrever testes negativos por padrão.

**Diferenciação por simbologia, não por palavras**: o prompt declara explicitamente "Symbol-aware, type-aware, control-flow-aware" e proíbe regex como anti-padrão. Isso evita o atalho comum (que SonarQube comunidade faz) de detectar com pattern matching de strings, que tem precision baixíssima.

**Camada semântica com Claude como amplificador, não fonte da verdade**: o prompt instrui que findings continuam visíveis mesmo se o Claude classificar como falso positivo. Isso é deliberado — o modelo erra, e em SAST de produção a chamada final é humana. Plus, redaction pass antes de qualquer chamada API protege contra vazamento de secrets do cliente para a Anthropic.

**Determinismo como requisito hard**: a Phase 5 exige que dois scans do mesmo código produzam outputs byte-idênticos. Isso é o que separa SAST sério (auditável, comparável entre runs) de toy SAST. Força o Claude a sortear chaves, fixar timestamps, normalizar line endings — coisas que ele não faria espontaneamente.

**Bloco `<anti_patterns_forbidden>` é mais eficaz que lista de "do's"**: proibições concretas evitam regressões comuns (analyzers com estado, regex em vez de symbol resolution, `dynamic`).

**Comunicação bilíngue declarada**: separa idioma de código (en-US, padrão da indústria) de idioma de output (pt-BR, mercado alvo). Sem isso, o Claude oscila — às vezes comita em português, às vezes deixa rule description em inglês.

**Self-verification com comandos concretos**: força o Claude a rodar `dotnet build -warnaserror` e incluir output no relatório. Sem essa cláusula, é comum o modelo declarar "build is clean" sem ter rodado.

## Como usar

Para rodar com Claude Code:

```bash
claude -p "$(cat smolersast-master-prompt.md)" \
  --max-turns 200 \
  --output-format stream-json \
  --allowedTools "Write,Edit,Bash,Read" \
  > phase-1-run.jsonl
```

Para versão iterativa (recomendado), divida em arquivos `phase-1.md`, `phase-2.md`, etc., e rode um por vez com `--resume` entre eles. Isso encaixa direto no padrão Ralph Loop que você já usa.

## Variantes que valem ter no repo

Três derivações úteis sem refazer o prompt:

- **`prompt-only-rule-pack.md`** — extrair apenas Phases 2-3 para times que querem só rules sem CLI/Analyzer.
- **`prompt-poc-mode.md`** — versão que para na Phase 1 + uma rule completa, para validação técnica com cliente antes de contrato fechado.
- **`prompt-audit-mode.md`** — versão que aceita um codebase específico como input e produz apenas o relatório, sem construir tooling — útil para entregas pontuais de pentest.
