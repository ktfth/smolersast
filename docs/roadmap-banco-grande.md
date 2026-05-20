# SmolerSAST — Roadmap: Peça Essencial no Ferramental de um Banco Grande

> Plano estratégico para tornar o SmolerSAST indispensável na esteira de segurança
> de uma instituição financeira de grande porte no Brasil.

## Diagnóstico do Estado Atual

| Dimensão | Status | Nota |
|----------|--------|------|
| Regras implementadas | 42 (36 base + 6 BR) | Bom início, mas bancos precisam de 80+ |
| Regulatório BR | LGPD (3), Bacen (2), CVM (1) | Muito raso — banco exige cobertura completa |
| Taint analysis | Não implementado | Bloqueador para adoção enterprise |
| Integração com ferramentas | SARIF + 3 CI/CDs | Falta SonarQube, Fortify, DefectDojo |
| Gestão de baseline/exceções | Inexistente | Obrigatório em banco com 500+ repos |
| Relatórios executivos | Markdown simples | Banco precisa de dashboards e tendências |
| Política como código | Inexistente | CISO precisa de quality gates configuráveis |
| Supply chain / SCA | Inexistente | Regulação Bacen exige |
| Performance em monorepo | Não testado | Bancos têm soluções com 2M+ LOC |
| Suporte a .NET Framework | Parcial (Roslyn) | Bancos ainda têm muito legado 4.x |

---

## Visão: O Que um Banco Grande Precisa de um SAST

Um banco brasileiro tier-1 (Itaú, Bradesco, BTG, Safra, etc.) tem estas necessidades:

1. **Compliance regulatório verificável** — Bacen 4.658, LGPD, CVM, PCI-DSS, Open Finance
2. **Integração na esteira DevSecOps** — não pode ser ferramenta isolada
3. **Gestão de findings em escala** — baseline, exceções, SLA por severidade
4. **Relatórios para auditoria** — evidência de scan, trilha de auditoria, tendências
5. **Baixo false-positive rate** — time de AppSec não pode triar 500 FPs por sprint
6. **Taint analysis** — detectar fluxos de dados inseguros end-to-end
7. **Policy-as-code** — CISO define regras que quebram build; squads não podem ignorar
8. **Suporte ao legado** — .NET Framework 4.5-4.8 ainda é core banking
9. **Supply chain** — CVEs em dependências NuGet
10. **Performance** — scan de solução com 200 projetos em < 5 minutos

---

## Fases Propostas

### Fase 6 — Taint Analysis Engine (Fundação para Enterprise)

**Por que primeiro:** Sem taint analysis, o SmolerSAST detecta apenas padrões locais. Bancos precisam rastrear dados sensíveis (PII, credenciais) fluindo de fontes (input do usuário, banco de dados) para sinks (SQL, logs, HTTP response). Isso é o diferencial entre "linter de segurança" e "SAST de verdade".

**Entregas:**

| Item | Descrição | Prioridade |
|------|-----------|------------|
| 6.1 | **Taint source registry** — marcar fontes: `HttpRequest`, `IFormFile`, `DbDataReader`, `IConfiguration`, parâmetros de controller | P0 |
| 6.2 | **Taint sink registry** — marcar sinks: `SqlCommand`, `Process.Start`, `HttpResponse.Write`, `ILogger.*`, `Redirect()` | P0 |
| 6.3 | **Sanitizer registry** — marcar sanitizadores: `HtmlEncoder`, `SqlParameter`, `AntiXss.*`, input validation | P0 |
| 6.4 | **Intraprocedural taint propagation** — rastrear taint dentro de um método via data flow do Roslyn | P0 |
| 6.5 | **Interprocedural taint (method summaries)** — propagar taint entre métodos usando summaries (parâmetro X → retorno tainted) | P1 |
| 6.6 | **Field-sensitive tracking** — rastrear taint em campos de objetos (`request.Body`, `dto.CpfCliente`) | P1 |
| 6.7 | **Taint-aware rules** — converter SMOL0001 (SQL injection), SMOL0005 (command injection) para usar taint engine em vez de pattern matching local | P0 |
| 6.8 | **Confidence scoring refinado** — findings com taint path completo têm confidence 0.95+; sem path = 0.6 | P1 |

**Quality Gate:** SMOL0001 (SQL injection) detecta injection em código onde o input vem de um controller action parameter, passa por 2+ métodos, e chega em `SqlCommand` — com o path completo no finding.

**Testes:** ≥ 30 testes de taint propagation (15 positivos, 15 negativos com sanitizers).

---

### Fase 7 — Cobertura Regulatória Completa para Setor Financeiro

**Por que agora:** Um banco não adota ferramenta que cobre 6 de 30 requisitos regulatórios. Precisa de cobertura suficiente para substituir checklists manuais.

**Novas regras brasileiras (SMOL1003-1030):**

#### LGPD Expandida (SMOL1003-1010)

| ID | Descrição | CWE | Ref. Legal |
|----|-----------|-----|------------|
| SMOL1003 | PII em exception messages (stack trace leak) | 209 | LGPD Art. 46 |
| SMOL1004 | PII em cache sem TTL ou sem cifragem | 312 | LGPD Art. 46 |
| SMOL1005 | Dados sensíveis em cookie sem cifragem | 315 | LGPD Art. 46 |
| SMOL1008 | Consentimento não verificado antes de processar PII | 862 | LGPD Art. 7 |
| SMOL1010 | Ausência de anonimização/pseudonimização em relatórios | 359 | LGPD Art. 12 |

#### Bacen Expandida (SMOL1011-1020)

| ID | Descrição | CWE | Ref. Legal |
|----|-----------|-----|------------|
| SMOL1011 | API sem rate limiting (Open Finance) | 770 | Bacen IN 99 |
| SMOL1013 | Mutual TLS não enforced em API financeira | 295 | Bacen Res. 4.658 Art. 3 |
| SMOL1014 | Audit log sem tamper protection (HMAC/hash chain) | 117 | Bacen Res. 4.658 Art. 12 |
| SMOL1015 | Token OAuth sem PKCE em fluxo público | 287 | Open Finance Brasil FAPI |
| SMOL1016 | Chave PIX exposta em log/response body | 532 | Bacen Res. 1/2020 |
| SMOL1017 | Dados de transação sem cifragem em trânsito | 319 | Bacen Res. 4.658 |
| SMOL1018 | Session fixation em autenticação bancária | 384 | Bacen Res. 4.658 |
| SMOL1019 | Timeout de sessão > 15min em canal autenticado | 613 | Bacen Res. 4.658 |
| SMOL1020 | API sem idempotency key em operação financeira | 352 | Open Finance Brasil |

#### PCI-DSS (SMOL1021-1025)

| ID | Descrição | CWE | Ref. Legal |
|----|-----------|-----|------------|
| SMOL1021 | PAN (número de cartão) em log/variável sem mascaramento | 532 | PCI-DSS Req. 3.4 |
| SMOL1022 | CVV armazenado em qualquer forma persistente | 312 | PCI-DSS Req. 3.2 |
| SMOL1023 | Criptografia de dados de cartão com algo < AES-256 | 327 | PCI-DSS Req. 3.5 |
| SMOL1024 | Transmissão de dados de cartão sem TLS 1.2+ | 319 | PCI-DSS Req. 4.1 |
| SMOL1025 | Ausência de MFA em acesso administrativo | 308 | PCI-DSS Req. 8.3 |

#### CVM Expandida (SMOL1026-1030)

| ID | Descrição | CWE | Ref. Legal |
|----|-----------|-----|------------|
| SMOL1026 | Operação de mercado sem trilha de auditoria | 778 | CVM Res. 35 |
| SMOL1027 | Dados de cotação/ordem sem validação de integridade | 345 | CVM Res. 35 |
| SMOL1028 | Acesso a dados de insider sem controle de need-to-know | 284 | CVM Res. 44 |
| SMOL1029 | Relatório regulatório gerado sem assinatura digital | 345 | CVM IN 505 |
| SMOL1030 | Timeout de sessão ausente em sistema de negociação | 613 | CVM Res. 35 |

**Quality Gate:** ≥ 25 novas regras BR implementadas, cada uma com ≥ 3 testes positivos e ≥ 3 negativos.

---

### Fase 8 — Policy-as-Code e Gestão de Baseline

**Por que:** O CISO do banco precisa definir políticas centralizadas. Squads não podem simplesmente ignorar findings.

**Entregas:**

| Item | Descrição | Prioridade |
|------|-----------|------------|
| 8.1 | **Arquivo de política `.smolersast.yml`** — define quality gates por severidade, regras obrigatórias, regras desabilitadas, thresholds | P0 |
| 8.2 | **Baseline file (`.smolersast-baseline.json`)** — findings conhecidos que não quebram build (com data de aceite, responsável, justificativa) | P0 |
| 8.3 | **Comando `baseline`** — `smolersast baseline --create` gera baseline do scan atual; `--diff` mostra apenas findings novos | P0 |
| 8.4 | **Exit codes configuráveis** — 0 = ok, 1 = novos findings acima do threshold, 2 = erro de scan | P0 |
| 8.5 | **Supressão inline** — `// SMOLERSAST-IGNORE SMOL0001 reason="parametrizado via stored proc" approved-by="fulano@banco.com"` | P1 |
| 8.6 | **SLA por severidade** — Critical = 48h, High = 7d, Medium = 30d, Low = 90d (configurável) | P1 |
| 8.7 | **Herança de política** — política global do banco + override por squad/repo | P1 |
| 8.8 | **Relatório de compliance de política** — % de repos em conformidade, repos fora de SLA | P2 |

**Formato do `.smolersast.yml`:**

```yaml
version: 1
quality-gates:
  fail-on:
    critical: 0          # Zero tolerance
    high: 5              # Até 5 aceitos com baseline
  block-merge: true
  
rules:
  required:              # Regras que DEVEM estar ativas
    - SMOL0001           # SQL injection
    - SMOL0009           # BinaryFormatter
    - SMOL1001           # PII em log
    - SMOL1007           # JWT validation
    - SMOL1021           # PAN em log
  disabled: []           # Nenhuma regra desabilitada por default
  
severity-sla:
  critical: 48h
  high: 7d
  medium: 30d
  low: 90d

baseline:
  max-age: 90d           # Baseline entries expiram após 90 dias
  require-approval: true # Necessita approved-by
```

**Quality Gate:** CLI respeita `.smolersast.yml`, baseline funciona com `--diff`, exit codes corretos.

---

### Fase 9 — Integrações Enterprise

**Por que:** Banco grande não troca ferramentas — integra. SmolerSAST precisa coexistir com SonarQube, Fortify, e alimentar dashboards existentes.

**Entregas:**

| Item | Descrição | Prioridade |
|------|-----------|------------|
| 9.1 | **Integração SonarQube** — plugin que importa SARIF do SmolerSAST como external issues | P0 |
| 9.2 | **Integração DefectDojo** — upload automático de findings via API REST | P0 |
| 9.3 | **Integração Azure DevOps Boards** — criar work items a partir de findings críticos | P1 |
| 9.4 | **Webhook genérico** — POST JSON de findings para qualquer endpoint (Slack, Teams, PagerDuty) | P1 |
| 9.5 | **GitHub Advanced Security** — upload SARIF nativo (já funciona, melhorar metadata) | P1 |
| 9.6 | **Relatório HTML interativo** — dashboard single-page com filtros, gráficos, drill-down | P0 |
| 9.7 | **Relatório PDF para auditoria** — cabeçalho da instituição, sumário executivo, assinatura digital | P1 |
| 9.8 | **API REST local** — `smolersast serve` expõe API para integração com portais internos | P2 |
| 9.9 | **Integração Jira** — criar issues a partir de findings com template configurável | P1 |

**Quality Gate:** SmolerSAST alimenta SonarQube e DefectDojo em pipeline real. Relatório HTML funciona offline.

---

### Fase 10 — Performance e Escala Enterprise

**Por que:** Banco tier-1 tem soluções .NET com 200+ projetos e 2M+ linhas. Scan precisa caber em pipeline de CI.

**Entregas:**

| Item | Descrição | Prioridade |
|------|-----------|------------|
| 10.1 | **Análise incremental** — só analisar arquivos alterados (via git diff) | P0 |
| 10.2 | **Cache de compilação** — reutilizar `Compilation` entre scans quando source não muda | P0 |
| 10.3 | **Paralelismo por projeto** — analisar projetos de uma solution em paralelo | P0 |
| 10.4 | **Benchmark suite** — medir tempo/memória em solutions de 10, 50, 100, 200 projetos | P0 |
| 10.5 | **Memory-bounded analysis** — limitar uso de memória com streaming de syntax trees | P1 |
| 10.6 | **NativeAOT build** — CLI compilado AOT para startup instantâneo (< 100ms) | P1 |
| 10.7 | **Distributed scan** — dividir projetos de uma solution entre N workers | P2 |
| 10.8 | **Métricas Prometheus/OpenTelemetry** — tempo de scan, regras executadas, findings por regra | P2 |

**Quality Gate:** Solution com 100 projetos (gerada sinteticamente) escaneia em < 3 minutos no CI.

---

### Fase 11 — Supply Chain Security (SCA)

**Por que:** Bacen Res. 4.658 exige controle de componentes third-party. Log4Shell mostrou que SCA não é opcional.

**Entregas:**

| Item | Descrição | Prioridade |
|------|-----------|------------|
| 11.1 | **NuGet vulnerability scan** — consultar NuGet Advisory DB para CVEs em dependências | P0 |
| 11.2 | **License compliance** — detectar licenças incompatíveis (GPL em projeto proprietário) | P1 |
| 11.3 | **SBOM generation** — gerar Software Bill of Materials em CycloneDX/SPDX | P0 |
| 11.4 | **Transitive dependency analysis** — identificar CVEs em dependências indiretas | P0 |
| 11.5 | **Allowlist/denylist de pacotes** — política corporativa de pacotes aprovados | P1 |
| 11.6 | **Outdated package report** — pacotes com major version atrasado | P2 |
| 11.7 | **Integração com GitHub Dependabot/Renovate** — enriquecer PRs de update com contexto de risco | P2 |

**Quality Gate:** SBOM gerado em CycloneDX, CVEs conhecidas detectadas em fixture com pacotes vulneráveis.

---

### Fase 12 — Relatórios Executivos e Dashboards

**Por que:** CISO, CTO e auditoria interna/externa precisam de visibilidade sem ler SARIF.

**Entregas:**

| Item | Descrição | Prioridade |
|------|-----------|------------|
| 12.1 | **Dashboard HTML standalone** — SPA com charts.js, exportável como PDF | P0 |
| 12.2 | **Trend analysis** — comparar scans ao longo do tempo (requer histórico SARIF) | P0 |
| 12.3 | **Relatório de conformidade regulatória** — checklist Bacen/LGPD/PCI com status por requisito | P0 |
| 12.4 | **Heat map de risco por repositório** — score de risco agregado por repo/squad | P1 |
| 12.5 | **Executive summary em PDF** — 1 página com métricas chave, assinatura digital | P1 |
| 12.6 | **Relatório de auditoria** — trilha completa: quando escaneou, quem aprovou baseline, SLA compliance | P1 |
| 12.7 | **API de métricas** — endpoint JSON para alimentar dashboards Grafana/Power BI | P2 |

**Quality Gate:** Dashboard HTML renderiza com dados de 3+ scans históricos, mostrando tendência.

---

### Fase 13 — Analyzer IDE Expandido

**Por que:** Developers precisam ver findings no IDE antes do commit. Reduz custo de correção em 10x.

**Entregas:**

| Item | Descrição | CWE | Prioridade |
|------|-----------|-----|------------|
| 13.1 | Expandir `SmolerSAST.Analyzer` para incluir **todas as 42+ regras** como Roslyn DiagnosticAnalyzers | — | P0 |
| 13.2 | **Code fixes automáticos** — quick fixes para findings de baixa complexidade (e.g., substituir MD5 por SHA256) | — | P1 |
| 13.3 | **Severity mapping** para IDE — Critical/High = Error, Medium = Warning, Low = Info | — | P0 |
| 13.4 | **Suporte VS Code** via OmniSharp / C# Dev Kit | — | P1 |
| 13.5 | **Suporte JetBrains Rider** via Roslyn analyzer pack | — | P1 |
| 13.6 | **EditorConfig integration** — `.editorconfig` pode desabilitar regras específicas | — | P2 |

**Quality Gate:** Developer instala NuGet, vê squigglies em código vulnerável, aplica code fix.

---

## Priorização por Impacto no Banco

```
                        IMPACTO NO BANCO
                    Alto ◄─────────────► Baixo
              ┌─────────────────────────────────┐
    Fácil     │ F8 Policy    │ F13 IDE          │
              │ F7 Regras BR │                  │
              ├──────────────┼──────────────────┤
    Esforço   │ F6 Taint     │ F12 Dashboards   │
              │ F9 Integração│ F11 SCA          │
              │ F10 Perf     │                  │
    Difícil   │              │                  │
              └─────────────────────────────────┘
```

## Ordem Recomendada de Execução

| Ordem | Fase | Justificativa |
|-------|------|---------------|
| 1º | **Fase 7** — Regras BR | Maior ROI imediato: banco vê cobertura regulatória e compra a ideia |
| 2º | **Fase 8** — Policy/Baseline | Sem isso, não passa da PoC — squads precisam de gestão de findings |
| 3º | **Fase 6** — Taint Analysis | Eleva de "linter" para "SAST real" — reduz FP, encontra bugs reais |
| 4º | **Fase 9** — Integrações | Conectar ao ecossistema existente (SonarQube, DefectDojo, Jira) |
| 5º | **Fase 10** — Performance | Necessário quando sair de PoC para rollout em 100+ repos |
| 6º | **Fase 12** — Dashboards | CISO precisa de visibilidade para justificar budget |
| 7º | **Fase 11** — SCA | Complementa SAST com análise de supply chain |
| 8º | **Fase 13** — IDE | Shift-left máximo — developer feedback loop |

---

## Métricas de Sucesso

| Métrica | Meta (12 meses) |
|---------|-----------------|
| Regras totais | ≥ 80 (42 → 80+) |
| Regras BR (regulatórias) | ≥ 30 (6 → 30+) |
| False positive rate | < 15% em codebase real |
| Tempo de scan (100 projetos) | < 3 minutos |
| Repos monitorados no banco | ≥ 50 |
| Integrações enterprise | SonarQube + DefectDojo + Jira |
| Cobertura regulatória | 100% Bacen 4.658, 100% PCI-DSS coding, 90% LGPD |
| Findings com taint path | ≥ 40% dos findings de injection |
| Developer adoption (IDE) | ≥ 30% dos devs .NET do banco |

---

## Riscos e Mitigações

| Risco | Impacto | Mitigação |
|-------|---------|-----------|
| Taint engine complexa demais | Atrasa todas as fases seguintes | Começar com intraprocedural apenas; interprocedural é P1 |
| Banco já usa Fortify/Checkmarx | "Já temos SAST" | Posicionar como complemento BR-specific, não substituição |
| False positives em regras novas | Time de AppSec perde confiança | Precisão declarada + baseline + confidence scoring |
| Performance em monorepo | Scan > 10min = não adotam | Análise incremental (git diff) resolve 80% |
| Regulação muda (Bacen, CVM) | Regras ficam obsoletas | Versionamento de regras + tag de ref. legal + review trimestral |
| Legado .NET Framework 4.x | Roslyn API diferente | Testar com `Microsoft.CodeAnalysis` versão que suporta ambos |

---

## Modelo de Adoção no Banco

```
Mês 1-2:    PoC com 3 repos críticos (PIX, Open Finance, core banking)
            └─ Foco: Fase 7 (regras BR) + Fase 8 (policy básica)

Mês 3-4:    Piloto com 1 squad (10 devs, 15 repos)
            └─ Foco: Fase 6 (taint) + Fase 9 (SonarQube integration)

Mês 5-8:    Rollout para área de tecnologia (50+ repos)
            └─ Foco: Fase 10 (performance) + Fase 12 (dashboards)

Mês 9-12:   Padrão corporativo (100+ repos, todas as squads .NET)
            └─ Foco: Fase 11 (SCA) + Fase 13 (IDE) + suporte contínuo
```

---

## Diferencial Competitivo vs. Ferramentas Existentes

| Critério | SmolerSAST | Fortify | Checkmarx | SonarQube |
|----------|-----------|---------|-----------|-----------|
| Regras Bacen/LGPD/CVM nativas | ✅ 30+ | ❌ | ❌ | ❌ |
| Mensagens em pt-BR | ✅ | ❌ | ❌ | ❌ Parcial |
| Remediação com contexto BR | ✅ | ❌ | ❌ | ❌ |
| Open source / auditável | ✅ MIT | ❌ | ❌ | ✅ Parcial |
| Custo por dev | Zero | $$$$ | $$$$ | $$ |
| Customização de regras | C# nativo | Proprietário | Proprietário | Java plugin |
| .NET focus (Roslyn-native) | ✅ | ✅ Genérico | ✅ Genérico | ✅ Genérico |
| PII detection (CPF/CNPJ/PIX) | ✅ Nativo | ❌ Custom | ❌ Custom | ❌ |
| SARIF 2.1.0 output | ✅ | ✅ | ✅ | ✅ Via plugin |
| Integração Open Finance BR | ✅ FAPI rules | ❌ | ❌ | ❌ |

**Posicionamento:** SmolerSAST não substitui Fortify/Checkmarx — ele **complementa** com o que eles não têm: regras regulatórias brasileiras nativas, mensagens em português, e custo zero. O banco roda SmolerSAST **junto** com a ferramenta comercial, usando policy-as-code para definir quais regras são obrigatórias de cada uma.

---

*Documento gerado em 2026-05-20. Revisão trimestral recomendada.*
