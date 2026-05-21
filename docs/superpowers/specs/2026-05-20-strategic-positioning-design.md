# Design: Posicionamento Estratégico — Profundidade sob Demanda

## Contexto

O SmolerSAST é um artefato técnico que prova capacidade em AppSec .NET para mercado financeiro brasileiro. O objetivo não é vender o produto — é posicionar o autor como alguém que **entende a engine por dentro**, não apenas opera ferramentas.

**Cenário:** Conversa informal com profissionais de AppSec, DevSecOps, ou engenharia de bancos.

**Objeção principal:** "Mas já existe Fortify/Checkmarx/SonarQube."

**Narrativa core:** "Eu não construí pra substituir. Construí pra entender como funciona por dentro — por que geram falso positivo, como taint analysis decide o que é vulnerável, e o que elas não cobrem no regulatório BR."

---

## Arquitetura da Conversa: 3 Camadas

### Camada 1 — A Frase (30 segundos)

Objetivo: Gerar uma pergunta de volta. Nunca explicar demais.

| Audiência | Frase |
|-----------|-------|
| AppSec / CISO | "Eu construí um SAST engine com Roslyn porque queria entender por que Fortify gera 60% de falso positivo em código financeiro .NET." |
| Engenheiro / Dev | "Eu implementei taint analysis do zero — source, sink, sanitizer, propagação — porque queria saber de verdade como uma ferramenta SAST decide que algo é vulnerável." |
| Gestor / CTO | "Eu escrevi 60 regras de segurança para .NET com symbol resolution porque nenhuma ferramenta comercial entende o que é PII no contexto Bacen/LGPD." |

**Regra:** Se a pessoa não pergunta nada, não forçar. Se perguntar, ir para Camada 2.

---

### Camada 2 — A Explicação (3 minutos)

Estrutura: **Problema → Insight → Prova**

**Problema (30s):**
Ferramentas comerciais usam regex ou AST pattern matching. Regex dá falso positivo absurdo. AST não resolve tipos — uma classe chamada `BinaryFormatter` no seu namespace é flagrada igual ao `System.Runtime.Serialization`.

**Insight (60s):**
O SmolerSAST usa Roslyn SemanticModel — symbol resolution real, não pattern matching por nome. Construí taint analysis por cima: marco fontes (HttpRequest, DbReader, File.Read), sinks (SqlCommand.Execute, Process.Start), e sanitizers (HtmlEncode, int.Parse, SqlParameter.Add). Se o dado passa por sanitizer, taint morre. Se não — finding com 95% de confiança e path completo.

**Prova (60s):**
22 regras brasileiras que não existem em nenhuma ferramenta comercial: chave PIX em log (Bacen Res. 1/2020), CVV armazenado em entity (PCI-DSS Req. 3.2), JWT sem PKCE (Open Finance FAPI), session timeout > 15min (Bacen 4.658). Tudo com referência regulatória exata.

**Ajustes por audiência:**
- Engenheiro → mais detalhes no insight técnico, mencionar Roslyn data flow API
- AppSec → mais detalhes no problema de FP, mencionar taint path no SARIF output
- Gestor → mais detalhes na prova regulatória, mencionar compliance gap

---

### Camada 3 — A Demo (60 segundos)

Só usada se a pessoa pedir para ver.

**Comando:**
```bash
smolersast scan --path fixtures/banking-sample --format html
```

**Narração durante execução:**
"São 61 regras em paralelo sobre Roslyn syntax tree com SemanticModel resolvido. Não é grep — é visitor pattern com type information."

**Resultado (31 findings), escolher UM:**

| Se quer mostrar... | Aponta para... | Diz... |
|---------------------|----------------|--------|
| Taint analysis | SMOL0041 (SQL injection) | "Input veio de `[FromQuery]`, passou por concatenação, chegou em `ExecuteNonQuery`. 2 steps, confidence 0.90. O `GetBalance` não foi flagrado porque usa `AddWithValue` — sanitizer." |
| Regulatório BR | SMOL1014 (PIX key) | "Chave PIX logada. Referência: Bacen Resolução 1/2020. Nenhuma ferramenta comercial detecta isso." |
| Design interno | Qualquer rule.cs | "60 linhas, sealed class, stateless. Registra callback em `InvocationExpression`. Sem regex, sem dynamic, sem mágica." |

**Remate:**
"Gera SARIF 2.1.0 que importa no SonarQube ou DefectDojo. Policy file define quality gates — zero critical passa no build, o resto vai pra baseline com SLA por severidade."

---

## Artefatos Demo-Ready

| Artefato | Path | Status |
|----------|------|--------|
| Banking sample (31 findings) | `fixtures/banking-sample/` | ✅ Pronto |
| HTML Dashboard | `fixtures/banking-sample/demo-report.html` | ✅ Pronto |
| Taint finding (SQL injection com path) | TransferController.cs → SMOL0041 | ✅ Funciona |
| Regulatório BR (PIX, LGPD, Bacen, PCI, CVM) | ComplianceViolations.cs | ✅ 10+ findings |
| Rule limpa para mostrar | Qualquer rule em `src/SmolerSAST.Rules.BR/` | ✅ 60 linhas, legível |
| GetBalance safe (não flagrado) | TransferController.cs:GetBalance | ✅ Sanitizer funciona |

---

## Pontos de Vulnerabilidade na Narrativa (e como defender)

| Se perguntarem... | Resposta |
|-------------------|----------|
| "Mas funciona em código real de produção?" | "Funciona em qualquer código .NET que o Roslyn compila — .NET 6-9, qualquer solution size. A análise é paralela por syntax tree. Em CI, uso scan incremental via git diff para analisar só o que mudou." |
| "Qual a taxa de falso positivo?" | "As regras taint-aware têm precision High — cada finding mostra o path completo source→sink. As regras heurísticas (tipo SMOL1016, idempotency) são precision Low e ficam em severity menor pra não poluir." |
| "Não é mais fácil configurar o Fortify?" | "Sim, se o banco já tem Fortify. Mas Fortify não tem regra pra chave PIX em log, CVV em entity, ou JWT sem PKCE pro Open Finance. E o learning de como funciona por dentro — symbol resolution, taint propagation, sanitizer modeling — é o que me permite tunar qualquer ferramenta, não só essa." |
| "Quantas horas você gastou nisso?" | "O valor não está nas horas — está na profundidade. Pra implementar taint analysis, tive que entender Roslyn SemanticModel, data flow graphs, e como cada método propagam ou neutraliza taint. Isso é o tipo de conhecimento que se aplica tuning Fortify, escrevendo custom rules pra Checkmarx, ou desenhando a esteira inteira." |
| "Isso é hobby ou projeto sério?" | "É um exercício deliberado de engenharia de segurança. 271 testes, zero warnings, 5 categorias regulatórias. Mas o ponto não é a ferramenta — é demonstrar que eu penso sobre esses problemas em profundidade." |

---

## O Que Esse Posicionamento Comunica (Sem Dizer)

1. **Você não é usuário de ferramenta — é construtor de ferramenta.** Quem constrói SAST entende segurança em nível que quem apenas roda scan não alcança.

2. **Você conhece regulatório BR de verdade.** Não são buzzwords — são referências exatas (Art. 46, Res. 4.658, Req. 3.4) implementadas em código funcionando.

3. **Você pensa em sistemas, não em features.** Policy-as-code, baseline, SLA por severidade, integração SonarQube/DefectDojo — isso é pensamento de quem desenha esteira DevSecOps, não quem só escreve código.

4. **Você entende o problema do false positive.** Isso é o que mais dói em AppSec enterprise. Mostrar que você construiu confidence scoring e taint path tracking para reduzir noise é falar a língua de quem sofre com isso diariamente.

---

## Ações Pós-Conversa (Follow-Up)

Se a conversa gerar interesse genuíno:

- **"Quer ver o repo?"** → GitHub público, README em português, tudo documentado
- **"Quer rodar no seu código?"** → `dotnet tool install --global SmolerSAST && smolersast scan --path .`
- **"Tem artigo sobre isso?"** → Oportunidade para escrever post técnico aprofundando um aspecto
- **"Conhece alguém que faz X?"** → Networking é mais valioso que venda direta

---

## Métricas de Sucesso do Posicionamento

| Sinal | Significado |
|-------|-------------|
| Pessoa pede o link do repo | Interesse técnico genuíno |
| Pessoa te apresenta para alguém | Credibilidade estabelecida |
| Pessoa volta falando do assunto | Você virou referência mental pra aquele tema |
| Convite pra palestra/conversa técnica | Autoridade reconhecida |
| Proposta de trabalho/consultoria | Conversão máxima |
