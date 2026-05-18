# SmolerSAST — Setup & Execute

Comando para preparar, validar e executar o SmolerSAST.

## Instruções

Quando este comando for invocado, execute os passos abaixo na ordem. Pare em qualquer passo que falhar e reporte o erro.

### Argumentos

O comando aceita um argumento opcional que determina a ação:

- **Sem argumento** ou **`setup`**: Faz o setup completo (restore + build + test)
- **`scan <path>`**: Escaneia o caminho especificado e exibe resultados
- **`status`**: Mostra o status atual do projeto (build, testes, cobertura)
- **`add-rule <SMOL_ID>`**: Gera scaffold de uma nova regra com testes

---

### Ação: `setup`

1. Verificar que o .NET SDK está instalado (`dotnet --version`). Requisito: 9.0+.
2. Restaurar pacotes:
   ```bash
   dotnet restore SmolerSAST.sln
   ```
3. Compilar com warnings como erros:
   ```bash
   dotnet build SmolerSAST.sln -c Release -warnaserror
   ```
4. Rodar todos os testes:
   ```bash
   dotnet test SmolerSAST.sln -c Release
   ```
5. Se tudo passou, exibir resumo:
   - Versão do .NET SDK
   - Resultado do build (warnings/errors)
   - Resultado dos testes (passed/failed/total)
   - Mensagem: "SmolerSAST pronto para uso. Execute `/smolersast scan <path>` para escanear."

### Ação: `scan <path>`

1. Verificar que o projeto está compilado. Se não, rodar build primeiro.
2. Executar o scanner:
   ```bash
   dotnet run --project src/SmolerSAST.Cli -c Release -- scan --path <path> --output scan-results.sarif
   ```
3. Exibir os findings formatados:
   - Total de findings por severidade
   - Lista de findings com localização e mensagem pt-BR
   - Caminho do arquivo SARIF gerado
4. Se nenhum finding, informar "Nenhuma vulnerabilidade detectada."

### Ação: `status`

1. Verificar build:
   ```bash
   dotnet build SmolerSAST.sln -c Release -warnaserror
   ```
2. Rodar testes com cobertura:
   ```bash
   dotnet test SmolerSAST.sln -c Release --collect:"XPlat Code Coverage" --results-directory tmp-coverage/
   ```
3. Extrair e exibir:
   - Build status (clean/com erros)
   - Total de testes e resultado
   - Line coverage rate de cada projeto de teste
   - Regras implementadas (listar todas as classes que herdam SmolerRule)
4. Limpar diretório temporário de coverage.

### Ação: `add-rule <SMOL_ID>`

1. Validar que SMOL_ID segue o formato `SMOLnnnn`.
2. Perguntar ao usuário:
   - Nome descritivo da regra (ex: "Raw SQL Concatenation")
   - CWE ID(s)
   - Categoria OWASP
   - Severidade (Critical/High/Medium/Low)
   - Precisão (High/Medium/Low)
   - Diretório de grupo (ex: Injection, Deserialization, Cryptography, AspNet, Configuration)
3. Gerar arquivo da regra em `src/SmolerSAST.Rules.Base/<Grupo>/<NomeDaRegra>Rule.cs` com scaffold completo (herda SmolerRule, implementa todas as propriedades, RegisterActions vazio com TODO).
4. Gerar arquivo de teste em `tests/SmolerSAST.Rules.Base.Tests/<Grupo>/<NomeDaRegra>RuleTests.cs` com scaffold (3 métodos de teste positivo + 3 negativos, todos marcados como `[Fact]` com `// TODO: implement`).
5. Registrar a regra no CLI (`src/SmolerSAST.Cli/Program.cs`): adicionar `registry.Register(new <NomeDaRegra>Rule())`.
6. Verificar que o build continua passando.

---

## Referências

- Master prompt: `assets/smolersast-master-prompt.md`
- Relatório Phase 1: `phase1/phase-1-report.md`
- Regra exemplo: `src/SmolerSAST.Rules.Base/Deserialization/BinaryFormatterUsageRule.cs`
- Teste exemplo: `tests/SmolerSAST.Rules.Base.Tests/Deserialization/BinaryFormatterUsageRuleTests.cs`

## Regras de Código (lembrete)

- **NUNCA** usar regex para detecção — Roslyn symbol resolution obrigatório
- **NUNCA** usar `dynamic`
- Regras **DEVEM** ser stateless (sealed class, sem campos mutáveis)
- Mensagens sempre bilíngues: pt-BR primário, en-US secundário
- Cada regra nova precisa ≥ 3 testes positivos e ≥ 3 negativos
- Build deve passar com zero warnings (`-warnaserror`)
