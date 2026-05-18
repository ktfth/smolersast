# SmolerSAST — Relatório de Análise de Segurança

**Data do scan**: 2026-05-18 22:55:59 UTC
**Alvo**: `fixtures/banking-sample`
**Versão**: SmolerSAST v0.2.0
**Modo**: Source
**Duração**: 5.5s
**Syntax trees analisadas**: 4
**Regras executadas**: 42

## Resumo

| Severidade | Quantidade |
|------------|------------|
| Critical | 13 |
| **Total** | **13** |

## Findings

### SMOL0009 — Instanciação de BinaryFormatter detectada

- **Severidade**: Critical
- **CWE**: CWE-502
- **OWASP**: A08:2021
- **Ocorrências**: 13

| Arquivo | Linha | Trecho |
|---------|-------|--------|
| `Source0.cs` | 17 | `new BinaryFormatter()` |
| `Source0.cs` | 18 | `formatter.Deserialize(ms)` |
| `Source0.cs` | 25 | `new BinaryFormatter()` |
| `Source0.cs` | 26 | `formatter.Serialize(ms, session)` |
| `Source0.cs` | 33 | `typeof(BinaryFormatter)` |
| `Source2.cs` | 17 | `new BinaryFormatter()` |
| `Source2.cs` | 18 | `bf.Deserialize(messageStream)` |
| `Source2.cs` | 24 | `new BinaryFormatter()` |
| `Source2.cs` | 27 | `bf.Serialize(output, payment)` |
| `Source3.cs` | 18 | `new BinaryFormatter().Deserialize(ms)` |
| `Source3.cs` | 18 | `new BinaryFormatter()` |
| `Source3.cs` | 24 | `new BinaryFormatter().Serialize(output, keyStore)` |
| `Source3.cs` | 24 | `new BinaryFormatter()` |

## Recomendações de Remediação

### SMOL0009

Substitua BinaryFormatter por um serializador seguro com contratos tipados.

Exemplo com System.Text.Json:
```csharp
// ANTES (inseguro):
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);

// DEPOIS (seguro):
var obj = await JsonSerializer.DeserializeAsync<MeuTipo>(stream);
```

Alternativas seguras: System.Text.Json, MessagePack (com contratos tipados),
Protocol Buffers (protobuf-net com contratos).

Referência: https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide

