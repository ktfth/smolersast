using System;
using System.Text.Json;

namespace BankingApp.Audit;

/// <summary>
/// Logger de auditoria — código SEGURO.
/// Usa System.Text.Json para serialização tipada.
/// Nenhum finding deveria ser gerado para este arquivo.
/// </summary>
public class AuditLogger
{
    // SAFE: Serialização tipada com System.Text.Json
    public string SerializeAuditEvent(AuditEvent evt)
    {
        return JsonSerializer.Serialize(evt);
    }

    // SAFE: Deserialização tipada
    public AuditEvent? DeserializeAuditEvent(string json)
    {
        return JsonSerializer.Deserialize<AuditEvent>(json);
    }

    // SAFE: Comentário mencionando BinaryFormatter para contexto
    // Migrado de BinaryFormatter para JSON em 2024-Q3 por compliance Bacen 4.658
    public void LogTransaction(string transactionId, decimal amount)
    {
        var evt = new AuditEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            TransactionId = transactionId,
            Amount = amount,
            Action = "TRANSFER",
        };
        Console.WriteLine(SerializeAuditEvent(evt));
    }
}

public class AuditEvent
{
    public DateTimeOffset Timestamp { get; set; }
    public string TransactionId { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Action { get; set; } = string.Empty;
}
