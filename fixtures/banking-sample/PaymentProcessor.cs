#pragma warning disable SYSLIB0011
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace BankingApp.Payments;

/// <summary>
/// Processador de pagamentos com padrões inseguros de deserialização.
/// Simula código legado encontrado em bancos brasileiros.
/// </summary>
public class PaymentProcessor
{
    // VULN: Deserialização de mensageria entre sistemas
    public object? ProcessIncomingMessage(Stream messageStream)
    {
        var bf = new BinaryFormatter();
        return bf.Deserialize(messageStream);
    }

    // VULN: Serialização de lote de pagamentos para fila
    public void EnqueueBatch(Stream output, object[] payments)
    {
        var bf = new BinaryFormatter();
        foreach (var payment in payments)
        {
            bf.Serialize(output, payment);
        }
    }
}
