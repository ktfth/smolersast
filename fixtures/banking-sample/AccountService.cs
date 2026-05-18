#pragma warning disable SYSLIB0011
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace BankingApp.Services;

/// <summary>
/// Serviço de contas bancárias com vulnerabilidades intencionais para teste do SmolerSAST.
/// </summary>
public class AccountService
{
    // VULN: BinaryFormatter para deserializar dados de transferência
    public object? DeserializeTransferRequest(byte[] data)
    {
        using var ms = new MemoryStream(data);
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(ms);
    }

    // VULN: BinaryFormatter para cache de sessão
    public byte[] SerializeSession(object session)
    {
        using var ms = new MemoryStream();
        var formatter = new BinaryFormatter();
        formatter.Serialize(ms, session);
        return ms.ToArray();
    }

    // VULN: typeof para registro dinâmico de formatador
    public Type GetLegacyFormatterType()
    {
        return typeof(BinaryFormatter);
    }
}
