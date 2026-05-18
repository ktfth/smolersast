#pragma warning disable SYSLIB0011
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace BankingApp.Pix;

/// <summary>
/// Serviço Pix com deserialização insegura de payload.
/// Simula integração legada com sistema de liquidação.
/// </summary>
public class PixService
{
    // VULN: Deserialização de resposta do SPI (Sistema de Pagamentos Instantâneos)
    public object? ParseSpiResponse(byte[] responseData)
    {
        using var ms = new MemoryStream(responseData);
        return new BinaryFormatter().Deserialize(ms);
    }

    // VULN: Backup de chaves Pix via serialização binária
    public void BackupPixKeys(Stream output, object keyStore)
    {
        new BinaryFormatter().Serialize(output, keyStore);
    }
}
