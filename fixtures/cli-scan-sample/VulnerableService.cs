#pragma warning disable SYSLIB0011
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace SampleApp;

public class VulnerableService
{
    // Positive 1: Direct instantiation
    public object? DeserializeData(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }

    // Positive 2: Serialize path
    public void SerializeData(Stream stream, object data)
    {
        BinaryFormatter bf = new();
        bf.Serialize(stream, data);
    }

    // Positive 3: typeof usage
    public Type GetFormatterType()
    {
        return typeof(BinaryFormatter);
    }
}
