// Intentionally vulnerable code for SmolerSAST testing.
// DO NOT use these patterns in production code.
#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete
#pragma warning disable CA2300      // Do not use insecure deserializer BinaryFormatter
#pragma warning disable CA2301
#pragma warning disable CA2302

using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableSamples;

// ═══════════════════════════════════════════════════════
// POSITIVE CASES — MUST be detected by SMOL0009
// ═══════════════════════════════════════════════════════

/// <summary>Positive 1: Direct instantiation and Deserialize call.</summary>
public class DirectUsage
{
    public object? DeserializeData(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }
}

/// <summary>Positive 2: Indirect usage via variable.</summary>
public class IndirectUsage
{
    public void SerializeData(Stream stream, object data)
    {
        BinaryFormatter bf = new();
        bf.Serialize(stream, data);
    }
}

/// <summary>Positive 3: typeof(BinaryFormatter) — reflection-based usage indicator.</summary>
public class ReflectionUsage
{
    public Type GetFormatterType()
    {
        return typeof(BinaryFormatter);
    }
}

/// <summary>Positive 4: BinaryFormatter in a helper method accepting Stream.</summary>
public class HelperMethodUsage
{
    private static object? DeserializeFromStream(Stream input)
    {
        var fmt = new BinaryFormatter();
        return fmt.Deserialize(input);
    }

    public object? ProcessData(byte[] data)
    {
        using var ms = new MemoryStream(data);
        return DeserializeFromStream(ms);
    }
}

/// <summary>Positive 5: BinaryFormatter with SurrogateSelector — still insecure.</summary>
public class SurrogateUsage
{
    public object? DeserializeWithSurrogate(Stream stream)
    {
        var formatter = new BinaryFormatter
        {
            SurrogateSelector = new System.Runtime.Serialization.SurrogateSelector()
        };
        return formatter.Deserialize(stream);
    }
}

// ═══════════════════════════════════════════════════════
// NEGATIVE CASES — MUST NOT be detected by SMOL0009
// ═══════════════════════════════════════════════════════

/// <summary>Negative 1: Safe alternative using System.Text.Json.</summary>
public class SafeJsonUsage
{
    public T? DeserializeSafely<T>(string json)
    {
        return System.Text.Json.JsonSerializer.Deserialize<T>(json);
    }
}

/// <summary>
/// Negative 2: User-defined class named BinaryFormatter in a different namespace.
/// This MUST NOT be detected — proves symbol resolution, not string matching.
/// </summary>
public class BinaryFormatter
{
    public string Format(byte[] data) => Convert.ToBase64String(data);
}

public class UserDefinedFormatterUsage
{
    public string UseCustomFormatter(byte[] data)
    {
        var formatter = new BinaryFormatter();
        return formatter.Format(data);
    }
}

/// <summary>Negative 3: Comment mentioning BinaryFormatter — must not trigger.</summary>
public class CommentMention
{
    // We used to use BinaryFormatter here but migrated to JSON.
    // BinaryFormatter is dangerous and should never be used.
    public string SafeMethod() => "safe";
}
