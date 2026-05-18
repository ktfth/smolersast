using System.Text.Json;

namespace SampleApp;

// This file should produce ZERO findings — all safe patterns.
public class SafeService
{
    // Negative: Safe JSON deserialization
    public T? DeserializeSafely<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json);
    }

    // Negative: Comment mentioning BinaryFormatter should not trigger
    // We used to use BinaryFormatter but migrated to JSON.
    public string GetStatus() => "safe";
}
