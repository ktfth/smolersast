using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SmolerSAST.Reporting;

/// <summary>
/// Emits a manifest.json with SHA-256 hashes of all scan artifacts.
/// </summary>
public static class ManifestEmitter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Creates a manifest from a list of artifact file paths.
    /// </summary>
    public static async Task<string> EmitAsync(
        IReadOnlyList<string> artifactPaths,
        DateTimeOffset scanStartTime,
        string toolVersion = "0.2.0",
        CancellationToken cancellationToken = default)
    {
        var artifacts = new List<ArtifactEntry>();

        foreach (var path in artifactPaths)
        {
            if (!File.Exists(path)) continue;

            var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));

            artifacts.Add(new ArtifactEntry
            {
                Path = path.Replace('\\', '/'),
                Sha256 = hash,
                SizeBytes = bytes.Length,
            });
        }

        var manifest = new Manifest
        {
            ScanStartTime = scanStartTime.UtcDateTime.ToString("O"),
            ToolName = "SmolerSAST",
            ToolVersion = toolVersion,
            Runtime = $"{Environment.OSVersion} / .NET {Environment.Version}",
            Artifacts = artifacts,
        };

        return JsonSerializer.Serialize(manifest, Options);
    }

    /// <summary>
    /// Writes the manifest to a file.
    /// </summary>
    public static async Task WriteAsync(
        IReadOnlyList<string> artifactPaths,
        DateTimeOffset scanStartTime,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var json = await EmitAsync(artifactPaths, scanStartTime, cancellationToken: cancellationToken).ConfigureAwait(false);
        await File.WriteAllTextAsync(outputPath, json, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class Manifest
{
    public string? ScanStartTime { get; set; }
    public string? ToolName { get; set; }
    public string? ToolVersion { get; set; }
    public string? Runtime { get; set; }
    public List<ArtifactEntry>? Artifacts { get; set; }
}

internal sealed class ArtifactEntry
{
    public string? Path { get; set; }
    public string? Sha256 { get; set; }
    public long SizeBytes { get; set; }
}
