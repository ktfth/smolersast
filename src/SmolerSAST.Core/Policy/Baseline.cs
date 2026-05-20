using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Policy;

/// <summary>
/// Represents a baseline of known findings that are accepted and should not fail the build.
/// </summary>
public sealed record Baseline(
    DateTimeOffset CreatedAt,
    string CreatedBy,
    ImmutableArray<BaselineEntry> Entries)
{
    public static readonly string DefaultFileName = ".smolersast-baseline.json";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static async Task<Baseline?> LoadAsync(string directoryPath)
    {
        var filePath = Path.Combine(directoryPath, DefaultFileName);
        if (!File.Exists(filePath)) return null;

        var json = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
        return JsonSerializer.Deserialize<Baseline>(json, SerializerOptions);
    }

    public static async Task SaveAsync(Baseline baseline, string directoryPath)
    {
        var filePath = Path.Combine(directoryPath, DefaultFileName);
        var json = JsonSerializer.Serialize(baseline, SerializerOptions);
        await File.WriteAllTextAsync(filePath, json).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a baseline from current findings.
    /// </summary>
    public static Baseline FromFindings(ImmutableArray<Finding> findings, string createdBy)
    {
        var entries = findings.Select(f => new BaselineEntry(
            RuleId: f.RuleId.ToString(),
            FilePath: f.Location.FilePath,
            StartLine: f.Location.StartLine,
            Fingerprint: ComputeFingerprint(f),
            AcceptedAt: DateTimeOffset.UtcNow,
            AcceptedBy: createdBy,
            Reason: null,
            ExpiresAt: null)).ToImmutableArray();

        return new Baseline(DateTimeOffset.UtcNow, createdBy, entries);
    }

    /// <summary>
    /// Filters findings, returning only those NOT in the baseline.
    /// </summary>
    public ImmutableArray<Finding> FilterNewFindings(ImmutableArray<Finding> findings, int maxAgeDays)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-maxAgeDays);
        var validEntries = Entries
            .Where(e => e.AcceptedAt >= cutoff && (e.ExpiresAt is null || e.ExpiresAt > DateTimeOffset.UtcNow))
            .ToImmutableArray();

        return findings
            .Where(f => !validEntries.Any(e => MatchesFinding(e, f)))
            .ToImmutableArray();
    }

    private static bool MatchesFinding(BaselineEntry entry, Finding finding)
    {
        return entry.RuleId == finding.RuleId.ToString() &&
               entry.Fingerprint == ComputeFingerprint(finding);
    }

    private static string ComputeFingerprint(Finding finding)
    {
        var input = $"{finding.RuleId}:{finding.Location.FilePath}:{finding.Location.CodeExcerpt}";
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(hash)[..16];
    }
}

/// <summary>
/// A single baselined finding entry.
/// </summary>
public sealed record BaselineEntry(
    string RuleId,
    string FilePath,
    int StartLine,
    string Fingerprint,
    DateTimeOffset AcceptedAt,
    string AcceptedBy,
    string? Reason,
    DateTimeOffset? ExpiresAt);
