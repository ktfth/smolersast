using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SmolerSAST.Core.Policy;

/// <summary>
/// Represents the .smolersast.json policy configuration.
/// Controls quality gates, required rules, severity SLA, and baseline behavior.
/// </summary>
public sealed record PolicyConfiguration(
    int Version,
    QualityGates QualityGates,
    RulePolicy Rules,
    SeveritySla SeveritySla,
    BaselinePolicy Baseline)
{
    public static readonly string DefaultFileName = ".smolersast.json";

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static PolicyConfiguration Default { get; } = new(
        Version: 1,
        QualityGates: new QualityGates(
            FailOn: new SeverityThresholds(Critical: 0, High: 5, Medium: -1, Low: -1, Info: -1),
            BlockMerge: true),
        Rules: new RulePolicy(
            Required: [],
            Disabled: []),
        SeveritySla: new SeveritySla(
            CriticalHours: 48,
            HighHours: 168,
            MediumHours: 720,
            LowHours: 2160),
        Baseline: new BaselinePolicy(
            MaxAgeDays: 90,
            RequireApproval: true));

    public static async Task<PolicyConfiguration> LoadAsync(string directoryPath)
    {
        var filePath = Path.Combine(directoryPath, DefaultFileName);
        if (!File.Exists(filePath)) return Default;

        var json = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
        return JsonSerializer.Deserialize<PolicyConfiguration>(json, ReadOptions) ?? Default;
    }

    public static async Task SaveAsync(PolicyConfiguration policy, string directoryPath)
    {
        var filePath = Path.Combine(directoryPath, DefaultFileName);
        var json = JsonSerializer.Serialize(policy, WriteOptions);
        await File.WriteAllTextAsync(filePath, json).ConfigureAwait(false);
    }
}

/// <summary>
/// Quality gates that control build failure based on finding counts by severity.
/// A value of -1 means no limit (disabled). 0 means zero tolerance.
/// </summary>
public sealed record QualityGates(
    SeverityThresholds FailOn,
    bool BlockMerge);

/// <summary>
/// Maximum findings per severity before the scan fails.
/// -1 = no limit (unlimited), 0 = zero tolerance.
/// </summary>
public sealed record SeverityThresholds(
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info);

/// <summary>
/// Controls which rules are required and which are disabled.
/// </summary>
public sealed record RulePolicy(
    ImmutableArray<string> Required,
    ImmutableArray<string> Disabled);

/// <summary>
/// SLA deadlines by severity (in hours).
/// </summary>
public sealed record SeveritySla(
    int CriticalHours,
    int HighHours,
    int MediumHours,
    int LowHours);

/// <summary>
/// Baseline configuration for managing known findings.
/// </summary>
public sealed record BaselinePolicy(
    int MaxAgeDays,
    bool RequireApproval);
