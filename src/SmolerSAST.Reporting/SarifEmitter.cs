using System.Text.Json;
using System.Text.Json.Serialization;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Reporting;

/// <summary>
/// Emits analysis results in SARIF 2.1.0 format.
/// Output is deterministic: sorted keys, fixed timestamps, normalized paths.
/// </summary>
public static class SarifEmitter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Emits a SARIF 2.1.0 report from the given pipeline result.
    /// </summary>
    /// <param name="result">The analysis pipeline result.</param>
    /// <param name="rules">The rules that were executed (for descriptors).</param>
    /// <param name="scanStartTime">Fixed scan start time for deterministic output.</param>
    /// <returns>SARIF JSON string.</returns>
    public static string Emit(
        PipelineResult result,
        IReadOnlyList<SmolerRule> rules,
        DateTimeOffset scanStartTime)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(rules);

        var sarifLog = new SarifLog
        {
            Schema = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            Version = "2.1.0",
            Runs =
            [
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifToolComponent
                        {
                            Name = "SmolerSAST",
                            Version = "0.1.0",
                            SemanticVersion = "0.1.0",
                            InformationUri = "https://github.com/smolersast/smolersast",
                            Rules = rules
                                .OrderBy(r => r.Id)
                                .Select(ToRuleDescriptor)
                                .ToList(),
                        },
                    },
                    Results = result.Findings
                        .Select(ToSarifResult)
                        .ToList(),
                    Invocations =
                    [
                        new SarifInvocation
                        {
                            StartTimeUtc = scanStartTime.UtcDateTime.ToString("O"),
                            EndTimeUtc = scanStartTime.Add(result.Duration).UtcDateTime.ToString("O"),
                            ExecutionSuccessful = true,
                        },
                    ],
                },
            ],
        };

        return JsonSerializer.Serialize(sarifLog, SerializerOptions);
    }

    /// <summary>
    /// Writes the SARIF report to a file.
    /// </summary>
    /// <param name="result">The analysis pipeline result.</param>
    /// <param name="rules">The rules that were executed.</param>
    /// <param name="scanStartTime">Fixed scan start time.</param>
    /// <param name="outputPath">Path to write the .sarif file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task WriteAsync(
        PipelineResult result,
        IReadOnlyList<SmolerRule> rules,
        DateTimeOffset scanStartTime,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var sarif = Emit(result, rules, scanStartTime);
        await File.WriteAllTextAsync(outputPath, sarif, cancellationToken).ConfigureAwait(false);
    }

    private static SarifReportingDescriptor ToRuleDescriptor(SmolerRule rule) => new()
    {
        Id = rule.Id.ToString(),
        Name = rule.Id.ToString(),
        ShortDescription = new SarifMessage { Text = rule.DescriptionEnUs },
        FullDescription = new SarifMessage { Text = rule.DescriptionPtBr },
        DefaultConfiguration = new SarifConfiguration
        {
            Level = MapSeverity(rule.Severity),
        },
        Properties = new Dictionary<string, object>
        {
            ["precision"] = rule.Precision.ToString(),
            ["tags"] = rule.Tags.ToArray(),
            ["cwe"] = rule.CweIds.Select(id => $"CWE-{id}").ToArray(),
            ["owasp"] = rule.OwaspCategory,
        },
    };

    private static SarifResult ToSarifResult(Finding finding) => new()
    {
        RuleId = finding.RuleId.ToString(),
        Level = MapSeverity(finding.Severity),
        Message = new SarifMessage { Text = finding.MessageEnUs },
        Locations =
        [
            new SarifLocation
            {
                PhysicalLocation = new SarifPhysicalLocation
                {
                    ArtifactLocation = new SarifArtifactLocation
                    {
                        Uri = finding.Location.FilePath.Replace('\\', '/'),
                    },
                    Region = new SarifRegion
                    {
                        StartLine = finding.Location.StartLine,
                        StartColumn = finding.Location.StartColumn + 1,
                        EndLine = finding.Location.EndLine,
                        EndColumn = finding.Location.EndColumn + 1,
                        Snippet = new SarifMessage { Text = finding.Location.CodeExcerpt },
                    },
                },
            },
        ],
        Properties = new Dictionary<string, object>
        {
            ["confidence"] = finding.Confidence,
            ["messagePtBr"] = finding.MessagePtBr,
        },
    };

    private static string MapSeverity(RuleSeverity severity) => severity switch
    {
        RuleSeverity.Critical => "error",
        RuleSeverity.High => "error",
        RuleSeverity.Medium => "warning",
        RuleSeverity.Low => "note",
        RuleSeverity.Info => "note",
        _ => "none",
    };
}

#region SARIF model (minimal, internal)

internal sealed class SarifLog
{
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    public string? Version { get; set; }
    public List<SarifRun>? Runs { get; set; }
}

internal sealed class SarifRun
{
    public SarifTool? Tool { get; set; }
    public List<SarifResult>? Results { get; set; }
    public List<SarifInvocation>? Invocations { get; set; }
}

internal sealed class SarifTool
{
    public SarifToolComponent? Driver { get; set; }
}

internal sealed class SarifToolComponent
{
    public string? Name { get; set; }
    public string? Version { get; set; }
    public string? SemanticVersion { get; set; }
    public string? InformationUri { get; set; }
    public List<SarifReportingDescriptor>? Rules { get; set; }
}

internal sealed class SarifReportingDescriptor
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public SarifMessage? ShortDescription { get; set; }
    public SarifMessage? FullDescription { get; set; }
    public SarifConfiguration? DefaultConfiguration { get; set; }
    public Dictionary<string, object>? Properties { get; set; }
}

internal sealed class SarifConfiguration
{
    public string? Level { get; set; }
}

internal sealed class SarifResult
{
    public string? RuleId { get; set; }
    public string? Level { get; set; }
    public SarifMessage? Message { get; set; }
    public List<SarifLocation>? Locations { get; set; }
    public Dictionary<string, object>? Properties { get; set; }
}

internal sealed class SarifLocation
{
    public SarifPhysicalLocation? PhysicalLocation { get; set; }
}

internal sealed class SarifPhysicalLocation
{
    public SarifArtifactLocation? ArtifactLocation { get; set; }
    public SarifRegion? Region { get; set; }
}

internal sealed class SarifArtifactLocation
{
    public string? Uri { get; set; }
}

internal sealed class SarifRegion
{
    public int? StartLine { get; set; }
    public int? StartColumn { get; set; }
    public int? EndLine { get; set; }
    public int? EndColumn { get; set; }
    public SarifMessage? Snippet { get; set; }
}

internal sealed class SarifMessage
{
    public string? Text { get; set; }
}

internal sealed class SarifInvocation
{
    public string? StartTimeUtc { get; set; }
    public string? EndTimeUtc { get; set; }
    public bool ExecutionSuccessful { get; set; }
}

#endregion
