using System.Collections.Immutable;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Represents a single security finding detected by a <see cref="SmolerRule"/>.
/// Immutable value object carrying the full context needed for reporting.
/// </summary>
/// <param name="RuleId">The stable rule identifier.</param>
/// <param name="Severity">Severity of the finding.</param>
/// <param name="Precision">Declared precision of the rule that produced this finding.</param>
/// <param name="MessagePtBr">User-facing message in Brazilian Portuguese.</param>
/// <param name="MessageEnUs">User-facing message in English.</param>
/// <param name="Location">Primary source location of the finding.</param>
/// <param name="AdditionalLocations">Additional related source locations (e.g., taint path).</param>
/// <param name="CweIds">CWE identifiers associated with this finding.</param>
/// <param name="OwaspCategory">OWASP Top 10 category (e.g., A08:2021).</param>
/// <param name="Tags">Searchable tags (e.g., "deserialization", "lgpd").</param>
/// <param name="Confidence">Confidence score from 0.0 (lowest) to 1.0 (highest).</param>
public sealed record Finding(
    RuleId RuleId,
    RuleSeverity Severity,
    RulePrecision Precision,
    string MessagePtBr,
    string MessageEnUs,
    FindingLocation Location,
    ImmutableArray<FindingLocation> AdditionalLocations,
    ImmutableArray<int> CweIds,
    string OwaspCategory,
    ImmutableArray<string> Tags,
    double Confidence);
