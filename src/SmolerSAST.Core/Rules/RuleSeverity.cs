namespace SmolerSAST.Core.Rules;

/// <summary>
/// Severity level of a security finding.
/// </summary>
public enum RuleSeverity
{
    /// <summary>Informational finding, no direct security impact.</summary>
    Info = 0,

    /// <summary>Low severity — minimal security impact.</summary>
    Low = 1,

    /// <summary>Medium severity — moderate security impact.</summary>
    Medium = 2,

    /// <summary>High severity — significant security impact.</summary>
    High = 3,

    /// <summary>Critical severity — immediate exploitation risk.</summary>
    Critical = 4,
}
