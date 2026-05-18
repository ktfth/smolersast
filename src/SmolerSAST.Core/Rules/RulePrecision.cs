namespace SmolerSAST.Core.Rules;

/// <summary>
/// Declared precision of a rule's detection. Used to gate noise in CI pipelines.
/// </summary>
public enum RulePrecision
{
    /// <summary>Low precision — expect a higher false positive rate.</summary>
    Low = 0,

    /// <summary>Medium precision — moderate confidence in findings.</summary>
    Medium = 1,

    /// <summary>High precision — very few false positives expected.</summary>
    High = 2,
}
