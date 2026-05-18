using System.Collections.Immutable;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Base class for all SmolerSAST security rules. Each rule is a sealed class
/// that declares its metadata and registers analysis actions. Rules MUST be stateless.
/// </summary>
public abstract class SmolerRule
{
    /// <summary>Gets the stable rule identifier (format: SMOLnnnn, never reused).</summary>
    public abstract RuleId Id { get; }

    /// <summary>Gets the CWE identifiers associated with this rule.</summary>
    public abstract ImmutableArray<int> CweIds { get; }

    /// <summary>Gets the OWASP Top 10 category (e.g., "A08:2021").</summary>
    public abstract string OwaspCategory { get; }

    /// <summary>Gets the severity level of findings produced by this rule.</summary>
    public abstract RuleSeverity Severity { get; }

    /// <summary>Gets the declared precision. Used to gate noise in CI pipelines.</summary>
    public abstract RulePrecision Precision { get; }

    /// <summary>Gets searchable tags (e.g., "deserialization", "lgpd", "crypto").</summary>
    public abstract ImmutableArray<string> Tags { get; }

    /// <summary>Gets the rule description in Brazilian Portuguese.</summary>
    public abstract string DescriptionPtBr { get; }

    /// <summary>Gets the rule description in English.</summary>
    public abstract string DescriptionEnUs { get; }

    /// <summary>Gets remediation guidance in Brazilian Portuguese, including code examples.</summary>
    public abstract string RemediationGuidancePtBr { get; }

    /// <summary>
    /// Registers analysis actions (syntax node, symbol, etc.) with the given context.
    /// Called once during pipeline initialization. The rule MUST NOT store mutable state.
    /// </summary>
    /// <param name="context">The analysis context to register callbacks with.</param>
    public abstract void RegisterActions(AnalysisContext context);
}
