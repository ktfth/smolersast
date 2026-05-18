using System.Collections.Immutable;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Pipeline;

/// <summary>
/// Configuration options for an analysis pipeline run.
/// </summary>
/// <param name="Path">Path to the target (solution, project, or assembly).</param>
/// <param name="EnabledRuleIds">Optional set of rule IDs to enable. Null means all rules.</param>
/// <param name="MaxConcurrency">Maximum parallel rule executions. Defaults to processor count.</param>
/// <param name="MemoryBudgetMb">Memory budget in MB. Zero means no limit.</param>
public sealed record AnalysisPipelineOptions(
    string Path,
    ImmutableHashSet<RuleId>? EnabledRuleIds = null,
    int MaxConcurrency = 0,
    int MemoryBudgetMb = 0)
{
    /// <summary>
    /// Gets the effective max concurrency (defaults to processor count if zero).
    /// </summary>
    public int EffectiveMaxConcurrency =>
        MaxConcurrency > 0 ? MaxConcurrency : Environment.ProcessorCount;
}
