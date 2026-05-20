using System.Collections.Immutable;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Policy;

/// <summary>
/// Evaluates scan findings against a policy configuration and baseline.
/// Returns an exit code and a summary of the evaluation.
/// </summary>
public static class PolicyEvaluator
{
    /// <summary>
    /// Evaluates findings against the policy and returns a result.
    /// Exit codes: 0 = pass, 1 = policy violation (new findings above threshold), 2 = scan error.
    /// </summary>
    public static PolicyEvaluationResult Evaluate(
        ImmutableArray<Finding> findings,
        PolicyConfiguration policy,
        Baseline? baseline)
    {
        // Filter disabled rules
        var activeFindings = findings;
        if (!policy.Rules.Disabled.IsDefaultOrEmpty)
        {
            activeFindings = findings
                .Where(f => !policy.Rules.Disabled.Contains(f.RuleId.ToString()))
                .ToImmutableArray();
        }

        // Apply baseline
        var newFindings = baseline is not null
            ? baseline.FilterNewFindings(activeFindings, policy.Baseline.MaxAgeDays)
            : activeFindings;

        var baselinedCount = activeFindings.Length - newFindings.Length;

        // Count by severity
        var counts = new Dictionary<RuleSeverity, int>
        {
            [RuleSeverity.Critical] = newFindings.Count(f => f.Severity == RuleSeverity.Critical),
            [RuleSeverity.High] = newFindings.Count(f => f.Severity == RuleSeverity.High),
            [RuleSeverity.Medium] = newFindings.Count(f => f.Severity == RuleSeverity.Medium),
            [RuleSeverity.Low] = newFindings.Count(f => f.Severity == RuleSeverity.Low),
            [RuleSeverity.Info] = newFindings.Count(f => f.Severity == RuleSeverity.Info),
        };

        // Evaluate thresholds
        var violations = new List<string>();
        var thresholds = policy.QualityGates.FailOn;

        EvaluateThreshold(violations, "Critical", counts[RuleSeverity.Critical], thresholds.Critical);
        EvaluateThreshold(violations, "High", counts[RuleSeverity.High], thresholds.High);
        EvaluateThreshold(violations, "Medium", counts[RuleSeverity.Medium], thresholds.Medium);
        EvaluateThreshold(violations, "Low", counts[RuleSeverity.Low], thresholds.Low);
        EvaluateThreshold(violations, "Info", counts[RuleSeverity.Info], thresholds.Info);

        var exitCode = violations.Count > 0 ? 1 : 0;

        return new PolicyEvaluationResult(
            ExitCode: exitCode,
            TotalFindings: activeFindings.Length,
            NewFindings: newFindings.Length,
            BaselinedFindings: baselinedCount,
            CountBySeverity: counts.ToImmutableDictionary(),
            Violations: violations.ToImmutableArray(),
            NewFindingsList: newFindings);
    }

    private static void EvaluateThreshold(List<string> violations, string severity, int count, int threshold)
    {
        if (threshold < 0) return; // -1 = disabled
        if (count > threshold)
        {
            violations.Add($"{severity}: {count} findings (max allowed: {threshold})");
        }
    }
}

/// <summary>
/// Result of policy evaluation.
/// </summary>
public sealed record PolicyEvaluationResult(
    int ExitCode,
    int TotalFindings,
    int NewFindings,
    int BaselinedFindings,
    ImmutableDictionary<RuleSeverity, int> CountBySeverity,
    ImmutableArray<string> Violations,
    ImmutableArray<Finding> NewFindingsList);
