using System.Collections.Immutable;
using System.Text.RegularExpressions;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Policy;

/// <summary>
/// Handles inline suppression comments in source code.
/// Format: // SMOLERSAST-IGNORE SMOL0001 reason="..." approved-by="..."
/// </summary>
public static partial class InlineSuppression
{
    [GeneratedRegex(
        @"SMOLERSAST-IGNORE\s+(SMOL\d{4})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex SuppressionPattern();

    /// <summary>
    /// Filters findings by removing those that have inline suppression comments.
    /// A suppression comment on the same line or the line immediately above the finding suppresses it.
    /// </summary>
    public static ImmutableArray<Finding> FilterSuppressed(
        ImmutableArray<Finding> findings,
        IReadOnlyDictionary<string, string[]> sourceLinesByFile)
    {
        return findings
            .Where(f => !IsSuppressed(f, sourceLinesByFile))
            .ToImmutableArray();
    }

    private static bool IsSuppressed(
        Finding finding,
        IReadOnlyDictionary<string, string[]> sourceLinesByFile)
    {
        if (!sourceLinesByFile.TryGetValue(finding.Location.FilePath, out var lines)) return false;

        var lineIndex = finding.Location.StartLine - 1; // 0-based
        if (lineIndex < 0 || lineIndex >= lines.Length) return false;

        // Check the finding line itself and the line above
        var ruleId = finding.RuleId.ToString();
        for (var i = Math.Max(0, lineIndex - 1); i <= lineIndex; i++)
        {
            var match = SuppressionPattern().Match(lines[i]);
            if (match.Success && match.Groups[1].Value.Equals(ruleId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
