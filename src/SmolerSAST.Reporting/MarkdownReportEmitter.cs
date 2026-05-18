using System.Globalization;
using System.Text;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Reporting;

/// <summary>
/// Emits a pt-BR executive summary in Markdown format.
/// </summary>
public static class MarkdownReportEmitter
{
    /// <summary>
    /// Generates a Markdown report in Brazilian Portuguese.
    /// </summary>
    public static string Emit(
        PipelineResult result,
        IReadOnlyList<SmolerRule> rules,
        DateTimeOffset scanStartTime,
        string targetPath)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(rules);

        var sb = new StringBuilder();

        sb.AppendLine("# SmolerSAST — Relatório de Análise de Segurança");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Data do scan**: {scanStartTime:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Alvo**: `{targetPath}`");
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Versão**: SmolerSAST v0.2.0");
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Modo**: {result.Mode}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Duração**: {result.Duration.TotalSeconds:F1}s");
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Syntax trees analisadas**: {result.SyntaxTreesAnalyzed}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Regras executadas**: {result.RulesExecuted}");
        sb.AppendLine();

        // Summary by severity
        sb.AppendLine("## Resumo");
        sb.AppendLine();
        sb.AppendLine("| Severidade | Quantidade |");
        sb.AppendLine("|------------|------------|");

        var groups = result.Findings.GroupBy(f => f.Severity).OrderByDescending(g => g.Key);
        foreach (var group in groups)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"| {group.Key} | {group.Count()} |");
        }

        sb.AppendLine(CultureInfo.InvariantCulture, $"| **Total** | **{result.Findings.Length}** |");
        sb.AppendLine();

        if (result.Findings.Length == 0)
        {
            sb.AppendLine("Nenhuma vulnerabilidade detectada.");
            return sb.ToString();
        }

        // Findings detail
        sb.AppendLine("## Findings");
        sb.AppendLine();

        var findingsByRule = result.Findings.GroupBy(f => f.RuleId).OrderBy(g => g.Key);
        foreach (var ruleGroup in findingsByRule)
        {
            var first = ruleGroup.First();
            sb.AppendLine(CultureInfo.InvariantCulture, $"### {ruleGroup.Key} — {first.MessagePtBr.Split('.')[0]}");
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **Severidade**: {first.Severity}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **CWE**: {string.Join(", ", first.CweIds.Select(id => $"CWE-{id}"))}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **OWASP**: {first.OwaspCategory}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **Ocorrências**: {ruleGroup.Count()}");
            sb.AppendLine();

            sb.AppendLine("| Arquivo | Linha | Trecho |");
            sb.AppendLine("|---------|-------|--------|");

            foreach (var finding in ruleGroup.OrderBy(f => f.Location.FilePath).ThenBy(f => f.Location.StartLine))
            {
                var excerpt = finding.Location.CodeExcerpt.Length > 60
                    ? finding.Location.CodeExcerpt[..57] + "..."
                    : finding.Location.CodeExcerpt;
                excerpt = excerpt.Replace("|", "\\|").Replace("\n", " ").Replace("\r", "");
                sb.AppendLine(CultureInfo.InvariantCulture, $"| `{finding.Location.FilePath}` | {finding.Location.StartLine} | `{excerpt}` |");
            }

            sb.AppendLine();
        }

        // Remediation
        sb.AppendLine("## Recomendações de Remediação");
        sb.AppendLine();

        var rulesUsed = result.Findings.Select(f => f.RuleId).Distinct().OrderBy(id => id);
        foreach (var ruleId in rulesUsed)
        {
            var rule = rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule is not null)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"### {ruleId}");
                sb.AppendLine();
                sb.AppendLine(rule.RemediationGuidancePtBr);
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Writes the Markdown report to a file.
    /// </summary>
    public static async Task WriteAsync(
        PipelineResult result,
        IReadOnlyList<SmolerRule> rules,
        DateTimeOffset scanStartTime,
        string targetPath,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var md = Emit(result, rules, scanStartTime, targetPath);
        await File.WriteAllTextAsync(outputPath, md, cancellationToken).ConfigureAwait(false);
    }
}
