using System.Globalization;
using System.Text;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Reporting;

/// <summary>
/// Generates a standalone HTML dashboard report with charts and drill-down.
/// Uses Chart.js CDN for interactive visualizations. Works offline after first load.
/// </summary>
#pragma warning disable CA1305 // HTML output does not require culture-sensitive formatting
public static class HtmlDashboardEmitter
{
    public static async Task WriteAsync(
        PipelineResult result,
        IReadOnlyList<SmolerRule> rules,
        DateTimeOffset scanTime,
        string targetPath,
        string outputPath)
    {
        var findings = result.Findings;
        var criticalCount = findings.Count(f => f.Severity == RuleSeverity.Critical);
        var highCount = findings.Count(f => f.Severity == RuleSeverity.High);
        var mediumCount = findings.Count(f => f.Severity == RuleSeverity.Medium);
        var lowCount = findings.Count(f => f.Severity == RuleSeverity.Low);
        var infoCount = findings.Count(f => f.Severity == RuleSeverity.Info);

        var findingsByRule = findings.GroupBy(f => f.RuleId.ToString())
            .OrderByDescending(g => g.Count())
            .ToList();

        var findingsByFile = findings.GroupBy(f => f.Location.FilePath)
            .OrderByDescending(g => g.Count())
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"pt-BR\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine("<title>SmolerSAST — Relatório de Segurança</title>");
        sb.AppendLine("<script src=\"https://cdn.jsdelivr.net/npm/chart.js@4\"></script>");
        sb.AppendLine("<style>");
        sb.AppendLine(GetCss());
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Header
        sb.AppendLine("<header>");
        sb.AppendLine("<h1>SmolerSAST — Relatório de Segurança</h1>");
        sb.Append(CultureInfo.InvariantCulture, $"<p class=\"meta\">Alvo: <strong>{EscapeHtml(targetPath)}</strong> | Scan: {scanTime:yyyy-MM-dd HH:mm:ss UTC} | Duração: {result.Duration.TotalSeconds:F1}s</p>").AppendLine();
        sb.Append(CultureInfo.InvariantCulture, $"<p class=\"meta\">Regras executadas: {result.RulesExecuted} | Syntax trees: {result.SyntaxTreesAnalyzed} | Total findings: {findings.Length}</p>").AppendLine();
        sb.AppendLine("</header>");

        // Summary cards
        sb.AppendLine("<section class=\"cards\">");
        EmitCard(sb, "Critical", criticalCount, "#dc2626");
        EmitCard(sb, "High", highCount, "#ea580c");
        EmitCard(sb, "Medium", mediumCount, "#ca8a04");
        EmitCard(sb, "Low", lowCount, "#2563eb");
        EmitCard(sb, "Info", infoCount, "#6b7280");
        sb.AppendLine("</section>");

        // Charts row
        sb.AppendLine("<section class=\"charts\">");
        sb.AppendLine("<div class=\"chart-container\"><canvas id=\"severityChart\"></canvas></div>");
        sb.AppendLine("<div class=\"chart-container\"><canvas id=\"ruleChart\"></canvas></div>");
        sb.AppendLine("</section>");

        // Findings table
        sb.AppendLine("<section class=\"findings\">");
        sb.AppendLine("<h2>Findings</h2>");
        sb.AppendLine("<input type=\"text\" id=\"filterInput\" placeholder=\"Filtrar por regra, arquivo ou severidade...\" oninput=\"filterTable()\">");
        sb.AppendLine("<table id=\"findingsTable\">");
        sb.AppendLine("<thead><tr><th>Severidade</th><th>Regra</th><th>Arquivo</th><th>Linha</th><th>Mensagem</th><th>CWE</th><th>Confiança</th></tr></thead>");
        sb.AppendLine("<tbody>");

        foreach (var finding in findings)
        {
            var severityClass = finding.Severity.ToString().ToLowerInvariant();
            sb.AppendLine($"<tr class=\"severity-{severityClass}\">");
            sb.AppendLine($"<td><span class=\"badge {severityClass}\">{finding.Severity}</span></td>");
            sb.AppendLine($"<td>{finding.RuleId}</td>");
            sb.AppendLine($"<td>{EscapeHtml(finding.Location.FilePath)}</td>");
            sb.AppendLine($"<td>{finding.Location.StartLine}</td>");
            sb.AppendLine($"<td>{EscapeHtml(finding.MessagePtBr)}</td>");
            sb.AppendLine($"<td>{string.Join(", ", finding.CweIds.Select(c => $"CWE-{c}"))}</td>");
            sb.Append(CultureInfo.InvariantCulture, $"<td>{finding.Confidence:P0}</td>").AppendLine();
            sb.AppendLine("</tr>");
        }

        sb.AppendLine("</tbody></table>");
        sb.AppendLine("</section>");

        // Top rules section
        sb.AppendLine("<section class=\"top-rules\">");
        sb.AppendLine("<h2>Top Regras por Ocorrência</h2>");
        sb.AppendLine("<table><thead><tr><th>Regra</th><th>Severidade</th><th>Ocorrências</th><th>Descrição</th></tr></thead><tbody>");

        foreach (var group in findingsByRule.Take(15))
        {
            var first = group.First();
            var rule = rules.FirstOrDefault(r => r.Id.ToString() == group.Key);
            sb.AppendLine($"<tr><td>{group.Key}</td><td><span class=\"badge {first.Severity.ToString().ToLowerInvariant()}\">{first.Severity}</span></td><td>{group.Count()}</td><td>{EscapeHtml(rule?.DescriptionPtBr ?? first.MessagePtBr)}</td></tr>");
        }

        sb.AppendLine("</tbody></table></section>");

        // Charts JavaScript
        sb.AppendLine("<script>");
        sb.AppendLine($@"
new Chart(document.getElementById('severityChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{{ data: [{criticalCount}, {highCount}, {mediumCount}, {lowCount}, {infoCount}],
            backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#2563eb', '#6b7280'] }}]
    }},
    options: {{ responsive: true, plugins: {{ title: {{ display: true, text: 'Findings por Severidade' }} }} }}
}});

const ruleLabels = [{string.Join(",", findingsByRule.Take(10).Select(g => $"'{g.Key}'"))}];
const ruleCounts = [{string.Join(",", findingsByRule.Take(10).Select(g => g.Count()))}];
new Chart(document.getElementById('ruleChart'), {{
    type: 'bar',
    data: {{
        labels: ruleLabels,
        datasets: [{{ label: 'Ocorrências', data: ruleCounts, backgroundColor: '#3b82f6' }}]
    }},
    options: {{ responsive: true, indexAxis: 'y', plugins: {{ title: {{ display: true, text: 'Top 10 Regras' }} }} }}
}});

function filterTable() {{
    const filter = document.getElementById('filterInput').value.toLowerCase();
    const rows = document.querySelectorAll('#findingsTable tbody tr');
    rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? '' : 'none';
    }});
}}
");
        sb.AppendLine("</script>");

        // Footer
        sb.AppendLine("<footer>");
        sb.AppendLine($"<p>Gerado por SmolerSAST v0.4.0 | {scanTime:yyyy-MM-dd HH:mm:ss UTC}</p>");
        sb.AppendLine("</footer>");
        sb.AppendLine("</body></html>");

        await File.WriteAllTextAsync(outputPath, sb.ToString()).ConfigureAwait(false);
    }

    private static void EmitCard(StringBuilder sb, string label, int count, string color)
    {
        sb.AppendLine($"<div class=\"card\" style=\"border-left: 4px solid {color}\">");
        sb.AppendLine($"<div class=\"card-count\" style=\"color: {color}\">{count}</div>");
        sb.AppendLine($"<div class=\"card-label\">{label}</div>");
        sb.AppendLine("</div>");
    }

    private static string EscapeHtml(string text)
    {
        return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private static string GetCss() => """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
        header { background: #0f172a; color: white; padding: 2rem; }
        header h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .meta { color: #94a3b8; font-size: 0.875rem; }
        .cards { display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }
        .card { background: white; padding: 1.25rem; border-radius: 8px; min-width: 140px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card-count { font-size: 2rem; font-weight: 700; }
        .card-label { font-size: 0.875rem; color: #64748b; text-transform: uppercase; }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; padding: 0 2rem 1.5rem; }
        .chart-container { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .findings, .top-rules { padding: 0 2rem 2rem; }
        h2 { margin-bottom: 1rem; font-size: 1.25rem; }
        #filterInput { width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 0.875rem; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th { background: #f1f5f9; text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; color: #64748b; }
        td { padding: 0.75rem 1rem; border-top: 1px solid #f1f5f9; font-size: 0.875rem; }
        tr:hover { background: #f8fafc; }
        .badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; color: white; }
        .critical { background: #dc2626; }
        .high { background: #ea580c; }
        .medium { background: #ca8a04; }
        .low { background: #2563eb; }
        .info { background: #6b7280; }
        footer { text-align: center; padding: 2rem; color: #94a3b8; font-size: 0.75rem; }
        @media (max-width: 768px) { .charts { grid-template-columns: 1fr; } .cards { flex-direction: column; } }
        """;
}
