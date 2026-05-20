using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1015: Detects session/token timeout configured above 15 minutes for authenticated channels.
/// Ref: Bacen Resolução 4.658/2018 — controle de sessão.
/// </summary>
public sealed class SessionTimeoutExcessiveRule : SmolerRule
{
    private static readonly string[] TimeoutProperties =
    [
        "IdleTimeout", "ExpireTimeSpan", "SlidingExpiration",
        "AbsoluteExpirationRelativeToNow", "TokenLifetime",
    ];

    public override RuleId Id { get; } = new("SMOL1015");
    public override ImmutableArray<int> CweIds { get; } = [613];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "session", "timeout"];
    public override string DescriptionPtBr => "Timeout de sessão > 15 minutos em canal autenticado. Bacen Res. 4.658 recomenda sessões curtas.";
    public override string DescriptionEnUs => "Session timeout > 15 minutes in authenticated channel. Bacen Res. 4.658 recommends short sessions.";
    public override string RemediationGuidancePtBr => "Configure IdleTimeout ≤ 15 minutos para sessões autenticadas. Use re-autenticação para operações sensíveis.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();
        if (!TimeoutProperties.Any(p => left.EndsWith(p, StringComparison.Ordinal))) return;

        var right = assignment.Right.ToString();

        // Detect TimeSpan.FromMinutes(X) where X > 15
        if (right.Contains("FromMinutes", StringComparison.Ordinal))
        {
            var minutes = ExtractMinutesFromTimeSpan(right);
            if (minutes > 15)
            {
                Report(context, assignment, minutes);
            }
        }
        // Detect TimeSpan.FromHours
        else if (right.Contains("FromHours", StringComparison.Ordinal))
        {
            Report(context, assignment, 60);
        }
    }

    private static int ExtractMinutesFromTimeSpan(string expression)
    {
        var start = expression.IndexOf('(');
        var end = expression.IndexOf(')');
        if (start < 0 || end < 0 || end <= start + 1) return 0;

        var valueStr = expression[(start + 1)..end].Trim();
        return int.TryParse(valueStr, out var val) ? val : 0;
    }

    private static void Report(SyntaxNodeAnalysisContext context, AssignmentExpressionSyntax assignment, int minutes)
    {
        var location = assignment.GetLocation();
        var lineSpan = location.GetLineSpan();
        context.ReportFinding(new Finding(
            new RuleId("SMOL1015"), RuleSeverity.Medium, RulePrecision.Medium,
            $"Timeout de sessão = {minutes}min (máx. recomendado: 15min). Bacen Res. 4.658.",
            $"Session timeout = {minutes}min (max recommended: 15min). Bacen Res. 4.658.",
            new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
            [], [613], "A07:2021", ["bacen", "session", "timeout"], 0.8));
    }
}
