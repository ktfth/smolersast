using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0030: Detects cookies configured without Secure, HttpOnly, or SameSite flags.
/// </summary>
public sealed class InsecureCookieRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0030");
    public override ImmutableArray<int> CweIds { get; } = [614];
    public override string OwaspCategory => "A05:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "cookie"];
    public override string DescriptionPtBr => "Cookie configurado sem flags de segurança (Secure, HttpOnly ou SameSite).";
    public override string DescriptionEnUs => "Cookie configured without security flags (Secure, HttpOnly, or SameSite).";
    public override string RemediationGuidancePtBr => "Configure Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict em CookieOptions.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();
        var isCookieSecureFlag = (left.EndsWith(".Secure", StringComparison.Ordinal) ||
                                  left.EndsWith(".HttpOnly", StringComparison.Ordinal)) &&
                                 assignment.Right is LiteralExpressionSyntax lit &&
                                 lit.IsKind(SyntaxKind.FalseLiteralExpression);

        if (isCookieSecureFlag)
        {
            var location = assignment.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0030"), RuleSeverity.Medium, RulePrecision.Medium,
                $"Cookie flag de segurança desabilitada: {left} = false.",
                $"Cookie security flag disabled: {left} = false.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
                [], [614], "A05:2021", ["aspnet", "cookie"], 0.85));
        }
    }
}
