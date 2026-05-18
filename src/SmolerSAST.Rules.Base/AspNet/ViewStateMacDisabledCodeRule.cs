using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0027: Detects EnableViewStateMac = false in code.
/// </summary>
public sealed class ViewStateMacDisabledCodeRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0027");
    public override ImmutableArray<int> CweIds { get; } = [642];
    public override string OwaspCategory => "A08:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.High;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "viewstate"];
    public override string DescriptionPtBr => "EnableViewStateMac desabilitado no código. ViewState sem MAC é vulnerável a tampering.";
    public override string DescriptionEnUs => "EnableViewStateMac disabled in code. ViewState without MAC is vulnerable to tampering.";
    public override string RemediationGuidancePtBr => "Remova a atribuição EnableViewStateMac = false. O MAC é essencial para integridade do ViewState.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();
        if (!left.EndsWith("EnableViewStateMac", StringComparison.Ordinal)) return;

        if (assignment.Right is LiteralExpressionSyntax { Token.ValueText: "false" } or
            LiteralExpressionSyntax { RawKind: (int)SyntaxKind.FalseLiteralExpression })
        {
            var location = assignment.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0027"), RuleSeverity.Critical, RulePrecision.High,
                "EnableViewStateMac = false detectado. ViewState sem validação MAC.",
                "EnableViewStateMac = false detected. ViewState without MAC validation.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
                [], [642], "A08:2021", ["aspnet", "viewstate"], 1.0));
        }
    }
}
