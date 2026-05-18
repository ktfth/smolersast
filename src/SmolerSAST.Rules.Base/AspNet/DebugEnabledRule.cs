using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0028: Detects Debug/Trace enabled in production configuration code.
/// </summary>
public sealed class DebugEnabledRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0028");
    public override ImmutableArray<int> CweIds { get; } = [215];
    public override string OwaspCategory => "A05:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "debug", "configuration"];
    public override string DescriptionPtBr => "Debug ou Trace habilitado no código. Informações sensíveis podem ser expostas em produção.";
    public override string DescriptionEnUs => "Debug or Trace enabled in code. Sensitive information may be exposed in production.";
    public override string RemediationGuidancePtBr => "Desabilite compilação com debug/trace em builds de produção. Use #if DEBUG para código de diagnóstico.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();
        var isDebugSetting = left.EndsWith("EnableDebugging", StringComparison.Ordinal) ||
                             left.EndsWith("Debug", StringComparison.Ordinal) && left.Contains("Compilation", StringComparison.Ordinal) ||
                             left.EndsWith("CustomErrors", StringComparison.Ordinal);

        if (!isDebugSetting) return;

        if (assignment.Right is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.TrueLiteralExpression))
        {
            var location = assignment.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0028"), RuleSeverity.Medium, RulePrecision.Medium,
                $"Debug/Trace habilitado: {left} = true.",
                $"Debug/Trace enabled: {left} = true.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
                [], [215], "A05:2021", ["aspnet", "debug", "configuration"], 0.7));
        }
    }
}
