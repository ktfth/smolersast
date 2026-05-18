using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Configuration;

/// <summary>
/// SMOL0038: Detects DI lifetime mismatch — Scoped service injected into Singleton.
/// </summary>
public sealed class DiLifetimeMismatchRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0038");
    public override ImmutableArray<int> CweIds { get; } = [664];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["di", "configuration"];
    public override string DescriptionPtBr => "Possível mismatch de lifetime no DI: serviço Scoped pode estar sendo injetado em Singleton.";
    public override string DescriptionEnUs => "Possible DI lifetime mismatch: Scoped service may be injected into Singleton.";
    public override string RemediationGuidancePtBr => "Verifique os lifetimes dos serviços. Use IServiceScopeFactory para acessar serviços Scoped dentro de Singletons.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression.ToString();
        if (!methodName.Contains("AddSingleton", StringComparison.Ordinal)) return;

        // Check if any generic type argument name contains "Scoped" indicator
        // This is a heuristic — full resolution requires cross-method analysis
        var args = invocation.ArgumentList.Arguments;
        foreach (var arg in args)
        {
            var argText = arg.ToString();
            if (argText.Contains("Scoped", StringComparison.OrdinalIgnoreCase) ||
                argText.Contains("scoped", StringComparison.Ordinal))
            {
                var location = invocation.GetLocation();
                var lineSpan = location.GetLineSpan();
                context.ReportFinding(new Finding(
                    new RuleId("SMOL0038"), RuleSeverity.High, RulePrecision.Low,
                    "Possível mismatch: serviço Scoped registrado como Singleton.",
                    "Possible mismatch: Scoped service registered as Singleton.",
                    new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                    [], [664], "A04:2021", ["di", "configuration"], 0.5));
            }
        }
    }
}
