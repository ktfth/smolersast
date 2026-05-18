using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0031: Detects AddAuthentication() without scheme validation configuration.
/// </summary>
public sealed class AuthenticationWithoutSchemeRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0031");
    public override ImmutableArray<int> CweIds { get; } = [287];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "authentication"];
    public override string DescriptionPtBr => "AddAuthentication() chamado sem configuração de esquema. Autenticação pode não funcionar corretamente.";
    public override string DescriptionEnUs => "AddAuthentication() called without scheme configuration.";
    public override string RemediationGuidancePtBr => "Configure o esquema de autenticação: services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(...)";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression.ToString();
        if (!methodName.EndsWith("AddAuthentication", StringComparison.Ordinal)) return;

        // Flag if AddAuthentication() has no arguments (no default scheme)
        if (invocation.ArgumentList.Arguments.Count == 0)
        {
            var location = invocation.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0031"), RuleSeverity.High, RulePrecision.Low,
                "AddAuthentication() sem esquema padrão configurado.",
                "AddAuthentication() without default scheme configuration.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                [], [287], "A07:2021", ["aspnet", "authentication"], 0.6));
        }
    }
}
