using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0032: Detects IDistributedCache usage without encryption of stored values.
/// </summary>
public sealed class DistributedCacheWithoutEncryptionRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0032");
    public override ImmutableArray<int> CweIds { get; } = [312];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "cache", "encryption"];
    public override string DescriptionPtBr => "Valor armazenado em IDistributedCache sem cifragem. Dados sensíveis podem ser expostos no cache.";
    public override string DescriptionEnUs => "Value stored in IDistributedCache without encryption. Sensitive data may be exposed in cache.";
    public override string RemediationGuidancePtBr => "Cifre valores antes de armazenar em cache distribuído usando DataProtection ou AES.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess) return;

        var methodName = memberAccess.Name.Identifier.Text;
        if (methodName is not ("SetString" or "SetStringAsync" or "Set" or "SetAsync")) return;

        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is null) return;

        var typeName = receiverType.ToDisplayString();
        if (typeName.Contains("IDistributedCache", StringComparison.Ordinal) ||
            typeName.Contains("DistributedCache", StringComparison.Ordinal))
        {
            var location = invocation.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0032"), RuleSeverity.Medium, RulePrecision.Low,
                $"Valor armazenado em IDistributedCache via {methodName}() sem cifragem aparente.",
                $"Value stored in IDistributedCache via {methodName}() without apparent encryption.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                [], [312], "A04:2021", ["aspnet", "cache", "encryption"], 0.5));
        }
    }
}
