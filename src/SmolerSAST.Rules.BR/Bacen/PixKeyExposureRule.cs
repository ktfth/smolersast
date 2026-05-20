using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1014: Detects PIX key exposure in logs or HTTP response bodies.
/// Ref: Bacen Resolução 1/2020 — proteção de dados PIX.
/// </summary>
public sealed class PixKeyExposureRule : SmolerRule
{
    private static readonly string[] PixFieldNames =
    [
        "pixkey", "pix_key", "chavepix", "chave_pix", "pixkeyvalue",
        "endtoendid", "end_to_end_id", "e2eid",
    ];

    private static readonly string[] LogMethods =
    [
        "Log", "LogInformation", "LogWarning", "LogError", "LogDebug", "LogTrace",
        "Info", "Warn", "Error", "Debug", "Write", "WriteLine",
    ];

    public override RuleId Id { get; } = new("SMOL1014");
    public override ImmutableArray<int> CweIds { get; } = [532];
    public override string OwaspCategory => "A09:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "pix", "logging"];
    public override string DescriptionPtBr => "Chave PIX ou EndToEndId exposta em log/response. Bacen Res. 1/2020 exige proteção de dados PIX.";
    public override string DescriptionEnUs => "PIX key or EndToEndId exposed in log/response. Bacen Res. 1/2020 requires PIX data protection.";
    public override string RemediationGuidancePtBr => "Mascare chaves PIX em logs (exibir apenas últimos 4 caracteres). Não retorne chaves completas em responses desnecessários.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            IdentifierNameSyntax id => id.Identifier.Text,
            _ => null,
        };

        if (methodName is null || !LogMethods.Any(m => m.Equals(methodName, StringComparison.OrdinalIgnoreCase))) return;

        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            var argText = arg.ToString().ToLowerInvariant();
            var matched = PixFieldNames.FirstOrDefault(p => argText.Contains(p, StringComparison.Ordinal));
            if (matched is not null)
            {
                var location = invocation.GetLocation();
                var lineSpan = location.GetLineSpan();
                context.ReportFinding(new Finding(
                    new RuleId("SMOL1014"), RuleSeverity.High, RulePrecision.Medium,
                    $"Chave PIX ({matched}) exposta em log. Bacen Res. 1/2020.",
                    $"PIX key ({matched}) exposed in log. Bacen Res. 1/2020.",
                    new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                    [], [532], "A09:2021", ["bacen", "pix", "logging"], 0.8));
                break;
            }
        }
    }
}
