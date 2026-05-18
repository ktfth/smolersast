using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Lgpd;

/// <summary>
/// SMOL1002: Detects PII transmitted in URL query strings.
/// Ref: LGPD Art. 46.
/// </summary>
public sealed class PiiInUrlQueryStringRule : SmolerRule
{
    private static readonly string[] PiiParams = ["cpf", "cnpj", "rg", "email", "telefone", "phone", "documento", "nome", "name"];

    public override RuleId Id { get; } = new("SMOL1002");
    public override ImmutableArray<int> CweIds { get; } = [598];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["lgpd", "pii", "url"];
    public override string DescriptionPtBr => "PII transmitido em query string de URL. Dados pessoais podem ser logados em servidores web e proxies.";
    public override string DescriptionEnUs => "PII transmitted in URL query string. Personal data may be logged by web servers and proxies.";
    public override string RemediationGuidancePtBr => "Transmita dados pessoais no corpo da requisição (POST) ou em headers criptografados. Nunca em query strings.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeStringLiteral, SyntaxKind.StringLiteralExpression, SyntaxKind.InterpolatedStringExpression);
    }

    private static void AnalyzeStringLiteral(SyntaxNodeAnalysisContext context)
    {
        var text = context.Node.ToString().ToLowerInvariant();
        if (!text.Contains('?') && !text.Contains("query", StringComparison.Ordinal)) return;

        var matchedPii = PiiParams.FirstOrDefault(p => text.Contains(p + "=", StringComparison.Ordinal) || text.Contains(p + "}", StringComparison.Ordinal));
        if (matchedPii is not null)
        {
            var location = context.Node.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1002"), RuleSeverity.High, RulePrecision.Medium,
                $"PII ({matchedPii}) em query string de URL. LGPD Art. 46.",
                $"PII ({matchedPii}) in URL query string.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, context.Node.ToString()),
                [], [598], "A04:2021", ["lgpd", "pii", "url"], 0.75));
        }
    }
}
