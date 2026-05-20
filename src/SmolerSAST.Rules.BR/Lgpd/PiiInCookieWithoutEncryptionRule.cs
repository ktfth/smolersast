using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Lgpd;

/// <summary>
/// SMOL1005: Detects PII stored in cookies without encryption.
/// Ref: LGPD Art. 46 — medidas técnicas para proteção de dados pessoais.
/// </summary>
public sealed class PiiInCookieWithoutEncryptionRule : SmolerRule
{
    private static readonly string[] PiiFieldNames =
    [
        "cpf", "cnpj", "rg", "email", "telefone", "phone",
        "nome", "name", "documento", "identidade",
    ];

    public override RuleId Id { get; } = new("SMOL1005");
    public override ImmutableArray<int> CweIds { get; } = [315];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["lgpd", "pii", "cookie"];
    public override string DescriptionPtBr => "PII armazenado em cookie sem cifragem. Cookies podem ser interceptados e lidos em texto claro. LGPD Art. 46.";
    public override string DescriptionEnUs => "PII stored in cookie without encryption. Cookies can be intercepted and read in plaintext.";
    public override string RemediationGuidancePtBr => "Não armazene dados pessoais em cookies. Se necessário, cifre com IDataProtector e marque Secure + HttpOnly.";

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
            _ => null,
        };

        if (methodName is null) return;

        // Detect Response.Cookies.Append or similar cookie-setting patterns
        if (!methodName.Equals("Append", StringComparison.Ordinal) &&
            !methodName.Equals("Add", StringComparison.Ordinal)) return;

        var expressionText = invocation.Expression.ToString().ToLowerInvariant();
        if (!expressionText.Contains("cookie", StringComparison.Ordinal)) return;

        // Check arguments for PII
        var argsText = invocation.ArgumentList.ToString().ToLowerInvariant();
        var matchedPii = PiiFieldNames.FirstOrDefault(p => argsText.Contains(p, StringComparison.Ordinal));

        if (matchedPii is not null)
        {
            var location = invocation.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1005"), RuleSeverity.High, RulePrecision.Medium,
                $"PII ({matchedPii}) em cookie sem cifragem. LGPD Art. 46.",
                $"PII ({matchedPii}) in cookie without encryption.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                [], [315], "A04:2021", ["lgpd", "pii", "cookie"], 0.75));
        }
    }
}
