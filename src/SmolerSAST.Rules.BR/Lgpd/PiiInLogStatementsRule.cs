using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Lgpd;

/// <summary>
/// SMOL1001: Detects PII (CPF, CNPJ, RG, CEP, email, telefone) in log statements.
/// Ref: LGPD Art. 46 — Medidas de segurança para proteção de dados pessoais.
/// </summary>
public sealed class PiiInLogStatementsRule : SmolerRule
{
    private static readonly string[] PiiFieldNames =
    [
        "cpf", "cnpj", "rg", "cep", "email", "telefone", "phone", "celular",
        "nome", "name", "endereco", "address", "datanascimento", "birthdate",
        "documento", "document", "identidade", "ssn",
    ];

    private static readonly string[] LogMethods =
    [
        "Log", "LogInformation", "LogWarning", "LogError", "LogDebug", "LogTrace", "LogCritical",
        "Info", "Warn", "Error", "Debug", "Fatal", "Write", "WriteLine",
    ];

    public override RuleId Id { get; } = new("SMOL1001");
    public override ImmutableArray<int> CweIds { get; } = [532];
    public override string OwaspCategory => "A09:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["lgpd", "pii", "logging"];
    public override string DescriptionPtBr => "Dado pessoal (PII) detectado em statement de log. Viola LGPD Art. 46 — dados pessoais devem ser protegidos contra acesso não autorizado.";
    public override string DescriptionEnUs => "PII detected in log statement. Violates LGPD Art. 46 — personal data must be protected against unauthorized access.";
    public override string RemediationGuidancePtBr => "Mascare dados pessoais antes de logar: CPF → ***.***.***-XX. Use filtros de redação no logger. Ref: LGPD Art. 46.";

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
            var matchedPii = PiiFieldNames.FirstOrDefault(p => argText.Contains(p, StringComparison.Ordinal));
            if (matchedPii is not null)
            {
                var location = invocation.GetLocation();
                var lineSpan = location.GetLineSpan();
                context.ReportFinding(new Finding(
                    new RuleId("SMOL1001"), RuleSeverity.High, RulePrecision.Medium,
                    $"PII ({matchedPii}) detectado em log statement. LGPD Art. 46.",
                    $"PII ({matchedPii}) detected in log statement. LGPD Art. 46.",
                    new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                    [], [532], "A09:2021", ["lgpd", "pii", "logging"], 0.8));
                break;
            }
        }
    }
}
