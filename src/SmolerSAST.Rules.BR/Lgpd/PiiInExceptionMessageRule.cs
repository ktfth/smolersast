using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Lgpd;

/// <summary>
/// SMOL1003: Detects PII in exception messages that may leak via stack traces.
/// Ref: LGPD Art. 46 — proteção de dados pessoais contra acesso não autorizado.
/// </summary>
public sealed class PiiInExceptionMessageRule : SmolerRule
{
    private static readonly string[] PiiFieldNames =
    [
        "cpf", "cnpj", "rg", "email", "telefone", "phone", "celular",
        "nome", "name", "endereco", "address", "documento", "identidade",
        "datanascimento", "birthdate", "ssn",
    ];

    private static readonly string[] ExceptionTypes =
    [
        "Exception", "ArgumentException", "InvalidOperationException",
        "ApplicationException", "FormatException", "ValidationException",
    ];

    public override RuleId Id { get; } = new("SMOL1003");
    public override ImmutableArray<int> CweIds { get; } = [209];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["lgpd", "pii", "exception"];
    public override string DescriptionPtBr => "PII detectado em mensagem de exceção. Stack traces podem vazar dados pessoais em logs e páginas de erro. LGPD Art. 46.";
    public override string DescriptionEnUs => "PII detected in exception message. Stack traces may leak personal data in logs and error pages.";
    public override string RemediationGuidancePtBr => "Nunca inclua dados pessoais em mensagens de exceção. Use IDs opacos e registre detalhes apenas em logs seguros com redação.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeThrow, SyntaxKind.ObjectCreationExpression);
    }

    private static void AnalyzeThrow(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation) return;

        var typeName = creation.Type.ToString();
        if (!ExceptionTypes.Any(e => typeName.Contains(e, StringComparison.Ordinal))) return;

        if (creation.ArgumentList is null || creation.ArgumentList.Arguments.Count == 0) return;

        var firstArg = creation.ArgumentList.Arguments[0].ToString().ToLowerInvariant();
        var matchedPii = PiiFieldNames.FirstOrDefault(p => firstArg.Contains(p, StringComparison.Ordinal));

        if (matchedPii is not null)
        {
            var location = creation.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1003"), RuleSeverity.High, RulePrecision.Medium,
                $"PII ({matchedPii}) em mensagem de exceção. Pode vazar via stack trace. LGPD Art. 46.",
                $"PII ({matchedPii}) in exception message. May leak via stack trace.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, creation.ToString()),
                [], [209], "A04:2021", ["lgpd", "pii", "exception"], 0.8));
        }
    }
}
