using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Lgpd;

/// <summary>
/// SMOL1006: Detects PII fields without [PersonalData] or equivalent annotation.
/// Ref: LGPD Art. 5 — definição de dados pessoais.
/// </summary>
public sealed class PiiWithoutPersonalDataAnnotationRule : SmolerRule
{
    private static readonly string[] PiiPropertyNames =
    [
        "cpf", "cnpj", "rg", "email", "telefone", "phone", "celular",
        "nome", "name", "endereco", "address", "datanascimento", "birthdate",
        "documento", "identidade",
    ];

    public override RuleId Id { get; } = new("SMOL1006");
    public override ImmutableArray<int> CweIds { get; } = [359];
    public override string OwaspCategory => "A01:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["lgpd", "pii", "annotation"];
    public override string DescriptionPtBr => "Propriedade com nome de PII sem anotação [PersonalData]. LGPD Art. 5 exige identificação de dados pessoais.";
    public override string DescriptionEnUs => "Property with PII name missing [PersonalData] annotation.";
    public override string RemediationGuidancePtBr => "Adicione [PersonalData] à propriedade para facilitar compliance com LGPD (direito ao esquecimento, exportação de dados).";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeProperty, SyntaxKind.PropertyDeclaration);
    }

    private static void AnalyzeProperty(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not PropertyDeclarationSyntax property) return;

        var propName = property.Identifier.Text.ToLowerInvariant();
        if (!PiiPropertyNames.Any(p => propName.Contains(p, StringComparison.Ordinal))) return;

        var hasAnnotation = property.AttributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("PersonalData", StringComparison.Ordinal) ||
                       a.Name.ToString().Contains("SensitiveData", StringComparison.Ordinal));

        if (!hasAnnotation)
        {
            var location = property.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1006"), RuleSeverity.Medium, RulePrecision.Low,
                $"Propriedade '{property.Identifier.Text}' parece conter PII sem anotação [PersonalData].",
                $"Property '{property.Identifier.Text}' appears to contain PII without [PersonalData] annotation.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, property.Identifier.Text),
                [], [359], "A01:2021", ["lgpd", "pii", "annotation"], 0.6));
        }
    }
}
