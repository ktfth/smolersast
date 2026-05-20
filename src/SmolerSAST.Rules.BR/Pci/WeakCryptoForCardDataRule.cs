using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Pci;

/// <summary>
/// SMOL1019: Detects card data encryption with algorithms weaker than AES-256.
/// Ref: PCI-DSS Req. 3.5 — Document and implement procedures to protect keys used to secure stored cardholder data.
/// </summary>
public sealed class WeakCryptoForCardDataRule : SmolerRule
{
    private static readonly string[] CardContextNames =
    [
        "card", "pan", "cartao", "payment", "pagamento",
        "cardholder", "portador",
    ];

    private static readonly string[] WeakAlgorithms =
    [
        "DES", "TripleDES", "3DES", "RC2", "RC4", "Blowfish",
        "RijndaelManaged",
    ];

    public override RuleId Id { get; } = new("SMOL1019");
    public override ImmutableArray<int> CweIds { get; } = [327];
    public override string OwaspCategory => "A02:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["pci-dss", "crypto", "card"];
    public override string DescriptionPtBr => "Dados de cartão cifrados com algoritmo fraco (< AES-256). PCI-DSS Req. 3.5 exige criptografia forte.";
    public override string DescriptionEnUs => "Card data encrypted with weak algorithm (< AES-256). PCI-DSS Req. 3.5 requires strong cryptography.";
    public override string RemediationGuidancePtBr => "Use AES-256-GCM ou AES-256-CBC para cifrar dados de cartão. Nunca use DES, 3DES, ou RC4. Ref: PCI-DSS Req. 3.5.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, SyntaxKind.ObjectCreationExpression);
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation) return;

        var typeName = creation.Type.ToString();
        if (!WeakAlgorithms.Any(a => typeName.Contains(a, StringComparison.OrdinalIgnoreCase))) return;

        // Check if usage is in a card-data context
        var parentMethod = creation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (parentMethod is null) return;

        var methodContext = parentMethod.Identifier.Text.ToLowerInvariant();
        var bodyText = parentMethod.Body?.ToString().ToLowerInvariant() ?? "";

        var isCardContext = CardContextNames.Any(c =>
            methodContext.Contains(c, StringComparison.Ordinal) ||
            bodyText.Contains(c, StringComparison.Ordinal));

        if (isCardContext)
        {
            var location = creation.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1019"), RuleSeverity.Critical, RulePrecision.Medium,
                $"Algoritmo fraco ({typeName}) usado para dados de cartão. PCI-DSS Req. 3.5.",
                $"Weak algorithm ({typeName}) used for card data. PCI-DSS Req. 3.5.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, creation.ToString()),
                [], [327], "A02:2021", ["pci-dss", "crypto", "card"], 0.8));
        }
    }
}
