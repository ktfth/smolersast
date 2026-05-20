using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Pci;

/// <summary>
/// SMOL1020: Detects card data transmitted without TLS 1.2+.
/// Ref: PCI-DSS Req. 4.1 — Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission.
/// </summary>
public sealed class CardDataWithoutTlsRule : SmolerRule
{
    private static readonly string[] CardContextNames =
    [
        "card", "pan", "cartao", "payment", "pagamento",
        "cardholder", "portador", "checkout",
    ];

    public override RuleId Id { get; } = new("SMOL1020");
    public override ImmutableArray<int> CweIds { get; } = [319];
    public override string OwaspCategory => "A02:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["pci-dss", "tls", "card"];
    public override string DescriptionPtBr => "Dados de cartão transmitidos via HTTP (sem TLS). PCI-DSS Req. 4.1 exige TLS 1.2+ para dados de portador.";
    public override string DescriptionEnUs => "Card data transmitted over HTTP (no TLS). PCI-DSS Req. 4.1 requires TLS 1.2+ for cardholder data.";
    public override string RemediationGuidancePtBr => "Use apenas HTTPS (TLS 1.2+) para transmitir dados de cartão. Nunca use HTTP plaintext para dados de portador.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeStringLiteral, SyntaxKind.StringLiteralExpression);
    }

    private static void AnalyzeStringLiteral(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not LiteralExpressionSyntax literal) return;

        var text = literal.Token.ValueText.ToLowerInvariant();

        // Only flag http:// URLs (not https://)
        if (!text.StartsWith("http://", StringComparison.Ordinal)) return;

        // Check if it's in a card-data context
        var parentMethod = literal.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (parentMethod is null) return;

        var methodName = parentMethod.Identifier.Text.ToLowerInvariant();
        var isCardContext = CardContextNames.Any(c => methodName.Contains(c, StringComparison.Ordinal));

        if (!isCardContext)
        {
            // Check surrounding code
            var bodyText = parentMethod.Body?.ToString().ToLowerInvariant() ?? "";
            isCardContext = CardContextNames.Any(c => bodyText.Contains(c, StringComparison.Ordinal));
        }

        if (isCardContext)
        {
            var location = literal.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1020"), RuleSeverity.Critical, RulePrecision.Medium,
                "URL HTTP em contexto de dados de cartão. PCI-DSS Req. 4.1 exige TLS 1.2+.",
                "HTTP URL in card data context. PCI-DSS Req. 4.1 requires TLS 1.2+.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, literal.ToString()),
                [], [319], "A02:2021", ["pci-dss", "tls", "card"], 0.8));
        }
    }
}
