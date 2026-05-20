using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Cvm;

/// <summary>
/// SMOL1023: Detects market data (quotes, orders) processed without integrity validation.
/// Ref: CVM Resolução 35 — integridade de dados de mercado.
/// </summary>
public sealed class DataIntegrityWithoutValidationRule : SmolerRule
{
    private static readonly string[] MarketDataTypes =
    [
        "quote", "cotacao", "order", "ordem", "trade", "negocio",
        "tick", "marketdata", "bookentry", "oferta",
    ];

    public override RuleId Id { get; } = new("SMOL1023");
    public override ImmutableArray<int> CweIds { get; } = [345];
    public override string OwaspCategory => "A08:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["cvm", "integrity", "market"];
    public override string DescriptionPtBr => "Dados de mercado processados sem validação de integridade (checksum/assinatura). CVM Res. 35.";
    public override string DescriptionEnUs => "Market data processed without integrity validation (checksum/signature). CVM Res. 35.";
    public override string RemediationGuidancePtBr => "Valide integridade de dados de mercado via HMAC, assinatura digital ou checksum antes de processar. Ref: CVM Res. 35.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var methodName = method.Identifier.Text.ToLowerInvariant();

        // Look for methods that process market data
        if (!methodName.StartsWith("process", StringComparison.Ordinal) &&
            !methodName.StartsWith("handle", StringComparison.Ordinal) &&
            !methodName.StartsWith("consume", StringComparison.Ordinal) &&
            !methodName.StartsWith("receive", StringComparison.Ordinal)) return;

        var hasMarketContext = MarketDataTypes.Any(t => methodName.Contains(t, StringComparison.Ordinal));
        if (!hasMarketContext)
        {
            // Check parameters
            var paramsText = method.ParameterList.ToString().ToLowerInvariant();
            hasMarketContext = MarketDataTypes.Any(t => paramsText.Contains(t, StringComparison.Ordinal));
        }

        if (!hasMarketContext) return;

        var bodyText = method.Body?.ToString().ToLowerInvariant() ?? "";

        var hasIntegrityCheck = bodyText.Contains("checksum", StringComparison.Ordinal) ||
                                bodyText.Contains("hash", StringComparison.Ordinal) ||
                                bodyText.Contains("verify", StringComparison.Ordinal) ||
                                bodyText.Contains("signature", StringComparison.Ordinal) ||
                                bodyText.Contains("hmac", StringComparison.Ordinal) ||
                                bodyText.Contains("integrity", StringComparison.Ordinal);

        if (!hasIntegrityCheck)
        {
            var location = method.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1023"), RuleSeverity.High, RulePrecision.Low,
                $"Método '{method.Identifier.Text}' processa dados de mercado sem validação de integridade.",
                $"Method '{method.Identifier.Text}' processes market data without integrity validation.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
                [], [345], "A08:2021", ["cvm", "integrity", "market"], 0.5));
        }
    }
}
