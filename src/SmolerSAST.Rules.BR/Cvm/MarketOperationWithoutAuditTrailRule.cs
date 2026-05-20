using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Cvm;

/// <summary>
/// SMOL1022: Detects market operations without audit trail logging.
/// Ref: CVM Resolução 35 — rastreabilidade de operações de mercado.
/// </summary>
public sealed class MarketOperationWithoutAuditTrailRule : SmolerRule
{
    private static readonly string[] MarketOperations =
    [
        "placeorder", "executeorder", "cancelorder", "modifyorder",
        "executartrade", "negociar", "liquidar", "settle",
        "allocate", "alocar", "match", "book",
    ];

    private static readonly string[] AuditIndicators =
    [
        "audit", "log", "trail", "track", "registrar", "evento",
    ];

    public override RuleId Id { get; } = new("SMOL1022");
    public override ImmutableArray<int> CweIds { get; } = [778];
    public override string OwaspCategory => "A09:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["cvm", "audit", "market"];
    public override string DescriptionPtBr => "Operação de mercado sem trilha de auditoria. CVM Res. 35 exige rastreabilidade completa de operações.";
    public override string DescriptionEnUs => "Market operation without audit trail. CVM Res. 35 requires complete operation traceability.";
    public override string RemediationGuidancePtBr => "Registre todas as operações de mercado com timestamp, usuário, ação, parâmetros e resultado. Ref: CVM Resolução 35.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var methodName = method.Identifier.Text.ToLowerInvariant();
        if (!MarketOperations.Any(op => methodName.Contains(op, StringComparison.Ordinal))) return;

        var bodyText = method.Body?.ToString().ToLowerInvariant()
                    ?? method.ExpressionBody?.ToString().ToLowerInvariant()
                    ?? "";

        var hasAudit = AuditIndicators.Any(a => bodyText.Contains(a, StringComparison.Ordinal));

        if (!hasAudit)
        {
            var location = method.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1022"), RuleSeverity.High, RulePrecision.Low,
                $"Operação de mercado '{method.Identifier.Text}' sem trilha de auditoria.",
                $"Market operation '{method.Identifier.Text}' without audit trail.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
                [], [778], "A09:2021", ["cvm", "audit", "market"], 0.5));
        }
    }
}
