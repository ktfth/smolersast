using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1016: Detects financial operation endpoints without idempotency key parameter.
/// Ref: Open Finance Brasil — APIs de pagamento devem ser idempotentes.
/// </summary>
public sealed class FinancialOperationWithoutIdempotencyRule : SmolerRule
{
    private static readonly string[] FinancialMethodNames =
    [
        "transfer", "payment", "pix", "ted", "doc", "boleto",
        "debit", "credit", "charge", "refund", "withdraw",
        "transferir", "pagar", "cobrar", "estornar", "sacar",
    ];

    public override RuleId Id { get; } = new("SMOL1016");
    public override ImmutableArray<int> CweIds { get; } = [352];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "idempotency", "openfinance"];
    public override string DescriptionPtBr => "Operação financeira sem parâmetro de idempotência. Open Finance Brasil exige idempotency key em APIs de pagamento.";
    public override string DescriptionEnUs => "Financial operation without idempotency parameter. Open Finance Brasil requires idempotency key in payment APIs.";
    public override string RemediationGuidancePtBr => "Adicione parâmetro X-Idempotency-Key ou idempotencyKey ao método. Armazene e valide chaves para evitar duplicação.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var methodName = method.Identifier.Text.ToLowerInvariant();
        if (!FinancialMethodNames.Any(f => methodName.Contains(f, StringComparison.Ordinal))) return;

        // Check if method has idempotency-related parameter
        var hasIdempotency = method.ParameterList.Parameters
            .Any(p =>
            {
                var paramName = p.Identifier.Text.ToLowerInvariant();
                return paramName.Contains("idempoten", StringComparison.Ordinal) ||
                       paramName.Contains("requestid", StringComparison.Ordinal) ||
                       paramName.Contains("correlationid", StringComparison.Ordinal);
            });

        // Also check attributes for [FromHeader] with idempotency
        if (!hasIdempotency)
        {
            var attrText = method.AttributeLists.ToString().ToLowerInvariant();
            hasIdempotency = attrText.Contains("idempoten", StringComparison.Ordinal);
        }

        if (!hasIdempotency)
        {
            var location = method.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1016"), RuleSeverity.High, RulePrecision.Low,
                $"Método financeiro '{method.Identifier.Text}' sem parâmetro de idempotência.",
                $"Financial method '{method.Identifier.Text}' without idempotency parameter.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
                [], [352], "A04:2021", ["bacen", "idempotency", "openfinance"], 0.55));
        }
    }
}
