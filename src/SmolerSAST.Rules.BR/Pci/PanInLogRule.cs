using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Pci;

/// <summary>
/// SMOL1017: Detects Primary Account Number (PAN) in log statements without masking.
/// Ref: PCI-DSS Req. 3.4 — Render PAN unreadable anywhere it is stored.
/// </summary>
public sealed class PanInLogRule : SmolerRule
{
    private static readonly string[] PanFieldNames =
    [
        "pan", "cardnumber", "card_number", "numerocartao", "numero_cartao",
        "primaryaccountnumber", "accountnumber", "account_number",
        "creditcard", "credit_card", "debitcard", "debit_card",
    ];

    private static readonly string[] LogMethods =
    [
        "Log", "LogInformation", "LogWarning", "LogError", "LogDebug", "LogTrace",
        "Info", "Warn", "Error", "Debug", "Write", "WriteLine",
    ];

    public override RuleId Id { get; } = new("SMOL1017");
    public override ImmutableArray<int> CweIds { get; } = [532];
    public override string OwaspCategory => "A09:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["pci-dss", "pan", "logging"];
    public override string DescriptionPtBr => "PAN (número de cartão) detectado em log sem mascaramento. PCI-DSS Req. 3.4 exige que PAN seja ilegível.";
    public override string DescriptionEnUs => "PAN (card number) detected in log without masking. PCI-DSS Req. 3.4 requires PAN to be rendered unreadable.";
    public override string RemediationGuidancePtBr => "Mascare PAN exibindo apenas primeiros 6 e últimos 4 dígitos (BIN + last4). Nunca logue número completo. Ref: PCI-DSS Req. 3.4.";

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

            // Check if masking is applied
            if (argText.Contains("mask", StringComparison.Ordinal) ||
                argText.Contains("redact", StringComparison.Ordinal) ||
                argText.Contains("last4", StringComparison.Ordinal) ||
                argText.Contains("truncat", StringComparison.Ordinal)) continue;

            var matched = PanFieldNames.FirstOrDefault(p => argText.Contains(p, StringComparison.Ordinal));
            if (matched is not null)
            {
                var location = invocation.GetLocation();
                var lineSpan = location.GetLineSpan();
                context.ReportFinding(new Finding(
                    new RuleId("SMOL1017"), RuleSeverity.Critical, RulePrecision.Medium,
                    $"PAN ({matched}) em log sem mascaramento. PCI-DSS Req. 3.4.",
                    $"PAN ({matched}) in log without masking. PCI-DSS Req. 3.4.",
                    new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                    [], [532], "A09:2021", ["pci-dss", "pan", "logging"], 0.85));
                break;
            }
        }
    }
}
