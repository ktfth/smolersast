using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Cvm;

/// <summary>
/// SMOL1012: Detects privileged actions (cancel, refund, admin override) without dual control evidence.
/// Ref: CVM Resolução 35 — controle dual para operações privilegiadas.
/// </summary>
public sealed class PrivilegedActionWithoutDualControlRule : SmolerRule
{
    private static readonly string[] PrivilegedActions =
    [
        "cancel", "refund", "reverse", "override", "approve", "delete",
        "remove", "admin", "escalate", "revoke", "estorno", "cancelar",
        "reverter", "aprovar", "excluir",
    ];

    public override RuleId Id { get; } = new("SMOL1012");
    public override ImmutableArray<int> CweIds { get; } = [271];
    public override string OwaspCategory => "A01:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["cvm", "dual-control", "audit"];
    public override string DescriptionPtBr => "Ação privilegiada sem evidência de controle dual. CVM Resolução 35 exige aprovação dupla para operações críticas.";
    public override string DescriptionEnUs => "Privileged action without dual control evidence. CVM Resolution 35 requires dual approval for critical operations.";
    public override string RemediationGuidancePtBr => "Implemente fluxo de aprovação dupla (maker-checker) para operações de cancelamento, estorno e override administrativo. Ref: CVM Resolução 35.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var methodName = method.Identifier.Text.ToLowerInvariant();
        if (!PrivilegedActions.Any(a => methodName.Contains(a, StringComparison.Ordinal))) return;

        // Check if method has dual-control related parameters or checks
        var hasDualControl = method.ParameterList.Parameters
            .Any(p => p.Identifier.Text.ToLowerInvariant() is var name &&
                      (name.Contains("approver", StringComparison.Ordinal) ||
                       name.Contains("authorizer", StringComparison.Ordinal) ||
                       name.Contains("checker", StringComparison.Ordinal) ||
                       name.Contains("approval", StringComparison.Ordinal)));

        if (!hasDualControl)
        {
            var location = method.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1012"), RuleSeverity.High, RulePrecision.Low,
                $"Método privilegiado '{method.Identifier.Text}' sem parâmetro de controle dual.",
                $"Privileged method '{method.Identifier.Text}' without dual control parameter.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
                [], [271], "A01:2021", ["cvm", "dual-control", "audit"], 0.5));
        }
    }
}
