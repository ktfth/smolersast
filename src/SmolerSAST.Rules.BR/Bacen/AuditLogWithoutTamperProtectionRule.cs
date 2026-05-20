using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1011: Detects audit logging without tamper protection (HMAC/hash chain).
/// Ref: Bacen Resolução 4.658/2018 Art. 12 — rastreabilidade de ações.
/// </summary>
public sealed class AuditLogWithoutTamperProtectionRule : SmolerRule
{
    private static readonly string[] AuditMethodNames =
    [
        "audit", "auditlog", "logaudit", "registrarauditoria",
        "writeaudit", "addauditentry", "addauditlog", "logactivity",
    ];

    public override RuleId Id { get; } = new("SMOL1011");
    public override ImmutableArray<int> CweIds { get; } = [117];
    public override string OwaspCategory => "A09:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "audit", "integrity"];
    public override string DescriptionPtBr => "Log de auditoria sem proteção contra adulteração (HMAC/hash chain). Bacen Res. 4.658 Art. 12 exige rastreabilidade íntegra.";
    public override string DescriptionEnUs => "Audit log without tamper protection (HMAC/hash chain). Bacen Res. 4.658 Art. 12 requires integrity of audit trails.";
    public override string RemediationGuidancePtBr => "Implemente HMAC ou hash chain nos registros de auditoria. Cada entry deve referenciar o hash da anterior. Ref: Bacen Res. 4.658 Art. 12.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var methodName = method.Identifier.Text.ToLowerInvariant();
        if (!AuditMethodNames.Any(a => methodName.Contains(a, StringComparison.Ordinal))) return;

        // Check if method body contains HMAC/hash integrity references
        var bodyText = method.Body?.ToString().ToLowerInvariant()
                    ?? method.ExpressionBody?.ToString().ToLowerInvariant()
                    ?? "";

        if (bodyText.Contains("hmac", StringComparison.Ordinal) ||
            bodyText.Contains("hashchain", StringComparison.Ordinal) ||
            bodyText.Contains("hash_chain", StringComparison.Ordinal) ||
            bodyText.Contains("computehash", StringComparison.Ordinal) ||
            bodyText.Contains("signature", StringComparison.Ordinal) ||
            bodyText.Contains("tamper", StringComparison.Ordinal)) return;

        var location = method.Identifier.GetLocation();
        var lineSpan = location.GetLineSpan();
        context.ReportFinding(new Finding(
            new RuleId("SMOL1011"), RuleSeverity.High, RulePrecision.Low,
            $"Método de auditoria '{method.Identifier.Text}' sem proteção contra adulteração.",
            $"Audit method '{method.Identifier.Text}' without tamper protection.",
            new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
            [], [117], "A09:2021", ["bacen", "audit", "integrity"], 0.55));
    }
}
