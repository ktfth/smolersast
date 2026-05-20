using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Cvm;

/// <summary>
/// SMOL1024: Detects regulatory report generation without digital signature.
/// Ref: CVM IN 505 — relatórios regulatórios devem ser assinados digitalmente.
/// </summary>
public sealed class RegulatoryReportWithoutDigitalSignatureRule : SmolerRule
{
    private static readonly string[] ReportMethodNames =
    [
        "generatereport", "gerarrelatorio", "exportreport",
        "submitreport", "enviarrelatorio", "createreport",
        "regulatoryreport", "relatorioregulatorio",
    ];

    public override RuleId Id { get; } = new("SMOL1024");
    public override ImmutableArray<int> CweIds { get; } = [345];
    public override string OwaspCategory => "A08:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["cvm", "signature", "report"];
    public override string DescriptionPtBr => "Relatório regulatório gerado sem assinatura digital. CVM IN 505 exige assinatura em relatórios regulatórios.";
    public override string DescriptionEnUs => "Regulatory report generated without digital signature. CVM IN 505 requires digital signature on regulatory reports.";
    public override string RemediationGuidancePtBr => "Assine relatórios regulatórios com certificado ICP-Brasil (A3/A1) antes de enviar à CVM. Ref: CVM IN 505.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var methodName = method.Identifier.Text.ToLowerInvariant();
        if (!ReportMethodNames.Any(r => methodName.Contains(r, StringComparison.Ordinal))) return;

        var bodyText = method.Body?.ToString().ToLowerInvariant()
                    ?? method.ExpressionBody?.ToString().ToLowerInvariant()
                    ?? "";

        var hasSigning = bodyText.Contains("sign", StringComparison.Ordinal) ||
                         bodyText.Contains("certificate", StringComparison.Ordinal) ||
                         bodyText.Contains("certificado", StringComparison.Ordinal) ||
                         bodyText.Contains("x509", StringComparison.Ordinal) ||
                         bodyText.Contains("icp", StringComparison.Ordinal) ||
                         bodyText.Contains("pkcs", StringComparison.Ordinal);

        if (!hasSigning)
        {
            var location = method.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1024"), RuleSeverity.Medium, RulePrecision.Low,
                $"Relatório regulatório '{method.Identifier.Text}' sem assinatura digital.",
                $"Regulatory report '{method.Identifier.Text}' without digital signature.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
                [], [345], "A08:2021", ["cvm", "signature", "report"], 0.5));
        }
    }
}
