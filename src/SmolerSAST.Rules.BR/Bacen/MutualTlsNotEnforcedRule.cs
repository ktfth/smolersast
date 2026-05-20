using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1010: Detects API endpoints without mutual TLS enforcement.
/// Ref: Bacen Resolução 4.658/2018 Art. 3 — comunicação segura.
/// </summary>
public sealed class MutualTlsNotEnforcedRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL1010");
    public override ImmutableArray<int> CweIds { get; } = [295];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "mtls", "openfinance"];
    public override string DescriptionPtBr => "Configuração de Kestrel/HttpClient sem mutual TLS (certificado de cliente). Bacen Res. 4.658 exige mTLS para APIs financeiras.";
    public override string DescriptionEnUs => "Kestrel/HttpClient configuration without mutual TLS (client certificate). Bacen Res. 4.658 requires mTLS for financial APIs.";
    public override string RemediationGuidancePtBr => "Configure ClientCertificateMode = RequireCertificate em Kestrel ou valide certificados de cliente em middleware. Ref: Bacen Res. 4.658 Art. 3.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();

        // Detect ClientCertificateMode = NoCertificate
        if (left.EndsWith("ClientCertificateMode", StringComparison.Ordinal))
        {
            var right = assignment.Right.ToString();
            if (right.Contains("NoCertificate", StringComparison.Ordinal) ||
                right.Contains("DelayCertificate", StringComparison.Ordinal))
            {
                ReportFinding(context, assignment);
            }
        }

        // Detect ServerCertificateCustomValidationCallback = DangerousAcceptAny
        if (left.EndsWith("ServerCertificateCustomValidationCallback", StringComparison.Ordinal))
        {
            var right = assignment.Right.ToString();
            if (right.Contains("DangerousAcceptAny", StringComparison.Ordinal) ||
                right.Contains("=> true", StringComparison.Ordinal) ||
                right.Contains("delegate { return true", StringComparison.Ordinal))
            {
                ReportFinding(context, assignment);
            }
        }
    }

    private static void ReportFinding(SyntaxNodeAnalysisContext context, AssignmentExpressionSyntax assignment)
    {
        var location = assignment.GetLocation();
        var lineSpan = location.GetLineSpan();
        context.ReportFinding(new Finding(
            new RuleId("SMOL1010"), RuleSeverity.High, RulePrecision.Low,
            $"mTLS não enforçado: {assignment.Left}. Bacen Res. 4.658 exige certificado de cliente.",
            $"mTLS not enforced: {assignment.Left}. Bacen Res. 4.658 requires client certificate.",
            new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
            [], [295], "A07:2021", ["bacen", "mtls", "openfinance"], 0.7));
    }
}
