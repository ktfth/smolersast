using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Configuration;

/// <summary>
/// SMOL0036: Detects HttpClient with ServerCertificateCustomValidationCallback that always returns true.
/// </summary>
public sealed class InsecureHttpClientRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0036");
    public override ImmutableArray<int> CweIds { get; } = [295];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.High;
    public override ImmutableArray<string> Tags { get; } = ["http", "tls", "certificate"];
    public override string DescriptionPtBr => "Validação de certificado TLS desabilitada. ServerCertificateCustomValidationCallback retorna true incondicionalmente.";
    public override string DescriptionEnUs => "TLS certificate validation disabled. ServerCertificateCustomValidationCallback returns true unconditionally.";
    public override string RemediationGuidancePtBr => "Remova o callback ou implemente validação de certificado adequada. Nunca desabilite validação TLS em produção.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();
        if (!left.Contains("ServerCertificateCustomValidationCallback", StringComparison.Ordinal) &&
            !left.Contains("DangerousAcceptAnyServerCertificateValidator", StringComparison.Ordinal))
            return;

        // Check if RHS is a lambda that returns true, or DangerousAcceptAny...
        var right = assignment.Right.ToString();
        if (right.Contains("=> true", StringComparison.Ordinal) ||
            right.Contains("DangerousAcceptAny", StringComparison.Ordinal) ||
            right.Contains("return true", StringComparison.Ordinal))
        {
            var location = assignment.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0036"), RuleSeverity.Critical, RulePrecision.High,
                "Validação de certificado TLS desabilitada — aceita qualquer certificado.",
                "TLS certificate validation disabled — accepts any certificate.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
                [], [295], "A07:2021", ["http", "tls", "certificate"], 1.0));
        }
    }
}
