using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1007: Detects JWT validation without audience, issuer, or expiry validation.
/// Ref: Bacen Resolução 4.658/2018, FAPI 1.0.
/// </summary>
public sealed class JwtValidationIncompleteRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL1007");
    public override ImmutableArray<int> CweIds { get; } = [287];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "jwt", "fapi"];
    public override string DescriptionPtBr => "Validação JWT incompleta: ValidateAudience, ValidateIssuer ou ValidateLifetime desabilitado. Obrigatório para FAPI 1.0 (Bacen Res. 4.658).";
    public override string DescriptionEnUs => "Incomplete JWT validation: ValidateAudience, ValidateIssuer, or ValidateLifetime disabled. Required for FAPI 1.0.";
    public override string RemediationGuidancePtBr => "Configure TokenValidationParameters com ValidateAudience = true, ValidateIssuer = true, ValidateLifetime = true. Ref: Bacen Resolução 4.658/2018.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();
        var isJwtValidation = left.EndsWith("ValidateAudience", StringComparison.Ordinal) ||
                              left.EndsWith("ValidateIssuer", StringComparison.Ordinal) ||
                              left.EndsWith("ValidateLifetime", StringComparison.Ordinal) ||
                              left.EndsWith("ValidateIssuerSigningKey", StringComparison.Ordinal);

        if (!isJwtValidation) return;

        if (assignment.Right is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.FalseLiteralExpression))
        {
            var location = assignment.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1007"), RuleSeverity.Critical, RulePrecision.Medium,
                $"{left} = false. Validação JWT incompleta viola Bacen Res. 4.658/FAPI 1.0.",
                $"{left} = false. Incomplete JWT validation violates Bacen Res. 4.658/FAPI 1.0.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
                [], [287], "A07:2021", ["bacen", "jwt", "fapi"], 0.9));
        }
    }
}
