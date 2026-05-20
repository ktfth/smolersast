using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1013: Detects OAuth/OIDC configuration without PKCE in public client flows.
/// Ref: Open Finance Brasil FAPI 1.0 — PKCE obrigatório.
/// </summary>
public sealed class OAuthWithoutPkceRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL1013");
    public override ImmutableArray<int> CweIds { get; } = [287];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "oauth", "pkce", "openfinance"];
    public override string DescriptionPtBr => "Configuração OAuth sem PKCE. Open Finance Brasil FAPI 1.0 exige PKCE em fluxos de autorização.";
    public override string DescriptionEnUs => "OAuth configuration without PKCE. Open Finance Brasil FAPI 1.0 requires PKCE in authorization flows.";
    public override string RemediationGuidancePtBr => "Configure UsePkce = true em OpenIdConnectOptions ou envie code_challenge + code_verifier no fluxo OAuth. Ref: FAPI 1.0.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;

        var left = assignment.Left.ToString();

        // Detect UsePkce = false
        if (left.EndsWith("UsePkce", StringComparison.Ordinal) &&
            assignment.Right is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.FalseLiteralExpression))
        {
            var location = assignment.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1013"), RuleSeverity.Critical, RulePrecision.Medium,
                "UsePkce = false. PKCE obrigatório para Open Finance Brasil FAPI 1.0.",
                "UsePkce = false. PKCE required for Open Finance Brasil FAPI 1.0.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, assignment.ToString()),
                [], [287], "A07:2021", ["bacen", "oauth", "pkce", "openfinance"], 0.9));
        }
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            _ => null,
        };

        // Detect AddOpenIdConnect without PKCE configuration
        if (methodName is not "AddOpenIdConnect") return;

        // Check if the lambda/delegate argument contains UsePkce
        var argsText = invocation.ArgumentList.ToString();
        if (!argsText.Contains("UsePkce", StringComparison.Ordinal))
        {
            var location = invocation.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1013"), RuleSeverity.Critical, RulePrecision.Medium,
                "AddOpenIdConnect sem configuração PKCE. Obrigatório para Open Finance Brasil.",
                "AddOpenIdConnect without PKCE configuration. Required for Open Finance Brasil.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                [], [287], "A07:2021", ["bacen", "oauth", "pkce", "openfinance"], 0.7));
        }
    }
}
