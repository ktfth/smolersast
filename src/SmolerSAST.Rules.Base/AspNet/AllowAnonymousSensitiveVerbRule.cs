using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0025: Detects [AllowAnonymous] on controllers/actions with sensitive HTTP verbs (POST, PUT, DELETE, PATCH).
/// </summary>
public sealed class AllowAnonymousSensitiveVerbRule : SmolerRule
{
    private static readonly HashSet<string> SensitiveVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "HttpPost", "HttpPut", "HttpDelete", "HttpPatch",
    };

    public override RuleId Id { get; } = new("SMOL0025");
    public override ImmutableArray<int> CweIds { get; } = [862];
    public override string OwaspCategory => "A01:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "authorization"];
    public override string DescriptionPtBr => "[AllowAnonymous] detectado em endpoint com verbo sensível (POST/PUT/DELETE/PATCH). Endpoints que modificam dados devem exigir autenticação.";
    public override string DescriptionEnUs => "[AllowAnonymous] detected on endpoint with sensitive HTTP verb (POST/PUT/DELETE/PATCH).";
    public override string RemediationGuidancePtBr => "Remova [AllowAnonymous] ou adicione validação de autorização explícita no corpo do método.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var hasAllowAnonymous = false;
        var hasSensitiveVerb = false;

        foreach (var attrList in method.AttributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();
                if (name.Contains("AllowAnonymous", StringComparison.Ordinal))
                    hasAllowAnonymous = true;
                if (SensitiveVerbs.Any(v => name.Contains(v, StringComparison.OrdinalIgnoreCase)))
                    hasSensitiveVerb = true;
            }
        }

        if (hasAllowAnonymous && hasSensitiveVerb)
        {
            ReportFinding(context, method);
        }
    }

    private static void ReportFinding(SyntaxNodeAnalysisContext context, MethodDeclarationSyntax method)
    {
        var location = method.Identifier.GetLocation();
        var lineSpan = location.GetLineSpan();
        context.ReportFinding(new Finding(
            new RuleId("SMOL0025"), RuleSeverity.High, RulePrecision.Medium,
            $"[AllowAnonymous] em método '{method.Identifier.Text}' com verbo HTTP sensível.",
            $"[AllowAnonymous] on method '{method.Identifier.Text}' with sensitive HTTP verb.",
            new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
            [], [862], "A01:2021", ["aspnet", "authorization"], 0.85));
    }
}
