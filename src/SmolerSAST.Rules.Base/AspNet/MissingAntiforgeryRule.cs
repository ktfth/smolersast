using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0026: Detects POST endpoints missing [ValidateAntiForgeryToken] attribute.
/// </summary>
public sealed class MissingAntiforgeryRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0026");
    public override ImmutableArray<int> CweIds { get; } = [352];
    public override string OwaspCategory => "A01:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "csrf"];
    public override string DescriptionPtBr => "Endpoint POST sem [ValidateAntiForgeryToken]. Vulnerável a CSRF.";
    public override string DescriptionEnUs => "POST endpoint missing [ValidateAntiForgeryToken]. Vulnerable to CSRF.";
    public override string RemediationGuidancePtBr => "Adicione [ValidateAntiForgeryToken] ao método ou [AutoValidateAntiforgeryToken] ao controller.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;

        var hasHttpPost = false;
        var hasAntiforgery = false;

        foreach (var attrList in method.AttributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();
                if (name.Contains("HttpPost", StringComparison.Ordinal)) hasHttpPost = true;
                if (name.Contains("ValidateAntiForgeryToken", StringComparison.Ordinal) ||
                    name.Contains("AutoValidateAntiforgeryToken", StringComparison.Ordinal) ||
                    name.Contains("IgnoreAntiforgeryToken", StringComparison.Ordinal))
                    hasAntiforgery = true;
            }
        }

        // Check class-level attributes too
        if (hasHttpPost && !hasAntiforgery && method.Parent is ClassDeclarationSyntax cls)
        {
            foreach (var attrList in cls.AttributeLists)
            {
                foreach (var attr in attrList.Attributes)
                {
                    var name = attr.Name.ToString();
                    if (name.Contains("ValidateAntiForgeryToken", StringComparison.Ordinal) ||
                        name.Contains("AutoValidateAntiforgeryToken", StringComparison.Ordinal))
                        hasAntiforgery = true;
                }
            }
        }

        if (hasHttpPost && !hasAntiforgery)
        {
            var location = method.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL0026"), RuleSeverity.High, RulePrecision.Medium,
                $"Endpoint POST '{method.Identifier.Text}' sem proteção anti-CSRF.",
                $"POST endpoint '{method.Identifier.Text}' missing anti-CSRF protection.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, method.Identifier.Text),
                [], [352], "A01:2021", ["aspnet", "csrf"], 0.8));
        }
    }
}
