using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Pci;

/// <summary>
/// SMOL1021: Detects administrative access endpoints without MFA enforcement.
/// Ref: PCI-DSS Req. 8.3 — Secure all individual non-console administrative access with MFA.
/// </summary>
public sealed class AdminWithoutMfaRule : SmolerRule
{
    private static readonly string[] AdminMethodNames =
    [
        "admin", "backoffice", "manage", "dashboard",
        "superuser", "root", "sistema", "painel",
    ];

    public override RuleId Id { get; } = new("SMOL1021");
    public override ImmutableArray<int> CweIds { get; } = [308];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["pci-dss", "mfa", "admin"];
    public override string DescriptionPtBr => "Acesso administrativo sem enforcement de MFA. PCI-DSS Req. 8.3 exige MFA para acesso administrativo não-console.";
    public override string DescriptionEnUs => "Administrative access without MFA enforcement. PCI-DSS Req. 8.3 requires MFA for non-console admin access.";
    public override string RemediationGuidancePtBr => "Implemente MFA (TOTP, FIDO2, SMS) para todos os endpoints administrativos. Use [Authorize(Policy = \"RequireMfa\")].";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeClass, SyntaxKind.ClassDeclaration);
    }

    private static void AnalyzeClass(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ClassDeclarationSyntax classDecl) return;

        var className = classDecl.Identifier.Text.ToLowerInvariant();
        if (!AdminMethodNames.Any(a => className.Contains(a, StringComparison.Ordinal))) return;

        // Check if class has Controller suffix (ASP.NET pattern)
        if (!classDecl.Identifier.Text.EndsWith("Controller", StringComparison.Ordinal)) return;

        // Check for MFA-related attributes or policy
        var attrText = classDecl.AttributeLists.ToString().ToLowerInvariant();
        var hasMfa = attrText.Contains("mfa", StringComparison.Ordinal) ||
                     attrText.Contains("twofactor", StringComparison.Ordinal) ||
                     attrText.Contains("multifactor", StringComparison.Ordinal) ||
                     attrText.Contains("requiremfa", StringComparison.Ordinal);

        if (!hasMfa)
        {
            var location = classDecl.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1021"), RuleSeverity.High, RulePrecision.Low,
                $"Controller administrativo '{classDecl.Identifier.Text}' sem enforcement de MFA.",
                $"Admin controller '{classDecl.Identifier.Text}' without MFA enforcement.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, classDecl.Identifier.Text),
                [], [308], "A07:2021", ["pci-dss", "mfa", "admin"], 0.5));
        }
    }
}
