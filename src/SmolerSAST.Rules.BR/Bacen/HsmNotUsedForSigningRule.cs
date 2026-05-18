using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Bacen;

/// <summary>
/// SMOL1009: Detects signing keys loaded from files or configuration instead of HSM/KMS.
/// Ref: Bacen Resolução 4.658/2018 — proteção criptográfica de chaves.
/// </summary>
public sealed class HsmNotUsedForSigningRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL1009");
    public override ImmutableArray<int> CweIds { get; } = [321];
    public override string OwaspCategory => "A02:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["bacen", "hsm", "crypto"];
    public override string DescriptionPtBr => "Chave de assinatura carregada de arquivo ou configuração. Bacen Res. 4.658 requer uso de HSM/KMS para chaves criptográficas.";
    public override string DescriptionEnUs => "Signing key loaded from file or configuration. Bacen Res. 4.658 requires HSM/KMS for cryptographic keys.";
    public override string RemediationGuidancePtBr => "Use Azure Key Vault, AWS KMS, ou HSM físico para gerenciar chaves de assinatura. Ref: Bacen Resolução 4.658/2018 Art. 3.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodText = invocation.Expression.ToString();

        // Detect File.ReadAllBytes/ReadAllText used for key loading
        if (methodText.Contains("ReadAllBytes", StringComparison.Ordinal) ||
            methodText.Contains("ReadAllText", StringComparison.Ordinal))
        {
            // Check if it's in a context involving signing/key
            var parent = invocation.Parent;
            while (parent is not null && parent is not MethodDeclarationSyntax)
            {
                parent = parent.Parent;
            }

            if (parent is MethodDeclarationSyntax method)
            {
                var methodName = method.Identifier.Text.ToLowerInvariant();
                if (methodName.Contains("sign", StringComparison.Ordinal) ||
                    methodName.Contains("key", StringComparison.Ordinal) ||
                    methodName.Contains("cert", StringComparison.Ordinal) ||
                    methodName.Contains("token", StringComparison.Ordinal))
                {
                    var location = invocation.GetLocation();
                    var lineSpan = location.GetLineSpan();
                    context.ReportFinding(new Finding(
                        new RuleId("SMOL1009"), RuleSeverity.High, RulePrecision.Medium,
                        "Chave carregada de arquivo em contexto de assinatura. Use HSM/KMS.",
                        "Key loaded from file in signing context. Use HSM/KMS.",
                        new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                        [], [321], "A02:2021", ["bacen", "hsm", "crypto"], 0.7));
                }
            }
        }
    }
}
