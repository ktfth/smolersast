using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Lgpd;

/// <summary>
/// SMOL1004: Detects PII stored in cache without encryption.
/// Ref: LGPD Art. 46 — medidas técnicas para proteção de dados pessoais.
/// </summary>
public sealed class PiiInCacheWithoutEncryptionRule : SmolerRule
{
    private static readonly string[] PiiFieldNames =
    [
        "cpf", "cnpj", "rg", "email", "telefone", "phone",
        "nome", "name", "documento", "identidade", "pii", "personal",
    ];

    private static readonly string[] CacheMethods =
    [
        "Set", "SetString", "SetAsync", "SetStringAsync",
        "Add", "Put", "Insert", "Store",
    ];

    public override RuleId Id { get; } = new("SMOL1004");
    public override ImmutableArray<int> CweIds { get; } = [312];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Low;
    public override ImmutableArray<string> Tags { get; } = ["lgpd", "pii", "cache", "encryption"];
    public override string DescriptionPtBr => "PII armazenado em cache sem evidência de cifragem. LGPD Art. 46 exige proteção técnica de dados pessoais.";
    public override string DescriptionEnUs => "PII stored in cache without encryption evidence. LGPD Art. 46 requires technical protection of personal data.";
    public override string RemediationGuidancePtBr => "Cifre dados pessoais antes de armazenar em cache (IDistributedCache, MemoryCache). Use IDataProtector ou AES-256.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            _ => null,
        };

        if (methodName is null || !CacheMethods.Any(m => m.Equals(methodName, StringComparison.OrdinalIgnoreCase))) return;

        // Check receiver looks like a cache
        var receiver = invocation.Expression is MemberAccessExpressionSyntax memberAccess
            ? memberAccess.Expression.ToString().ToLowerInvariant()
            : "";

        if (!receiver.Contains("cache", StringComparison.Ordinal)) return;

        // Check arguments for PII references
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            var argText = arg.ToString().ToLowerInvariant();
            var matchedPii = PiiFieldNames.FirstOrDefault(p => argText.Contains(p, StringComparison.Ordinal));
            if (matchedPii is not null)
            {
                // Check if encryption/protect methods are visible in the same statement or nearby
                var parentBlock = invocation.Ancestors().OfType<BlockSyntax>().FirstOrDefault();
                var blockText = parentBlock?.ToString().ToLowerInvariant() ?? "";
                if (blockText.Contains("encrypt", StringComparison.Ordinal) ||
                    blockText.Contains("protect", StringComparison.Ordinal) ||
                    blockText.Contains("cipher", StringComparison.Ordinal)) return;

                var location = invocation.GetLocation();
                var lineSpan = location.GetLineSpan();
                context.ReportFinding(new Finding(
                    new RuleId("SMOL1004"), RuleSeverity.High, RulePrecision.Low,
                    $"PII ({matchedPii}) armazenado em cache sem cifragem. LGPD Art. 46.",
                    $"PII ({matchedPii}) stored in cache without encryption.",
                    new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                    [], [312], "A04:2021", ["lgpd", "pii", "cache", "encryption"], 0.65));
                break;
            }
        }
    }
}
