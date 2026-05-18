using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0018: Detects assignment of CipherMode.ECB.
/// ECB mode encrypts identical plaintext blocks to identical ciphertext blocks,
/// leaking patterns in the data — CWE-327.
/// </summary>
public sealed class EcbCipherModeRule : SmolerRule
{
    private const string CipherModeFullName = "System.Security.Cryptography.CipherMode";

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0018");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [327];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "ecb-mode"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso do modo de cifra ECB detectado. " +
        "ECB cifra blocos idênticos de texto em blocos idênticos de cifra, vazando padrões nos dados.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "ECB cipher mode usage detected. " +
        "ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua CipherMode.ECB por um modo autenticado como GCM ou, no mínimo, CBC com HMAC.

        ```csharp
        // ANTES (inseguro):
        aes.Mode = CipherMode.ECB;

        // DEPOIS (seguro):
        using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        ```

        Referência: https://learn.microsoft.com/dotnet/api/system.security.cryptography.aesgcm
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeMemberAccess,
            SyntaxKind.SimpleMemberAccessExpression);
    }

    private void AnalyzeMemberAccess(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        if (!string.Equals(memberAccess.Name.Identifier.Text, "ECB", StringComparison.Ordinal))
        {
            return;
        }

        var symbolInfo = context.SemanticModel.GetSymbolInfo(memberAccess);
        if (symbolInfo.Symbol is not IFieldSymbol fieldSymbol)
        {
            return;
        }

        if (string.Equals(fieldSymbol.ContainingType?.ToDisplayString(), CipherModeFullName, StringComparison.Ordinal))
        {
            var location = context.Node.GetLocation();
            var lineSpan = location.GetLineSpan();

            var finding = new Finding(
                RuleId: Id,
                Severity: Severity,
                Precision: Precision,
                MessagePtBr: "Uso do modo de cifra ECB detectado.",
                MessageEnUs: "ECB cipher mode usage detected.",
                Location: new FindingLocation(
                    FilePath: lineSpan.Path ?? "Unknown",
                    StartLine: lineSpan.StartLinePosition.Line + 1,
                    StartColumn: lineSpan.StartLinePosition.Character,
                    EndLine: lineSpan.EndLinePosition.Line + 1,
                    EndColumn: lineSpan.EndLinePosition.Character,
                    CodeExcerpt: context.Node.ToString()),
                AdditionalLocations: [],
                CweIds: CweIds,
                OwaspCategory: OwaspCategory,
                Tags: Tags,
                Confidence: 1.0);

            context.ReportFinding(finding);
        }
    }
}
