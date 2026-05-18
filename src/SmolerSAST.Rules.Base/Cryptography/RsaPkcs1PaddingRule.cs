using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0021: Detects usage of RSAEncryptionPadding.Pkcs1.
/// PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks — CWE-780.
/// </summary>
public sealed class RsaPkcs1PaddingRule : SmolerRule
{
    private const string PaddingFullName = "System.Security.Cryptography.RSAEncryptionPadding";

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0021");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [780];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Medium;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "rsa-padding"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de RSAEncryptionPadding.Pkcs1 detectado. " +
        "O padding PKCS#1 v1.5 é vulnerável a ataques de Bleichenbacher.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "RSAEncryptionPadding.Pkcs1 usage detected. " +
        "PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua PKCS#1 v1.5 por OAEP (Optimal Asymmetric Encryption Padding).

        ```csharp
        // ANTES (inseguro):
        var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);

        // DEPOIS (seguro):
        var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        ```

        Referência: https://learn.microsoft.com/dotnet/api/system.security.cryptography.rsaencryptionpadding
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

        if (!string.Equals(memberAccess.Name.Identifier.Text, "Pkcs1", StringComparison.Ordinal))
        {
            return;
        }

        var symbolInfo = context.SemanticModel.GetSymbolInfo(memberAccess);
        if (symbolInfo.Symbol is not IPropertySymbol propertySymbol)
        {
            return;
        }

        if (string.Equals(propertySymbol.ContainingType?.ToDisplayString(), PaddingFullName, StringComparison.Ordinal))
        {
            var location = context.Node.GetLocation();
            var lineSpan = location.GetLineSpan();

            var finding = new Finding(
                RuleId: Id,
                Severity: Severity,
                Precision: Precision,
                MessagePtBr: "Uso de RSAEncryptionPadding.Pkcs1 detectado.",
                MessageEnUs: "RSAEncryptionPadding.Pkcs1 usage detected.",
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
