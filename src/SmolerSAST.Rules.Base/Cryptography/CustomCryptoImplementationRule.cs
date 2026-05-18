using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0023: Detects custom cryptographic implementations.
/// Methods named Encrypt/Decrypt/Hash containing bitwise XOR (^) or shift operators
/// (&lt;&lt;, &gt;&gt;) suggest hand-rolled crypto — CWE-327.
/// </summary>
public sealed class CustomCryptoImplementationRule : SmolerRule
{
    private static readonly ImmutableHashSet<string> CryptoMethodNames = ImmutableHashSet.Create(
        StringComparer.OrdinalIgnoreCase,
        "Encrypt", "Decrypt", "Hash", "Cipher", "Encipher", "Decipher");

    private static readonly ImmutableHashSet<SyntaxKind> BitwiseOperators = ImmutableHashSet.Create(
        SyntaxKind.ExclusiveOrExpression,      // ^
        SyntaxKind.LeftShiftExpression,         // <<
        SyntaxKind.RightShiftExpression);       // >>

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0023");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [327];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Medium;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Low;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "custom-crypto"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Possível implementação criptográfica customizada detectada. " +
        "Métodos com nomes criptográficos contendo operações bitwise sugerem criptografia manual, " +
        "que é propensa a erros e vulnerabilidades.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Possible custom cryptographic implementation detected. " +
        "Methods with crypto-related names containing bitwise operations suggest hand-rolled cryptography, " +
        "which is error-prone and vulnerable.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Nunca implemente sua própria criptografia. Use bibliotecas padrão.

        ```csharp
        // ANTES (inseguro — cripto manual):
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] ^= key[i % key.Length];
            return data;
        }

        // DEPOIS (seguro):
        using var aes = Aes.Create();
        using var encryptor = aes.CreateEncryptor(key, iv);
        var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
        ```

        Referência: https://learn.microsoft.com/dotnet/standard/security/cryptographic-services
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeMethod,
            SyntaxKind.MethodDeclaration);
    }

    private void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method)
        {
            return;
        }

        // Check if method name is crypto-related
        if (!CryptoMethodNames.Contains(method.Identifier.Text))
        {
            return;
        }

        // Check if method body contains bitwise XOR or shift operators
        if (method.Body is null && method.ExpressionBody is null)
        {
            return;
        }

        var bodyNode = (SyntaxNode?)method.Body ?? method.ExpressionBody;
        if (bodyNode is null)
        {
            return;
        }

        var hasBitwiseOp = bodyNode
            .DescendantNodes()
            .OfType<BinaryExpressionSyntax>()
            .Any(b => BitwiseOperators.Contains(b.Kind()));

        if (!hasBitwiseOp)
        {
            return;
        }

        var location = method.Identifier.GetLocation();
        var lineSpan = location.GetLineSpan();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: $"Possível implementação criptográfica customizada no método '{method.Identifier.Text}'.",
            MessageEnUs: $"Possible custom cryptographic implementation in method '{method.Identifier.Text}'.",
            Location: new FindingLocation(
                FilePath: lineSpan.Path ?? "Unknown",
                StartLine: lineSpan.StartLinePosition.Line + 1,
                StartColumn: lineSpan.StartLinePosition.Character,
                EndLine: lineSpan.EndLinePosition.Line + 1,
                EndColumn: lineSpan.EndLinePosition.Character,
                CodeExcerpt: method.Identifier.Text),
            AdditionalLocations: [],
            CweIds: CweIds,
            OwaspCategory: OwaspCategory,
            Tags: Tags,
            Confidence: 0.6);

        context.ReportFinding(finding);
    }
}
