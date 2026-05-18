using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0017: Detects usage of weak hash algorithms MD5 and SHA1.
/// These algorithms are cryptographically broken and must not be used for
/// password hashing, integrity verification, or digital signatures — CWE-328.
/// </summary>
public sealed class WeakHashAlgorithmRule : SmolerRule
{
    private static readonly ImmutableHashSet<string> WeakTypes = ImmutableHashSet.Create(
        StringComparer.Ordinal,
        "System.Security.Cryptography.MD5",
        "System.Security.Cryptography.SHA1",
        "System.Security.Cryptography.MD5CryptoServiceProvider",
        "System.Security.Cryptography.SHA1CryptoServiceProvider",
        "System.Security.Cryptography.MD5Cng",
        "System.Security.Cryptography.SHA1Cng",
        "System.Security.Cryptography.SHA1Managed");

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0017");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [328];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "weak-hash"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de algoritmo de hash fraco (MD5/SHA1) detectado. " +
        "MD5 e SHA1 são criptograficamente quebrados e não devem ser usados para hashing de senhas, " +
        "verificação de integridade ou assinaturas digitais.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Weak hash algorithm (MD5/SHA1) usage detected. " +
        "MD5 and SHA1 are cryptographically broken and must not be used for password hashing, " +
        "integrity verification, or digital signatures.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua MD5/SHA1 por algoritmos seguros.

        Para hashing de senhas:
        ```csharp
        // ANTES (inseguro):
        var hash = MD5.Create().ComputeHash(data);

        // DEPOIS (seguro — para senhas):
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations: 600000, HashAlgorithmName.SHA256, 32);

        // DEPOIS (seguro — para integridade):
        var hash = SHA256.HashData(data);
        ```

        Referência: https://learn.microsoft.com/dotnet/standard/security/cryptographic-services
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression,
            SyntaxKind.ImplicitObjectCreationExpression);

        context.RegisterSyntaxNodeAction(
            AnalyzeInvocation,
            SyntaxKind.InvocationExpression);
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        if (typeInfo.Type is not null && WeakTypes.Contains(typeInfo.Type.ToDisplayString()))
        {
            ReportFinding(context, typeInfo.Type.Name);
        }
    }

    private void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation)
        {
            return;
        }

        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is not IMethodSymbol methodSymbol)
        {
            return;
        }

        // Detect MD5.Create() / SHA1.Create()
        if (string.Equals(methodSymbol.Name, "Create", StringComparison.Ordinal) &&
            methodSymbol.ContainingType is not null &&
            WeakTypes.Contains(methodSymbol.ContainingType.ToDisplayString()))
        {
            ReportFinding(context, methodSymbol.ContainingType.Name);
        }
    }

    private void ReportFinding(SyntaxNodeAnalysisContext context, string algorithmName)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: $"Uso de algoritmo de hash fraco ({algorithmName}) detectado.",
            MessageEnUs: $"Weak hash algorithm ({algorithmName}) usage detected.",
            Location: new FindingLocation(
                FilePath: lineSpan.Path ?? "Unknown",
                StartLine: lineSpan.StartLinePosition.Line + 1,
                StartColumn: lineSpan.StartLinePosition.Character,
                EndLine: lineSpan.EndLinePosition.Line + 1,
                EndColumn: lineSpan.EndLinePosition.Character,
                CodeExcerpt: sourceText),
            AdditionalLocations: [],
            CweIds: CweIds,
            OwaspCategory: OwaspCategory,
            Tags: Tags,
            Confidence: 1.0);

        context.ReportFinding(finding);
    }
}
