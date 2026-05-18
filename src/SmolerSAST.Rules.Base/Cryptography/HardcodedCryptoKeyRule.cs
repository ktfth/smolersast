using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0019: Detects hardcoded cryptographic keys and IVs.
/// Byte array literals assigned to .Key or .IV properties, or passed to
/// CreateEncryptor/CreateDecryptor — CWE-321.
/// </summary>
public sealed class HardcodedCryptoKeyRule : SmolerRule
{
    private static readonly ImmutableHashSet<string> SensitivePropertyNames = ImmutableHashSet.Create(
        StringComparer.Ordinal, "Key", "IV");

    private static readonly ImmutableHashSet<string> SensitiveMethodNames = ImmutableHashSet.Create(
        StringComparer.Ordinal, "CreateEncryptor", "CreateDecryptor");

    private const string SymmetricAlgorithmFullName = "System.Security.Cryptography.SymmetricAlgorithm";

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0019");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [321];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "hardcoded-key"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Chave ou IV criptográfico hardcoded detectado no código-fonte. " +
        "Chaves hardcoded podem ser extraídas por engenharia reversa e comprometem toda a criptografia.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Hardcoded cryptographic key or IV detected in source code. " +
        "Hardcoded keys can be extracted via reverse engineering and compromise all encryption.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Nunca hardcode chaves criptográficas no código-fonte. Use um gerenciador de segredos.

        ```csharp
        // ANTES (inseguro):
        aes.Key = new byte[] { 0x01, 0x02, 0x03, ... };

        // DEPOIS (seguro):
        aes.Key = Convert.FromBase64String(Configuration["Encryption:Key"]);
        // Ou use Azure Key Vault, AWS KMS, etc.
        ```

        Referência: https://learn.microsoft.com/dotnet/standard/security/cryptographic-services
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: aes.Key = new byte[] { ... }; aes.IV = new byte[] { ... };
        context.RegisterSyntaxNodeAction(
            AnalyzeAssignment,
            SyntaxKind.SimpleAssignmentExpression);

        // Detect: CreateEncryptor(byteArrayLiteral, byteArrayLiteral)
        context.RegisterSyntaxNodeAction(
            AnalyzeInvocation,
            SyntaxKind.InvocationExpression);
    }

    private void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment)
        {
            return;
        }

        // Check if left side is .Key or .IV on a SymmetricAlgorithm
        if (assignment.Left is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        if (!SensitivePropertyNames.Contains(memberAccess.Name.Identifier.Text))
        {
            return;
        }

        // Verify receiver type derives from SymmetricAlgorithm
        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is null || !InheritsFrom(receiverType, SymmetricAlgorithmFullName))
        {
            return;
        }

        // Check if right side is a byte array literal
        if (IsByteArrayLiteral(assignment.Right, context.SemanticModel))
        {
            var propName = memberAccess.Name.Identifier.Text;
            ReportFinding(context, propName);
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

        if (!SensitiveMethodNames.Contains(methodSymbol.Name))
        {
            return;
        }

        if (methodSymbol.ContainingType is null ||
            !InheritsFrom(methodSymbol.ContainingType, SymmetricAlgorithmFullName))
        {
            return;
        }

        // Check if any argument is a byte array literal
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (IsByteArrayLiteral(arg.Expression, context.SemanticModel))
            {
                ReportFinding(context, methodSymbol.Name);
                return;
            }
        }
    }

    private static bool IsByteArrayLiteral(ExpressionSyntax expression, SemanticModel semanticModel)
    {
        // new byte[] { 0x01, 0x02 }
        if (expression is ArrayCreationExpressionSyntax arrayCreation)
        {
            var typeInfo = semanticModel.GetTypeInfo(arrayCreation);
            if (typeInfo.Type is IArrayTypeSymbol { ElementType.SpecialType: SpecialType.System_Byte })
            {
                return arrayCreation.Initializer is not null;
            }
        }

        // new[] { (byte)0x01, (byte)0x02 } or implicit
        if (expression is ImplicitArrayCreationExpressionSyntax implicitArray)
        {
            var typeInfo = semanticModel.GetTypeInfo(implicitArray);
            if (typeInfo.Type is IArrayTypeSymbol { ElementType.SpecialType: SpecialType.System_Byte })
            {
                return true;
            }
        }

        // stackalloc or collection expression [0x01, 0x02]
        if (expression is CollectionExpressionSyntax)
        {
            var typeInfo = semanticModel.GetTypeInfo(expression);
            if (typeInfo.ConvertedType is IArrayTypeSymbol { ElementType.SpecialType: SpecialType.System_Byte })
            {
                return true;
            }
        }

        return false;
    }

    private static bool InheritsFrom(ITypeSymbol type, string baseTypeName)
    {
        var current = type;
        while (current is not null)
        {
            if (string.Equals(current.ToDisplayString(), baseTypeName, StringComparison.Ordinal))
            {
                return true;
            }

            current = current.BaseType;
        }

        return false;
    }

    private void ReportFinding(SyntaxNodeAnalysisContext context, string targetName)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: $"Chave/IV criptográfico hardcoded detectado em '{targetName}'.",
            MessageEnUs: $"Hardcoded cryptographic key/IV detected in '{targetName}'.",
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
            Confidence: 0.9);

        context.ReportFinding(finding);
    }
}
