using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0020: Detects instantiation of <c>System.Security.Cryptography.RijndaelManaged</c>.
/// RijndaelManaged is deprecated in favor of Aes/AesGcm — CWE-327.
/// </summary>
public sealed class RijndaelManagedUsageRule : SmolerRule
{
    private const string RijndaelManagedFullName = "System.Security.Cryptography.RijndaelManaged";

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0020");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [327];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Medium;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "deprecated-crypto"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de RijndaelManaged detectado. RijndaelManaged está obsoleto e deve ser substituído por Aes ou AesGcm.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "RijndaelManaged usage detected. RijndaelManaged is deprecated and should be replaced with Aes or AesGcm.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua RijndaelManaged por Aes ou AesGcm.

        ```csharp
        // ANTES (obsoleto):
        using var rijndael = new RijndaelManaged();

        // DEPOIS (seguro):
        using var aes = Aes.Create();
        // Ou para criptografia autenticada:
        using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        ```

        Referência: https://learn.microsoft.com/dotnet/api/system.security.cryptography.aes
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression,
            SyntaxKind.ImplicitObjectCreationExpression);
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        if (typeInfo.Type is null)
        {
            return;
        }

        if (!string.Equals(typeInfo.Type.ToDisplayString(), RijndaelManagedFullName, StringComparison.Ordinal))
        {
            return;
        }

        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: "Instanciação de RijndaelManaged detectada.",
            MessageEnUs: "RijndaelManaged instantiation detected.",
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
