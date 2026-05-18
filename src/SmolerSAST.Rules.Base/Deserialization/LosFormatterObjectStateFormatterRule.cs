using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0011: Detects instantiation of <c>System.Web.UI.LosFormatter</c> or
/// <c>System.Web.UI.ObjectStateFormatter</c>. Both are insecure deserializers — CWE-502.
/// </summary>
public sealed class LosFormatterObjectStateFormatterRule : SmolerRule
{
    private static readonly ImmutableArray<string> DangerousTypes =
    [
        "System.Web.UI.LosFormatter",
        "System.Web.UI.ObjectStateFormatter",
    ];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0011");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "los-formatter", "object-state-formatter"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de LosFormatter ou ObjectStateFormatter detectado. " +
        "Ambos são deserializadores inseguros usados internamente pelo ASP.NET ViewState e permitem execução de código arbitrário.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "LosFormatter or ObjectStateFormatter usage detected. " +
        "Both are insecure deserializers used internally by ASP.NET ViewState and allow arbitrary code execution.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Não utilize LosFormatter ou ObjectStateFormatter diretamente.

        Exemplo seguro:
        ```csharp
        // ANTES (inseguro):
        var formatter = new LosFormatter();
        var obj = formatter.Deserialize(input);

        // DEPOIS (seguro):
        var obj = JsonSerializer.Deserialize<MeuTipo>(input);
        ```

        Use serializadores com contratos tipados como System.Text.Json ou DataContractSerializer.

        Referência: https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide
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
        if (IsDangerousType(typeInfo.Type))
        {
            var typeName = typeInfo.Type!.Name;
            ReportFinding(context,
                $"Instanciação de {typeName} detectada.",
                $"{typeName} instantiation detected.");
        }
    }

    private static bool IsDangerousType(ITypeSymbol? type)
    {
        if (type is null)
        {
            return false;
        }

        var fullName = type.ToDisplayString();
        return DangerousTypes.Contains(fullName);
    }

    private void ReportFinding(
        SyntaxNodeAnalysisContext context,
        string messagePtBr,
        string messageEnUs)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: messagePtBr,
            MessageEnUs: messageEnUs,
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
