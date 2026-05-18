using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0010: Detects usage of <c>NetDataContractSerializer</c> or <c>SoapFormatter</c>.
/// Both are inherently insecure deserializers — CWE-502.
/// </summary>
public sealed class NetDataContractSerializerSoapFormatterRule : SmolerRule
{
    private static readonly ImmutableArray<string> DangerousTypes =
    [
        "System.Runtime.Serialization.NetDataContractSerializer",
        "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
    ];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0010");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "net-data-contract", "soap-formatter"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de NetDataContractSerializer ou SoapFormatter detectado. " +
        "Ambos são deserializadores inerentemente inseguros que permitem execução de código arbitrário via dados maliciosos.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "NetDataContractSerializer or SoapFormatter usage detected. " +
        "Both are inherently insecure deserializers that allow arbitrary code execution via malicious data.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua NetDataContractSerializer/SoapFormatter por um serializador seguro com contratos tipados.

        Exemplo com System.Text.Json:
        ```csharp
        // ANTES (inseguro):
        var serializer = new NetDataContractSerializer();
        var obj = serializer.ReadObject(stream);

        // DEPOIS (seguro):
        var obj = await JsonSerializer.DeserializeAsync<MeuTipo>(stream);
        ```

        Alternativas seguras: System.Text.Json, DataContractSerializer com tipos conhecidos fixos,
        Protocol Buffers (protobuf-net com contratos).

        Referência: https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide
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
        if (IsDangerousType(typeInfo.Type))
        {
            var typeName = GetShortName(typeInfo.Type!);
            ReportFinding(context,
                $"Instanciação de {typeName} detectada.",
                $"{typeName} instantiation detected.");
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

        if (IsDangerousType(methodSymbol.ContainingType))
        {
            var typeName = GetShortName(methodSymbol.ContainingType);
            var methodName = methodSymbol.Name;
            ReportFinding(context,
                $"Chamada a {typeName}.{methodName}() detectada.",
                $"{typeName}.{methodName}() call detected.");
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

    private static string GetShortName(ITypeSymbol type) => type.Name;

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
