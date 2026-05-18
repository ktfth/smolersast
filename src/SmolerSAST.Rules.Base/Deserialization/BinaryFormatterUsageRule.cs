using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0009: Detects any usage of <c>System.Runtime.Serialization.Formatters.Binary.BinaryFormatter</c>.
/// BinaryFormatter is inherently insecure and cannot be made safe — CWE-502.
/// Precision: High (zero false positives — any usage is a finding).
/// </summary>
public sealed class BinaryFormatterUsageRule : SmolerRule
{
    private const string BinaryFormatterFullName =
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter";

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0009");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "binary-formatter"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de BinaryFormatter detectado. BinaryFormatter é inerentemente inseguro e não pode ser tornado seguro. " +
        "Qualquer dado deserializado pode executar código arbitrário, independente de validações aplicadas.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "BinaryFormatter usage detected. BinaryFormatter is inherently insecure and cannot be made safe. " +
        "Any deserialized data can execute arbitrary code regardless of applied validations.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua BinaryFormatter por um serializador seguro com contratos tipados.

        Exemplo com System.Text.Json:
        ```csharp
        // ANTES (inseguro):
        var formatter = new BinaryFormatter();
        var obj = formatter.Deserialize(stream);

        // DEPOIS (seguro):
        var obj = await JsonSerializer.DeserializeAsync<MeuTipo>(stream);
        ```

        Alternativas seguras: System.Text.Json, MessagePack (com contratos tipados),
        Protocol Buffers (protobuf-net com contratos).

        Referência: https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: new BinaryFormatter()
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression,
            SyntaxKind.ImplicitObjectCreationExpression);

        // Detect: invocations on BinaryFormatter (Serialize/Deserialize)
        context.RegisterSyntaxNodeAction(
            AnalyzeInvocation,
            SyntaxKind.InvocationExpression);

        // Detect: typeof(BinaryFormatter) — indicates reflection-based usage
        context.RegisterSyntaxNodeAction(
            AnalyzeTypeOf,
            SyntaxKind.TypeOfExpression);
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        if (IsBinaryFormatterType(typeInfo.Type))
        {
            ReportFinding(context, "Instanciação de BinaryFormatter detectada.",
                "BinaryFormatter instantiation detected.");
        }
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation)
        {
            return;
        }

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is not IMethodSymbol methodSymbol)
        {
            return;
        }

        if (IsBinaryFormatterType(methodSymbol.ContainingType))
        {
            var methodName = methodSymbol.Name;
            ReportFinding(context,
                $"Chamada a BinaryFormatter.{methodName}() detectada.",
                $"BinaryFormatter.{methodName}() call detected.");
        }
    }

    private static void AnalyzeTypeOf(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not TypeOfExpressionSyntax typeOfExpr)
        {
            return;
        }

        var typeInfo = context.SemanticModel.GetTypeInfo(typeOfExpr.Type);
        if (IsBinaryFormatterType(typeInfo.Type))
        {
            ReportFinding(context,
                "Referência a typeof(BinaryFormatter) detectada — possível uso via reflection.",
                "typeof(BinaryFormatter) reference detected — possible reflection-based usage.");
        }
    }

    private static bool IsBinaryFormatterType(ITypeSymbol? type)
    {
        if (type is null)
        {
            return false;
        }

        return string.Equals(
            type.ToDisplayString(),
            BinaryFormatterFullName,
            StringComparison.Ordinal);
    }

    private static void ReportFinding(
        SyntaxNodeAnalysisContext context,
        string messagePtBr,
        string messageEnUs)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: new RuleId("SMOL0009"),
            Severity: RuleSeverity.Critical,
            Precision: RulePrecision.High,
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
            CweIds: [502],
            OwaspCategory: "A08:2021",
            Tags: ["deserialization", "binary-formatter"],
            Confidence: 1.0);

        context.ReportFinding(finding);
    }
}
