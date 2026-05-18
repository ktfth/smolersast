using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0016: Detects <c>DataContractSerializer</c> constructor usage where KnownTypes
/// come from a dynamic/untrusted source (variable, method call, parameter) rather than
/// a fixed list of types. CWE-502.
/// </summary>
public sealed class DataContractSerializerDynamicKnownTypesRule : SmolerRule
{
    private const string DataContractSerializerFullName =
        "System.Runtime.Serialization.DataContractSerializer";

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0016");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "data-contract-serializer", "known-types"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "DataContractSerializer com KnownTypes de fonte dinâmica detectado. " +
        "Se os tipos conhecidos vierem de entrada do usuário ou fonte não confiável, um atacante pode forçar a " +
        "deserialização de tipos arbitrários.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "DataContractSerializer with KnownTypes from dynamic source detected. " +
        "If known types come from user input or an untrusted source, an attacker can force " +
        "deserialization of arbitrary types.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use uma lista fixa de tipos conhecidos ao criar DataContractSerializer.

        ```csharp
        // ANTES (inseguro):
        var types = GetTypesFromInput(userInput);
        var serializer = new DataContractSerializer(typeof(MyData), types);

        // DEPOIS (seguro):
        var knownTypes = new[] { typeof(Order), typeof(Customer) };
        var serializer = new DataContractSerializer(typeof(MyData), knownTypes);
        ```

        Nunca permita que tipos conhecidos sejam determinados por entrada externa.

        Referência: https://learn.microsoft.com/dotnet/api/system.runtime.serialization.datacontractserializer
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression);
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation)
        {
            return;
        }

        // Check if this is a DataContractSerializer instantiation
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        bool isDataContractSerializer;

        if (typeInfo.Type is not null)
        {
            isDataContractSerializer = string.Equals(
                typeInfo.Type.ToDisplayString(),
                DataContractSerializerFullName,
                StringComparison.Ordinal);
        }
        else
        {
            // Fallback to syntax check
            var typeName = creation.Type.ToString();
            isDataContractSerializer = typeName.Contains("DataContractSerializer", StringComparison.Ordinal);
        }

        if (!isDataContractSerializer)
        {
            return;
        }

        // Check constructor arguments — we need at least 2 args (type + knownTypes)
        var args = creation.ArgumentList?.Arguments;
        if (args is null || args.Value.Count < 2)
        {
            return;
        }

        // The knownTypes parameter is typically the second argument (IEnumerable<Type>)
        // Check if any argument after the first is dynamic (not a fixed array/list literal)
        for (var i = 1; i < args.Value.Count; i++)
        {
            var arg = args.Value[i];
            if (IsDynamicTypeSource(arg.Expression))
            {
                ReportFinding(context);
                return;
            }
        }
    }

    private static bool IsDynamicTypeSource(ExpressionSyntax expression)
    {
        // Safe patterns: new[] { typeof(...) }, new List<Type> { typeof(...) }, array literals
        // Unsafe patterns: variables, method calls, parameters

        return expression switch
        {
            // Array/collection creation with typeof initializers is safe
            ArrayCreationExpressionSyntax => false,
            ImplicitArrayCreationExpressionSyntax => false,
            CollectionExpressionSyntax => false,

            // Method call — potentially dynamic
            InvocationExpressionSyntax => true,

            // Variable/parameter/field — potentially from user input
            IdentifierNameSyntax => true,
            MemberAccessExpressionSyntax => true,

            // Object creation (new List<Type>(someSource)) — check inner
            ObjectCreationExpressionSyntax objCreation =>
                objCreation.ArgumentList?.Arguments.Count > 0,

            _ => false,
        };
    }

    private void ReportFinding(SyntaxNodeAnalysisContext context)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: "DataContractSerializer com KnownTypes de fonte dinâmica detectado.",
            MessageEnUs: "DataContractSerializer with KnownTypes from dynamic source detected.",
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
            Confidence: 0.7);

        context.ReportFinding(finding);
    }
}
