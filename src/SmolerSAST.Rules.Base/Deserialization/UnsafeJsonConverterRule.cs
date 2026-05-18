using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0014: Detects custom System.Text.Json JsonConverter implementations that call
/// <c>JsonSerializer.Deserialize</c> with a <c>Type</c> parameter (runtime type), which
/// can lead to type-confusion deserialization attacks — CWE-502.
/// </summary>
public sealed class UnsafeJsonConverterRule : SmolerRule
{
    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0014");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "system-text-json", "json-converter"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "JsonConverter customizado com chamada a JsonSerializer.Deserialize usando parâmetro Type detectado. " +
        "Isso pode permitir deserialização de tipos arbitrários se o Type vier de fonte não confiável.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Custom JsonConverter calling JsonSerializer.Deserialize with a Type parameter detected. " +
        "This can allow deserialization of arbitrary types if the Type comes from an untrusted source.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use a sobrecarga genérica tipada de JsonSerializer.Deserialize<T> em vez da sobrecarga com Type.

        ```csharp
        // ANTES (potencialmente inseguro):
        var obj = JsonSerializer.Deserialize(ref reader, someType, options);

        // DEPOIS (seguro):
        var obj = JsonSerializer.Deserialize<MeuTipoConhecido>(ref reader, options);
        ```

        Se o Type for necessário, valide-o contra uma lista de tipos permitidos.

        Referência: https://learn.microsoft.com/dotnet/standard/serialization/system-text-json/converters-how-to
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeInvocation,
            SyntaxKind.InvocationExpression);
    }

    private void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation)
        {
            return;
        }

        // Check if the method is named "Deserialize"
        string methodName;
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            methodName = memberAccess.Name.Identifier.Text;
        }
        else
        {
            return;
        }

        if (!string.Equals(methodName, "Deserialize", StringComparison.Ordinal))
        {
            return;
        }

        // Try symbol resolution
        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            var containingType = methodSymbol.ContainingType?.ToDisplayString() ?? string.Empty;

            // Must be System.Text.Json.JsonSerializer
            if (!string.Equals(containingType, "System.Text.Json.JsonSerializer", StringComparison.Ordinal))
            {
                return;
            }

            // Check if any parameter is of type System.Type
            var hasTypeParam = methodSymbol.Parameters.Any(p =>
                string.Equals(p.Type.ToDisplayString(), "System.Type", StringComparison.Ordinal));

            if (!hasTypeParam)
            {
                return;
            }
        }
        else
        {
            // Unresolved symbol — check syntactically if it looks like JsonSerializer.Deserialize
            // with a Type argument
            if (!memberAccess.Expression.ToString().Contains("JsonSerializer", StringComparison.Ordinal))
            {
                return;
            }

            // Check arguments for a typeof() or Type-typed argument
            var hasTypeArg = invocation.ArgumentList.Arguments.Any(arg =>
                arg.Expression is TypeOfExpressionSyntax ||
                arg.Expression.ToString().Contains("Type", StringComparison.Ordinal));

            if (!hasTypeArg)
            {
                return;
            }
        }

        // Check if we are inside a class that inherits from JsonConverter
        var containingClass = invocation.FirstAncestorOrSelf<ClassDeclarationSyntax>();
        if (containingClass is null)
        {
            return;
        }

        var classSymbol = context.SemanticModel.GetDeclaredSymbol(containingClass);
        if (classSymbol is not null && !InheritsFromJsonConverter(classSymbol))
        {
            return;
        }

        ReportFinding(context);
    }

    private static bool InheritsFromJsonConverter(INamedTypeSymbol classSymbol)
    {
        var current = classSymbol.BaseType;
        while (current is not null)
        {
            var baseName = current.ToDisplayString();
            if (baseName.Contains("JsonConverter", StringComparison.Ordinal))
            {
                return true;
            }

            current = current.BaseType;
        }

        return false;
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
            MessagePtBr: "JsonSerializer.Deserialize com parâmetro Type em JsonConverter customizado.",
            MessageEnUs: "JsonSerializer.Deserialize with Type parameter in custom JsonConverter.",
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
            Confidence: 0.8);

        context.ReportFinding(finding);
    }
}
