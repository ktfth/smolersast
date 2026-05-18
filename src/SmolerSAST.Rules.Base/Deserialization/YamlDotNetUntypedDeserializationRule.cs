using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0015: Detects YamlDotNet untyped deserialization — <c>Deserialize&lt;object&gt;()</c>
/// or <c>Deserialize()</c> without a target type. CWE-502.
/// </summary>
public sealed class YamlDotNetUntypedDeserializationRule : SmolerRule
{
    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0015");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "yamldotnet", "untyped"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Deserialização não tipada com YamlDotNet detectada. " +
        "Usar Deserialize<object>() ou Deserialize() sem tipo específico pode permitir instanciação de tipos arbitrários.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Untyped YamlDotNet deserialization detected. " +
        "Using Deserialize<object>() or Deserialize() without a specific type can allow instantiation of arbitrary types.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use Deserialize com um tipo específico e configure SafeYaml.

        ```csharp
        // ANTES (inseguro):
        var deserializer = new Deserializer();
        var obj = deserializer.Deserialize<object>(yaml);

        // DEPOIS (seguro):
        var deserializer = new DeserializerBuilder()
            .WithTagMapping("!myType", typeof(MyType))
            .Build();
        var obj = deserializer.Deserialize<MyType>(yaml);
        ```

        Referência: https://github.com/aaubry/YamlDotNet/wiki/Deserialization
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

        // Get the method name
        string methodName;
        SimpleNameSyntax nameSyntax;

        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            nameSyntax = memberAccess.Name;
            methodName = nameSyntax.Identifier.Text;
        }
        else
        {
            return;
        }

        if (!string.Equals(methodName, "Deserialize", StringComparison.Ordinal))
        {
            return;
        }

        // Try symbol resolution first
        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            var containingType = methodSymbol.ContainingType?.ToDisplayString() ?? string.Empty;

            // Must be a YamlDotNet type (Deserializer, IDeserializer, etc.)
            if (!containingType.Contains("YamlDotNet", StringComparison.Ordinal) &&
                !containingType.Contains("Deserializer", StringComparison.Ordinal))
            {
                return;
            }

            // Check if it's generic Deserialize<object>
            if (methodSymbol.IsGenericMethod && methodSymbol.TypeArguments.Length == 1)
            {
                var typeArg = methodSymbol.TypeArguments[0];
                if (string.Equals(typeArg.ToDisplayString(), "object", StringComparison.Ordinal) ||
                    string.Equals(typeArg.SpecialType.ToString(), "System_Object", StringComparison.Ordinal))
                {
                    ReportFinding(context, "Deserialize<object>");
                    return;
                }
            }

            // Check if it's non-generic Deserialize (returns object)
            if (!methodSymbol.IsGenericMethod &&
                methodSymbol.ReturnType.SpecialType == SpecialType.System_Object)
            {
                ReportFinding(context, "Deserialize (untyped)");
                return;
            }
        }
        else
        {
            // Symbol unresolvable — use syntax-based detection
            // Check if receiver looks like a Deserializer instance
            var receiverText = memberAccess.Expression.ToString();
            if (!receiverText.Contains("deserializer", StringComparison.OrdinalIgnoreCase) &&
                !receiverText.Contains("Deserializer", StringComparison.Ordinal))
            {
                return;
            }

            // Check for Deserialize<object> via generic name syntax
            if (nameSyntax is GenericNameSyntax generic)
            {
                var typeArgText = generic.TypeArgumentList.Arguments.FirstOrDefault()?.ToString();
                if (string.Equals(typeArgText, "object", StringComparison.Ordinal))
                {
                    ReportFinding(context, "Deserialize<object>");
                    return;
                }
            }
        }
    }

    private void ReportFinding(SyntaxNodeAnalysisContext context, string pattern)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: $"Deserialização YamlDotNet não tipada detectada: {pattern}.",
            MessageEnUs: $"Untyped YamlDotNet deserialization detected: {pattern}.",
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
