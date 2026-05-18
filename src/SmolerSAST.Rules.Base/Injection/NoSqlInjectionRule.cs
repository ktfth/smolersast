using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0007: Detects NoSQL injection in MongoDB.Driver filter strings or
/// BsonDocument.Parse from user input — CWE-943.
/// </summary>
public sealed class NoSqlInjectionRule : SmolerRule
{
    private static readonly string[] BsonDocumentFullNames =
        ["MongoDB.Bson.BsonDocument"];

    private static readonly string[] BsonDocumentSimpleNames = ["BsonDocument"];

    private static readonly string[] FilterDefinitionBuilderFullNames =
        ["MongoDB.Driver.FilterDefinitionBuilder", "MongoDB.Driver.Builders"];

    private static readonly string[] FilterSimpleNames =
        ["FilterDefinitionBuilder", "Builders"];

    private static readonly string[] TargetMethodNames =
        ["Parse", "JsonFilter"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0007");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [943];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "nosql", "mongodb"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Injeção NoSQL detectada. Concatenação de string usada em BsonDocument.Parse ou filtros MongoDB " +
        "pode permitir manipulação de consultas NoSQL (CWE-943).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "NoSQL injection detected. String concatenation used in BsonDocument.Parse or MongoDB filters " +
        "may allow NoSQL query manipulation (CWE-943).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use builders tipados do MongoDB.Driver em vez de strings JSON.

        ```csharp
        // ANTES (inseguro):
        var filter = BsonDocument.Parse("{ name: '" + userInput + "' }");

        // DEPOIS (seguro):
        var filter = Builders<User>.Filter.Eq(u => u.Name, userInput);
        ```

        Use Builders<T>.Filter para construir filtros de forma tipada e segura.
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

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        var methodName = memberAccess.Name.Identifier.Text;
        if (!TargetMethodNames.AsSpan().Contains(methodName))
        {
            return;
        }

        // Check receiver type
        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            var allFullNames = BsonDocumentFullNames
                .Concat(FilterDefinitionBuilderFullNames).ToArray();
            var allSimpleNames = BsonDocumentSimpleNames
                .Concat(FilterSimpleNames).ToArray();
            if (!InjectionHelper.IsMethodOnType(methodSymbol, allFullNames, allSimpleNames))
            {
                return;
            }
        }
        else
        {
            var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType is not null)
            {
                var allFullNames = BsonDocumentFullNames
                    .Concat(FilterDefinitionBuilderFullNames).ToArray();
                if (!InjectionHelper.IsTypeOneOf(receiverType, allFullNames))
                {
                    return;
                }
            }

            if (receiverType is null)
            {
                var name = (memberAccess.Expression as IdentifierNameSyntax)?.Identifier.Text;
                var allSimpleNames = BsonDocumentSimpleNames
                    .Concat(FilterSimpleNames).ToArray();
                if (name is null || !allSimpleNames.AsSpan().Contains(name))
                {
                    return;
                }
            }
        }

        if (invocation.ArgumentList.Arguments.Count == 0)
        {
            return;
        }

        var firstArg = invocation.ArgumentList.Arguments[0].Expression;
        if (InjectionHelper.ContainsNonLiteralStringConcatenation(firstArg, context.SemanticModel))
        {
            ReportFinding(context,
                $"Concatenação de string em {methodName}() — possível injeção NoSQL.",
                $"String concatenation in {methodName}() — possible NoSQL injection.");
        }
    }

    private void ReportFinding(
        SyntaxNodeAnalysisContext context,
        string messagePtBr,
        string messageEnUs)
    {
        var finding = InjectionHelper.CreateFinding(
            context, Id, Severity, Precision,
            messagePtBr, messageEnUs,
            [943], OwaspCategory, ["injection", "nosql", "mongodb"], 0.80);
        context.ReportFinding(finding);
    }
}
