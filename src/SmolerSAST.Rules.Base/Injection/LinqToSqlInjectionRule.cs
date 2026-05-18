using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0006: Detects SQL injection via string concatenation in DataContext.ExecuteQuery
/// or similar raw SQL methods in LINQ-to-SQL — CWE-89.
/// </summary>
public sealed class LinqToSqlInjectionRule : SmolerRule
{
    private static readonly string[] FullTypeNames =
        ["System.Data.Linq.DataContext"];

    private static readonly string[] SimpleTypeNames = ["DataContext"];

    private static readonly string[] TargetMethodNames =
        ["ExecuteQuery", "ExecuteCommand"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0006");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [89];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "sql", "linq-to-sql"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Injeção SQL via LINQ-to-SQL detectada. Concatenação de string em ExecuteQuery/ExecuteCommand " +
        "no DataContext pode permitir injeção SQL (CWE-89).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "SQL injection via LINQ-to-SQL detected. String concatenation in ExecuteQuery/ExecuteCommand " +
        "on DataContext may allow SQL injection (CWE-89).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use parâmetros inline do LINQ-to-SQL em vez de concatenação.

        ```csharp
        // ANTES (inseguro):
        ctx.ExecuteQuery<User>("SELECT * FROM Users WHERE Name = '" + name + "'");

        // DEPOIS (seguro):
        ctx.ExecuteQuery<User>("SELECT * FROM Users WHERE Name = {0}", name);
        ```

        O DataContext suporta parâmetros posicionais ({0}, {1}, ...) nativamente.
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

        // Handle generic method names like ExecuteQuery<T>
        if (memberAccess.Name is GenericNameSyntax genericName)
        {
            methodName = genericName.Identifier.Text;
        }

        if (!TargetMethodNames.AsSpan().Contains(methodName))
        {
            return;
        }

        // Check receiver type
        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            if (!InjectionHelper.IsMethodOnType(methodSymbol, FullTypeNames, SimpleTypeNames))
            {
                return;
            }
        }
        else
        {
            var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType is not null &&
                !InjectionHelper.IsTypeOneOf(receiverType, FullTypeNames))
            {
                return;
            }

            if (receiverType is null)
            {
                var name = (memberAccess.Expression as IdentifierNameSyntax)?.Identifier.Text;
                if (name is null || !SimpleTypeNames.AsSpan().Contains(name))
                {
                    return;
                }
            }
        }

        if (invocation.ArgumentList.Arguments.Count == 0)
        {
            return;
        }

        // Check all arguments — the SQL string may not be the first parameter
        // (e.g., ExecuteQuery(Type, string) has SQL as the second argument).
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (InjectionHelper.ContainsNonLiteralStringConcatenation(arg.Expression, context.SemanticModel))
            {
                ReportFinding(context,
                    $"Concatenação de string em DataContext.{methodName}() — possível injeção SQL.",
                    $"String concatenation in DataContext.{methodName}() — possible SQL injection.");
                return;
            }
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
            [89], OwaspCategory, ["injection", "sql", "linq-to-sql"], 0.80);
        context.ReportFinding(finding);
    }
}
