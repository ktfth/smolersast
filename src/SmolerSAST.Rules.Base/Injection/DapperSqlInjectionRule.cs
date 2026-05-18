using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0008: Detects SQL injection via string concatenation in Dapper
/// Execute/Query methods — CWE-89.
/// </summary>
public sealed class DapperSqlInjectionRule : SmolerRule
{
    private static readonly string[] FullTypeNames =
        ["Dapper.SqlMapper"];

    private static readonly string[] SimpleTypeNames = ["SqlMapper"];

    private static readonly string[] TargetMethodNames =
    [
        "Execute", "ExecuteAsync",
        "Query", "QueryAsync",
        "QueryFirst", "QueryFirstAsync",
        "QueryFirstOrDefault", "QueryFirstOrDefaultAsync",
        "QuerySingle", "QuerySingleAsync",
        "QuerySingleOrDefault", "QuerySingleOrDefaultAsync",
        "QueryMultiple", "QueryMultipleAsync",
    ];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0008");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [89];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "sql", "dapper"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Injeção SQL via Dapper detectada. Concatenação de string em métodos Execute/Query do Dapper " +
        "pode permitir injeção SQL (CWE-89).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "SQL injection via Dapper detected. String concatenation in Dapper Execute/Query methods " +
        "may allow SQL injection (CWE-89).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use parâmetros do Dapper em vez de concatenação de strings.

        ```csharp
        // ANTES (inseguro):
        connection.Query("SELECT * FROM Users WHERE Name = '" + name + "'");

        // DEPOIS (seguro):
        connection.Query("SELECT * FROM Users WHERE Name = @Name", new { Name = name });
        ```

        O Dapper suporta parâmetros anônimos nativamente.
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

        string? methodName = null;

        switch (invocation.Expression)
        {
            case MemberAccessExpressionSyntax memberAccess:
                methodName = memberAccess.Name is GenericNameSyntax genericName
                    ? genericName.Identifier.Text
                    : memberAccess.Name.Identifier.Text;
                break;
            default:
                return;
        }

        if (!TargetMethodNames.AsSpan().Contains(methodName))
        {
            return;
        }

        // Dapper methods are extension methods on IDbConnection.
        // With symbol resolution, we check if the method is defined on SqlMapper.
        // Without it, we rely on method name matching (since these are very specific names
        // used predominantly by Dapper).
        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            // Extension methods: check the ReducedFrom's containing type
            var containingType = methodSymbol.ReducedFrom?.ContainingType
                                 ?? methodSymbol.ContainingType;
            if (containingType is not null)
            {
                var displayString = containingType.ToDisplayString();
                var isKnownDapper = false;
                foreach (var name in FullTypeNames)
                {
                    if (string.Equals(displayString, name, StringComparison.Ordinal))
                    {
                        isKnownDapper = true;
                        break;
                    }
                }

                foreach (var name in SimpleTypeNames)
                {
                    if (string.Equals(containingType.Name, name, StringComparison.Ordinal))
                    {
                        isKnownDapper = true;
                        break;
                    }
                }

                if (!isKnownDapper)
                {
                    // Symbol resolved but it's not Dapper — could be any Execute/Query method
                    return;
                }
            }
        }
        // If symbol is null (unresolved), we proceed with name-based detection
        // since the Dapper package isn't referenced. This is intentional for
        // the simplified detection approach.

        if (invocation.ArgumentList.Arguments.Count == 0)
        {
            return;
        }

        // Check all arguments — when called as a static method on SqlMapper,
        // the connection is the first arg and SQL is the second. When called
        // as an extension method, SQL is the first visible argument.
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (InjectionHelper.ContainsNonLiteralStringConcatenation(arg.Expression, context.SemanticModel))
            {
                ReportFinding(context,
                    $"Concatenação de string em Dapper.{methodName}() — possível injeção SQL.",
                    $"String concatenation in Dapper.{methodName}() — possible SQL injection.");
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
            [89], OwaspCategory, ["injection", "sql", "dapper"], 0.85);
        context.ReportFinding(finding);
    }
}
