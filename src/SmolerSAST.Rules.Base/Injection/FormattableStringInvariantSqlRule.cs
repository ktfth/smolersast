using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0002: Detects FormattableString.Invariant() used to build SQL strings
/// passed to SqlCommand — CWE-89.
/// FormattableString.Invariant() converts interpolated strings to plain strings,
/// defeating the purpose of parameterized queries.
/// </summary>
public sealed class FormattableStringInvariantSqlRule : SmolerRule
{
    private static readonly string[] SqlCommandFullNames =
    [
        "System.Data.SqlClient.SqlCommand",
        "Microsoft.Data.SqlClient.SqlCommand",
    ];

    private static readonly string[] SqlCommandSimpleNames = ["SqlCommand"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0002");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [89];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "sql", "formattable-string"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de FormattableString.Invariant() para construir SQL detectado. " +
        "Isso converte strings interpoladas em texto plano, anulando a parametrização.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "FormattableString.Invariant() used to build SQL detected. " +
        "This converts interpolated strings to plain text, defeating parameterization.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Não use FormattableString.Invariant() para SQL. Use consultas parametrizadas.

        ```csharp
        // ANTES (inseguro):
        cmd.CommandText = FormattableString.Invariant($"SELECT * FROM Users WHERE Id = {userId}");

        // DEPOIS (seguro):
        cmd.CommandText = "SELECT * FROM Users WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", userId);
        ```
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: cmd.CommandText = FormattableString.Invariant(...)
        context.RegisterSyntaxNodeAction(
            AnalyzeAssignment,
            SyntaxKind.SimpleAssignmentExpression);

        // Detect: new SqlCommand(FormattableString.Invariant(...))
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression);
    }

    private static bool IsFormattableStringInvariant(
        ExpressionSyntax expression,
        SemanticModel semanticModel)
    {
        if (expression is not InvocationExpressionSyntax invocation)
        {
            return false;
        }

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
        {
            return false;
        }

        if (!string.Equals(memberAccess.Name.Identifier.Text, "Invariant", StringComparison.Ordinal))
        {
            return false;
        }

        // Try symbol resolution
        var symbolInfo = semanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            var containingType = methodSymbol.ContainingType?.ToDisplayString();
            return string.Equals(containingType,
                "System.FormattableString", StringComparison.Ordinal);
        }

        // Fallback: name-based check
        return memberAccess.Expression switch
        {
            IdentifierNameSyntax id => string.Equals(
                id.Identifier.Text, "FormattableString", StringComparison.Ordinal),
            _ => false,
        };
    }

    private void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment)
        {
            return;
        }

        if (assignment.Left is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        if (!string.Equals(memberAccess.Name.Identifier.Text, "CommandText", StringComparison.Ordinal))
        {
            return;
        }

        if (!IsFormattableStringInvariant(assignment.Right, context.SemanticModel))
        {
            return;
        }

        // Verify receiver type
        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is not null &&
            !InjectionHelper.IsTypeOneOf(receiverType, SqlCommandFullNames))
        {
            return;
        }

        if (receiverType is null)
        {
            var name = (memberAccess.Expression as IdentifierNameSyntax)?.Identifier.Text;
            if (name is null || !SqlCommandSimpleNames.AsSpan().Contains(name))
            {
                return;
            }
        }

        ReportFinding(context,
            "FormattableString.Invariant() usado para construir SQL em SqlCommand.CommandText.",
            "FormattableString.Invariant() used to build SQL in SqlCommand.CommandText.");
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation)
        {
            return;
        }

        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        var isTarget = InjectionHelper.IsTypeOneOf(typeInfo.Type, SqlCommandFullNames);

        if (!isTarget && typeInfo.Type is not null)
        {
            return;
        }

        if (!isTarget && typeInfo.Type is null)
        {
            var typeName = creation.Type switch
            {
                IdentifierNameSyntax id => id.Identifier.Text,
                QualifiedNameSyntax q => q.Right.Identifier.Text,
                _ => null,
            };
            if (typeName is null || !SqlCommandSimpleNames.AsSpan().Contains(typeName))
            {
                return;
            }
        }

        if (creation.ArgumentList is null)
        {
            return;
        }

        foreach (var arg in creation.ArgumentList.Arguments)
        {
            if (IsFormattableStringInvariant(arg.Expression, context.SemanticModel))
            {
                ReportFinding(context,
                    "FormattableString.Invariant() usado no construtor de SqlCommand.",
                    "FormattableString.Invariant() used in SqlCommand constructor.");
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
            [89], OwaspCategory, ["injection", "sql", "formattable-string"], 0.80);
        context.ReportFinding(finding);
    }
}
