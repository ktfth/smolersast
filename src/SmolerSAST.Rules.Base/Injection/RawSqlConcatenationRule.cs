using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0001: Detects raw SQL string concatenation assigned to SqlCommand.CommandText
/// or passed to the SqlCommand constructor — CWE-89.
/// </summary>
public sealed class RawSqlConcatenationRule : SmolerRule
{
    private static readonly string[] FullTypeNames =
    [
        "System.Data.SqlClient.SqlCommand",
        "Microsoft.Data.SqlClient.SqlCommand",
    ];

    private static readonly string[] SimpleTypeNames = ["SqlCommand"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0001");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [89];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "sql"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Concatenação de string SQL detectada em SqlCommand. " +
        "Strings SQL construídas por concatenação são vulneráveis a injeção de SQL (CWE-89).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Raw SQL string concatenation detected in SqlCommand. " +
        "SQL strings built via concatenation are vulnerable to SQL injection (CWE-89).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use consultas parametrizadas em vez de concatenação de strings.

        ```csharp
        // ANTES (inseguro):
        cmd.CommandText = "SELECT * FROM Users WHERE Id = " + userId;

        // DEPOIS (seguro):
        cmd.CommandText = "SELECT * FROM Users WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", userId);
        ```
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: cmd.CommandText = "..." + variable
        context.RegisterSyntaxNodeAction(
            AnalyzeAssignment,
            SyntaxKind.SimpleAssignmentExpression);

        // Detect: new SqlCommand("..." + variable)
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression);
    }

    private void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment)
        {
            return;
        }

        if (!InjectionHelper.ContainsNonLiteralStringConcatenation(
                assignment.Right, context.SemanticModel))
        {
            return;
        }

        // Check if left side is *.CommandText
        if (assignment.Left is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        if (!string.Equals(memberAccess.Name.Identifier.Text, "CommandText", StringComparison.Ordinal))
        {
            return;
        }

        // Try to resolve the type of the receiver
        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is not null &&
            !InjectionHelper.IsTypeOneOf(receiverType, FullTypeNames))
        {
            // Type resolved but is not SqlCommand — skip
            return;
        }

        // If type is null (unresolved), fall back to name check
        if (receiverType is null)
        {
            var receiverName = GetSimpleTypeName(memberAccess.Expression);
            if (receiverName is null || !SimpleTypeNames.AsSpan().Contains(receiverName))
            {
                return;
            }
        }

        ReportFinding(context,
            "Concatenação de string SQL atribuída a SqlCommand.CommandText.",
            "SQL string concatenation assigned to SqlCommand.CommandText.");
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation)
        {
            return;
        }

        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        var isTargetType = InjectionHelper.IsTypeOneOf(typeInfo.Type, FullTypeNames);

        if (!isTargetType && typeInfo.Type is not null)
        {
            return;
        }

        // Fallback for unresolved types
        if (!isTargetType && typeInfo.Type is null)
        {
            var typeName = GetCreationTypeName(creation);
            if (typeName is null || !SimpleTypeNames.AsSpan().Contains(typeName))
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
            if (InjectionHelper.ContainsNonLiteralStringConcatenation(
                    arg.Expression, context.SemanticModel))
            {
                ReportFinding(context,
                    "Concatenação de string SQL passada ao construtor de SqlCommand.",
                    "SQL string concatenation passed to SqlCommand constructor.");
                return;
            }
        }
    }

    private static string? GetSimpleTypeName(ExpressionSyntax expression)
    {
        return expression switch
        {
            IdentifierNameSyntax id => id.Identifier.Text,
            _ => null,
        };
    }

    private static string? GetCreationTypeName(ObjectCreationExpressionSyntax creation)
    {
        return creation.Type switch
        {
            IdentifierNameSyntax id => id.Identifier.Text,
            QualifiedNameSyntax qualified => qualified.Right.Identifier.Text,
            _ => null,
        };
    }

    private void ReportFinding(
        SyntaxNodeAnalysisContext context,
        string messagePtBr,
        string messageEnUs)
    {
        var finding = InjectionHelper.CreateFinding(
            context, Id, Severity, Precision,
            messagePtBr, messageEnUs,
            [89], OwaspCategory, ["injection", "sql"], 0.85);
        context.ReportFinding(finding);
    }
}
