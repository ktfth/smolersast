using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0003: Detects LDAP injection via string concatenation in DirectoryEntry path
/// or DirectorySearcher.Filter — CWE-90.
/// </summary>
public sealed class LdapInjectionRule : SmolerRule
{
    private static readonly string[] DirectoryEntryFullNames =
        ["System.DirectoryServices.DirectoryEntry"];

    private static readonly string[] DirectorySearcherFullNames =
        ["System.DirectoryServices.DirectorySearcher"];

    private static readonly string[] DirectoryEntrySimpleNames = ["DirectoryEntry"];
    private static readonly string[] DirectorySearcherSimpleNames = ["DirectorySearcher"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0003");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [90];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "ldap"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Injeção LDAP detectada. Concatenação de string usada em caminho DirectoryEntry ou filtro DirectorySearcher " +
        "pode permitir manipulação de consultas LDAP (CWE-90).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "LDAP injection detected. String concatenation used in DirectoryEntry path or DirectorySearcher.Filter " +
        "may allow LDAP query manipulation (CWE-90).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Sanitize valores de entrada antes de usar em consultas LDAP.

        ```csharp
        // ANTES (inseguro):
        var entry = new DirectoryEntry("LDAP://DC=" + userInput);

        // DEPOIS (seguro):
        var sanitized = LdapEncoder.Encode(userInput);
        var entry = new DirectoryEntry("LDAP://DC=" + sanitized);
        ```

        Use bibliotecas de sanitização LDAP ou filtros parametrizados quando disponíveis.
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: new DirectoryEntry("LDAP://" + variable)
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression);

        // Detect: searcher.Filter = "..." + variable
        context.RegisterSyntaxNodeAction(
            AnalyzeAssignment,
            SyntaxKind.SimpleAssignmentExpression);
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation)
        {
            return;
        }

        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        var isTarget = InjectionHelper.IsTypeOneOf(typeInfo.Type, DirectoryEntryFullNames);

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
            if (typeName is null || !DirectoryEntrySimpleNames.AsSpan().Contains(typeName))
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
                    "Concatenação de string no caminho de DirectoryEntry — possível injeção LDAP.",
                    "String concatenation in DirectoryEntry path — possible LDAP injection.");
                return;
            }
        }
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

        if (assignment.Left is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        if (!string.Equals(memberAccess.Name.Identifier.Text, "Filter", StringComparison.Ordinal))
        {
            return;
        }

        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is not null &&
            !InjectionHelper.IsTypeOneOf(receiverType, DirectorySearcherFullNames))
        {
            return;
        }

        if (receiverType is null)
        {
            var name = (memberAccess.Expression as IdentifierNameSyntax)?.Identifier.Text;
            if (name is null || !DirectorySearcherSimpleNames.AsSpan().Contains(name))
            {
                return;
            }
        }

        ReportFinding(context,
            "Concatenação de string em DirectorySearcher.Filter — possível injeção LDAP.",
            "String concatenation in DirectorySearcher.Filter — possible LDAP injection.");
    }

    private void ReportFinding(
        SyntaxNodeAnalysisContext context,
        string messagePtBr,
        string messageEnUs)
    {
        var finding = InjectionHelper.CreateFinding(
            context, Id, Severity, Precision,
            messagePtBr, messageEnUs,
            [90], OwaspCategory, ["injection", "ldap"], 0.80);
        context.ReportFinding(finding);
    }
}
