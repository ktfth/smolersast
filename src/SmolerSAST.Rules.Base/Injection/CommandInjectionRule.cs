using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0005: Detects command injection via non-literal strings in
/// ProcessStartInfo.FileName/Arguments or Process.Start with concatenated args — CWE-78.
/// </summary>
public sealed class CommandInjectionRule : SmolerRule
{
    private static readonly string[] ProcessStartInfoFullNames =
        ["System.Diagnostics.ProcessStartInfo"];

    private static readonly string[] ProcessFullNames =
        ["System.Diagnostics.Process"];

    private static readonly string[] ProcessStartInfoSimpleNames = ["ProcessStartInfo"];
    private static readonly string[] ProcessSimpleNames = ["Process"];

    private static readonly string[] DangerousProperties = ["FileName", "Arguments"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0005");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [78];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "command", "os"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Injeção de comando detectada. String não-literal usada em ProcessStartInfo.FileName/Arguments " +
        "ou Process.Start pode permitir execução de comandos arbitrários (CWE-78).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Command injection detected. Non-literal string in ProcessStartInfo.FileName/Arguments " +
        "or Process.Start may allow arbitrary command execution (CWE-78).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Evite concatenação de strings em comandos de processo.

        ```csharp
        // ANTES (inseguro):
        Process.Start("cmd.exe", "/c " + userInput);

        // DEPOIS (seguro):
        var psi = new ProcessStartInfo("myapp.exe")
        {
            ArgumentList = { sanitizedArg1, sanitizedArg2 }
        };
        Process.Start(psi);
        ```

        Use ProcessStartInfo.ArgumentList em vez de concatenação de Arguments.
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: psi.FileName = "..." + variable; psi.Arguments = "..." + variable
        context.RegisterSyntaxNodeAction(
            AnalyzeAssignment,
            SyntaxKind.SimpleAssignmentExpression);

        // Detect: Process.Start("cmd", "..." + variable)
        context.RegisterSyntaxNodeAction(
            AnalyzeInvocation,
            SyntaxKind.InvocationExpression);

        // Detect: new ProcessStartInfo("..." + variable)
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

        if (assignment.Left is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        var propName = memberAccess.Name.Identifier.Text;
        if (!DangerousProperties.AsSpan().Contains(propName))
        {
            return;
        }

        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is not null &&
            !InjectionHelper.IsTypeOneOf(receiverType, ProcessStartInfoFullNames))
        {
            return;
        }

        if (receiverType is null)
        {
            var name = (memberAccess.Expression as IdentifierNameSyntax)?.Identifier.Text;
            if (name is null || !ProcessStartInfoSimpleNames.AsSpan().Contains(name))
            {
                return;
            }
        }

        ReportFinding(context,
            $"Concatenação de string em ProcessStartInfo.{propName} — possível injeção de comando.",
            $"String concatenation in ProcessStartInfo.{propName} — possible command injection.");
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

        if (!string.Equals(memberAccess.Name.Identifier.Text, "Start", StringComparison.Ordinal))
        {
            return;
        }

        // Check receiver type
        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
        {
            if (!InjectionHelper.IsMethodOnType(methodSymbol, ProcessFullNames, ProcessSimpleNames))
            {
                return;
            }
        }
        else
        {
            var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType is not null &&
                !InjectionHelper.IsTypeOneOf(receiverType, ProcessFullNames))
            {
                return;
            }
        }

        if (invocation.ArgumentList.Arguments.Count == 0)
        {
            return;
        }

        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (InjectionHelper.ContainsNonLiteralStringConcatenation(
                    arg.Expression, context.SemanticModel))
            {
                ReportFinding(context,
                    "Concatenação de string em Process.Start() — possível injeção de comando.",
                    "String concatenation in Process.Start() — possible command injection.");
                return;
            }
        }
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not ObjectCreationExpressionSyntax creation)
        {
            return;
        }

        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        var isTarget = InjectionHelper.IsTypeOneOf(typeInfo.Type, ProcessStartInfoFullNames);

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
            if (typeName is null || !ProcessStartInfoSimpleNames.AsSpan().Contains(typeName))
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
                    "Concatenação de string no construtor de ProcessStartInfo — possível injeção de comando.",
                    "String concatenation in ProcessStartInfo constructor — possible command injection.");
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
            [78], OwaspCategory, ["injection", "command", "os"], 0.85);
        context.ReportFinding(finding);
    }
}
