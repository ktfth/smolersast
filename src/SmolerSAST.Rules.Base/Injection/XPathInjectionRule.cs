using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0004: Detects XPath injection via string concatenation passed to
/// XmlDocument.SelectNodes/SelectSingleNode — CWE-643.
/// </summary>
public sealed class XPathInjectionRule : SmolerRule
{
    private static readonly string[] FullTypeNames =
    [
        "System.Xml.XmlDocument",
        "System.Xml.XmlNode",
    ];

    private static readonly string[] SimpleTypeNames = ["XmlDocument", "XmlNode"];

    private static readonly string[] TargetMethodNames = ["SelectNodes", "SelectSingleNode"];

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0004");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [643];

    /// <inheritdoc />
    public override string OwaspCategory => "A03:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["injection", "xpath", "xml"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Injeção XPath detectada. Concatenação de string passada a SelectNodes/SelectSingleNode " +
        "pode permitir manipulação de consultas XPath (CWE-643).";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "XPath injection detected. String concatenation passed to SelectNodes/SelectSingleNode " +
        "may allow XPath query manipulation (CWE-643).";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use XPath compilado ou sanitize valores de entrada.

        ```csharp
        // ANTES (inseguro):
        var nodes = doc.SelectNodes("//user[@name='" + userName + "']");

        // DEPOIS (seguro):
        var nav = doc.CreateNavigator();
        var expr = nav.Compile("//user[@name=$name]");
        var ctx = new XsltArgumentList();
        // Use variáveis XPath em vez de concatenação
        ```
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
            if (!InjectionHelper.IsMethodOnType(methodSymbol, FullTypeNames, SimpleTypeNames))
            {
                return;
            }
        }
        else
        {
            // Fallback: check receiver expression type name
            var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType is not null &&
                !InjectionHelper.IsTypeOneOf(receiverType, FullTypeNames))
            {
                return;
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
                $"Concatenação de string passada a {methodName}() — possível injeção XPath.",
                $"String concatenation passed to {methodName}() — possible XPath injection.");
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
            [643], OwaspCategory, ["injection", "xpath", "xml"], 0.80);
        context.ReportFinding(finding);
    }
}
