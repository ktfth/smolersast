using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Configuration;

/// <summary>
/// SMOL0040: Detects reflection-based dynamic invocation from potentially untrusted input.
/// </summary>
public sealed class ReflectionDynamicInvocationRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0040");
    public override ImmutableArray<int> CweIds { get; } = [470];
    public override string OwaspCategory => "A03:2021";
    public override RuleSeverity Severity => RuleSeverity.High;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["reflection", "injection"];
    public override string DescriptionPtBr => "Invocação dinâmica via reflection detectada. Se o tipo ou método vem de input não confiável, pode permitir execução de código arbitrário.";
    public override string DescriptionEnUs => "Dynamic reflection-based invocation detected. If type or method comes from untrusted input, it may allow arbitrary code execution.";
    public override string RemediationGuidancePtBr => "Valide e restrinja tipos/métodos a uma allow-list. Nunca use Type.GetType() ou Assembly.Load() com input do usuário.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess) return;

        var methodName = memberAccess.Name.Identifier.Text;

        // Dangerous reflection methods
        if (methodName is "Invoke" or "InvokeMember" or "CreateInstance")
        {
            var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
            if (symbolInfo.Symbol is IMethodSymbol methodSymbol)
            {
                var containingType = methodSymbol.ContainingType?.ToDisplayString() ?? "";
                if (containingType.Contains("System.Reflection", StringComparison.Ordinal) ||
                    containingType.Contains("System.Activator", StringComparison.Ordinal) ||
                    containingType == "System.Type")
                {
                    Report(context, invocation, methodName, containingType);
                    return;
                }
            }
        }

        // Type.GetType with non-literal
        if (methodName == "GetType" && invocation.ArgumentList.Arguments.Count > 0)
        {
            var arg = invocation.ArgumentList.Arguments[0].Expression;
            if (arg is not LiteralExpressionSyntax)
            {
                var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
                if (symbolInfo.Symbol is IMethodSymbol ms && ms.ContainingType?.ToDisplayString() == "System.Type")
                {
                    Report(context, invocation, "Type.GetType", "System.Type");
                }
            }
        }

        // Assembly.Load with non-literal
        if (methodName is "Load" or "LoadFrom" or "LoadFile")
        {
            var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation);
            if (symbolInfo.Symbol is IMethodSymbol ms &&
                ms.ContainingType?.ToDisplayString().Contains("System.Reflection.Assembly", StringComparison.Ordinal) == true)
            {
                var arg = invocation.ArgumentList.Arguments.FirstOrDefault()?.Expression;
                if (arg is not LiteralExpressionSyntax)
                {
                    Report(context, invocation, methodName, "System.Reflection.Assembly");
                }
            }
        }
    }

    private static void Report(SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation, string methodName, string containingType)
    {
        var location = invocation.GetLocation();
        var lineSpan = location.GetLineSpan();
        context.ReportFinding(new Finding(
            new RuleId("SMOL0040"), RuleSeverity.High, RulePrecision.Medium,
            $"Invocação dinâmica via reflection: {containingType}.{methodName}().",
            $"Dynamic reflection invocation: {containingType}.{methodName}().",
            new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
            [], [470], "A03:2021", ["reflection", "injection"], 0.75));
    }
}
