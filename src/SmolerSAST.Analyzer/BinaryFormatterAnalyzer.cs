using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SmolerSAST.Analyzer;

/// <summary>
/// Roslyn DiagnosticAnalyzer for IDE-time BinaryFormatter detection (SMOL0009).
/// Shows squigglies in Visual Studio and Rider.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class BinaryFormatterAnalyzer : DiagnosticAnalyzer
{
    private const string DiagnosticId = "SMOL0009";
    private const string BinaryFormatterFullName = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "BinaryFormatter usage detected",
        messageFormat: "BinaryFormatter é inerentemente inseguro (CWE-502). Use System.Text.Json ou MessagePack.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "BinaryFormatter is inherently insecure and cannot be made safe. Any deserialized data can execute arbitrary code.");

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [Rule];

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression,
            SyntaxKind.ImplicitObjectCreationExpression);

        context.RegisterSyntaxNodeAction(AnalyzeInvocation,
            SyntaxKind.InvocationExpression);

        context.RegisterSyntaxNodeAction(AnalyzeTypeOf,
            SyntaxKind.TypeOfExpression);
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node, context.CancellationToken);
        if (IsBinaryFormatter(typeInfo.Type))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, context.Node.GetLocation()));
        }
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;
        if (invocation.Expression is not MemberAccessExpressionSyntax) return;

        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken);
        if (symbolInfo.Symbol is IMethodSymbol method && IsBinaryFormatter(method.ContainingType))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, context.Node.GetLocation()));
        }
    }

    private static void AnalyzeTypeOf(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not TypeOfExpressionSyntax typeOf) return;

        var typeInfo = context.SemanticModel.GetTypeInfo(typeOf.Type, context.CancellationToken);
        if (IsBinaryFormatter(typeInfo.Type))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, context.Node.GetLocation()));
        }
    }

    private static bool IsBinaryFormatter(ITypeSymbol? type) =>
        type is not null && string.Equals(type.ToDisplayString(), BinaryFormatterFullName, System.StringComparison.Ordinal);
}
