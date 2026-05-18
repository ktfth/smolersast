using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SmolerSAST.Analyzer;

/// <summary>
/// Roslyn DiagnosticAnalyzer for IDE-time MD5/SHA1 detection (SMOL0017).
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class WeakHashAnalyzer : DiagnosticAnalyzer
{
    private const string DiagnosticId = "SMOL0017";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Weak hash algorithm detected",
        messageFormat: "MD5/SHA1 detectado (CWE-328). Use SHA256 ou superior para hashing.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "MD5 and SHA1 are cryptographically broken and should not be used for security purposes.");

    private static readonly string[] WeakTypes =
    [
        "System.Security.Cryptography.MD5",
        "System.Security.Cryptography.SHA1",
        "System.Security.Cryptography.MD5CryptoServiceProvider",
        "System.Security.Cryptography.SHA1CryptoServiceProvider",
        "System.Security.Cryptography.SHA1Managed",
    ];

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [Rule];

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, SyntaxKind.ObjectCreationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var symbolInfo = context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken);
        if (symbolInfo.Symbol is IMethodSymbol method && method.Name == "Create")
        {
            var typeName = method.ContainingType?.ToDisplayString();
            if (typeName is not null && WeakTypes.Any(w => typeName.StartsWith(w, System.StringComparison.Ordinal)))
            {
                context.ReportDiagnostic(Diagnostic.Create(Rule, context.Node.GetLocation()));
            }
        }
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node, context.CancellationToken);
        var typeName = typeInfo.Type?.ToDisplayString();
        if (typeName is not null && WeakTypes.Any(w => typeName.StartsWith(w, System.StringComparison.Ordinal)))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, context.Node.GetLocation()));
        }
    }
}
