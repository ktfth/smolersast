using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// Shared utilities for injection detection rules.
/// All methods are pure and stateless.
/// </summary>
internal static class InjectionHelper
{
    /// <summary>
    /// Determines whether the given expression contains string concatenation
    /// (binary + on strings) that includes at least one non-literal operand.
    /// </summary>
    internal static bool ContainsNonLiteralStringConcatenation(
        ExpressionSyntax expression,
        SemanticModel semanticModel)
    {
        if (expression is not BinaryExpressionSyntax binary)
        {
            return false;
        }

        if (!binary.IsKind(SyntaxKind.AddExpression))
        {
            return false;
        }

        var typeInfo = semanticModel.GetTypeInfo(binary);
        if (typeInfo.Type is null ||
            typeInfo.Type.SpecialType != SpecialType.System_String)
        {
            return false;
        }

        // At least one operand must be non-literal (variable, method call, etc.)
        return !IsLiteralOrConstant(binary.Left, semanticModel) ||
               !IsLiteralOrConstant(binary.Right, semanticModel);
    }

    /// <summary>
    /// Recursively checks whether an expression is a compile-time literal or constant.
    /// </summary>
    internal static bool IsLiteralOrConstant(
        ExpressionSyntax expression,
        SemanticModel semanticModel)
    {
        // Direct string literal
        if (expression is LiteralExpressionSyntax)
        {
            return true;
        }

        // Parenthesized expression — unwrap
        if (expression is ParenthesizedExpressionSyntax paren)
        {
            return IsLiteralOrConstant(paren.Expression, semanticModel);
        }

        // Concatenation of two constants is still constant
        if (expression is BinaryExpressionSyntax binary &&
            binary.IsKind(SyntaxKind.AddExpression))
        {
            return IsLiteralOrConstant(binary.Left, semanticModel) &&
                   IsLiteralOrConstant(binary.Right, semanticModel);
        }

        // Check semantic model for compile-time constants (const fields, const locals)
        var constantValue = semanticModel.GetConstantValue(expression);
        return constantValue.HasValue;
    }

    /// <summary>
    /// Checks whether a given type symbol matches any of the provided fully-qualified type names.
    /// </summary>
    internal static bool IsTypeOneOf(ITypeSymbol? type, ReadOnlySpan<string> fullNames)
    {
        if (type is null)
        {
            return false;
        }

        var displayString = type.ToDisplayString();
        foreach (var name in fullNames)
        {
            if (string.Equals(displayString, name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks whether the containing type of a method symbol matches any of the provided
    /// fully-qualified type names. Falls back to simple name matching when the symbol
    /// cannot be fully resolved (e.g., external packages not referenced).
    /// </summary>
    internal static bool IsMethodOnType(
        IMethodSymbol method,
        ReadOnlySpan<string> fullTypeNames,
        ReadOnlySpan<string> simpleTypeNames)
    {
        var containingType = method.ContainingType;
        if (containingType is null)
        {
            return false;
        }

        var displayString = containingType.ToDisplayString();

        // Try full symbol resolution first
        foreach (var name in fullTypeNames)
        {
            if (string.Equals(displayString, name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        // Fallback: simple type name match (for unresolved external types)
        var simpleName = containingType.Name;
        foreach (var name in simpleTypeNames)
        {
            if (string.Equals(simpleName, name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Creates a <see cref="Finding"/> from a syntax node analysis context.
    /// </summary>
    internal static Finding CreateFinding(
        SyntaxNodeAnalysisContext context,
        RuleId ruleId,
        RuleSeverity severity,
        RulePrecision precision,
        string messagePtBr,
        string messageEnUs,
        int[] cweIds,
        string owaspCategory,
        string[] tags,
        double confidence)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        return new Finding(
            RuleId: ruleId,
            Severity: severity,
            Precision: precision,
            MessagePtBr: messagePtBr,
            MessageEnUs: messageEnUs,
            Location: new FindingLocation(
                FilePath: lineSpan.Path ?? "Unknown",
                StartLine: lineSpan.StartLinePosition.Line + 1,
                StartColumn: lineSpan.StartLinePosition.Character,
                EndLine: lineSpan.EndLinePosition.Line + 1,
                EndColumn: lineSpan.EndLinePosition.Character,
                CodeExcerpt: sourceText),
            AdditionalLocations: [],
            CweIds: [.. cweIds],
            OwaspCategory: owaspCategory,
            Tags: [.. tags],
            Confidence: confidence);
    }
}
