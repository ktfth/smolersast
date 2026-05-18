using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0013: Detects Newtonsoft.Json TypeNameHandling set to anything other than None.
/// When TypeNameHandling is not None, deserialized JSON can instantiate arbitrary types — CWE-502.
/// </summary>
public sealed class NewtonsoftTypeNameHandlingRule : SmolerRule
{
    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0013");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [502];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "newtonsoft", "type-name-handling"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "TypeNameHandling do Newtonsoft.Json configurado com valor diferente de None. " +
        "Isso permite que dados JSON deserializados instanciem tipos arbitrários, levando a execução remota de código.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Newtonsoft.Json TypeNameHandling set to a value other than None. " +
        "This allows deserialized JSON data to instantiate arbitrary types, leading to remote code execution.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use TypeNameHandling.None (padrão) ou migre para System.Text.Json.

        ```csharp
        // ANTES (inseguro):
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };

        // DEPOIS (seguro):
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None
        };
        // Ou melhor ainda, não defina TypeNameHandling (o padrão já é None).
        ```

        Se TypeNameHandling for necessário, use um SerializationBinder customizado restritivo.

        Referência: https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: TypeNameHandling = TypeNameHandling.All / Objects / Arrays / Auto
        context.RegisterSyntaxNodeAction(
            AnalyzeAssignment,
            SyntaxKind.SimpleAssignmentExpression);
    }

    private void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment)
        {
            return;
        }

        // Check left side: must be a member access with name "TypeNameHandling"
        string propertyName;
        if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
        {
            propertyName = memberAccess.Name.Identifier.Text;
        }
        else if (assignment.Left is IdentifierNameSyntax identifier)
        {
            propertyName = identifier.Identifier.Text;
        }
        else
        {
            return;
        }

        if (!string.Equals(propertyName, "TypeNameHandling", StringComparison.Ordinal))
        {
            return;
        }

        // Try symbol resolution to verify it's from Newtonsoft.Json
        var leftSymbol = context.SemanticModel.GetSymbolInfo(assignment.Left);
        if (leftSymbol.Symbol is IPropertySymbol propSymbol)
        {
            var containingType = propSymbol.ContainingType?.ToDisplayString() ?? string.Empty;
            if (!containingType.Contains("Newtonsoft.Json", StringComparison.Ordinal) &&
                !containingType.Contains("JsonSerializerSettings", StringComparison.Ordinal))
            {
                return;
            }
        }

        // Check right side: is it TypeNameHandling.None?
        if (IsNoneValue(context, assignment.Right))
        {
            return; // TypeNameHandling.None is safe
        }

        ReportFinding(context, assignment.Right.ToString());
    }

    private static bool IsNoneValue(SyntaxNodeAnalysisContext context, ExpressionSyntax expression)
    {
        // Check for TypeNameHandling.None via member access
        if (expression is MemberAccessExpressionSyntax memberAccess)
        {
            if (string.Equals(memberAccess.Name.Identifier.Text, "None", StringComparison.Ordinal))
            {
                return true;
            }
        }

        // Check for the integer literal 0 (TypeNameHandling.None == 0)
        if (expression is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.NumericLiteralExpression) &&
            literal.Token.Value is int intValue &&
            intValue == 0)
        {
            return true;
        }

        // Try constant folding via semantic model
        var constantValue = context.SemanticModel.GetConstantValue(expression);
        if (constantValue.HasValue && constantValue.Value is int constInt && constInt == 0)
        {
            return true;
        }

        return false;
    }

    private void ReportFinding(SyntaxNodeAnalysisContext context, string assignedValue)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: $"TypeNameHandling configurado como {assignedValue} — valor inseguro.",
            MessageEnUs: $"TypeNameHandling set to {assignedValue} — insecure value.",
            Location: new FindingLocation(
                FilePath: lineSpan.Path ?? "Unknown",
                StartLine: lineSpan.StartLinePosition.Line + 1,
                StartColumn: lineSpan.StartLinePosition.Character,
                EndLine: lineSpan.EndLinePosition.Line + 1,
                EndColumn: lineSpan.EndLinePosition.Character,
                CodeExcerpt: sourceText),
            AdditionalLocations: [],
            CweIds: CweIds,
            OwaspCategory: OwaspCategory,
            Tags: Tags,
            Confidence: 1.0);

        context.ReportFinding(finding);
    }
}
