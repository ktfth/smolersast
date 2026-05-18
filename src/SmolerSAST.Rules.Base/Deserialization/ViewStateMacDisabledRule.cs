using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Deserialization;

/// <summary>
/// SMOL0012: Detects ViewState MAC validation being disabled via code assignments
/// such as <c>pages.EnableViewStateMac = false</c> or <c>Pages.EnableViewStateMac = false</c>.
/// CWE-642 — External Control of Critical State Data.
/// </summary>
public sealed class ViewStateMacDisabledRule : SmolerRule
{
    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0012");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [642];

    /// <inheritdoc />
    public override string OwaspCategory => "A08:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.Critical;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["deserialization", "viewstate", "mac-validation"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Validação MAC do ViewState desabilitada. " +
        "Desabilitar EnableViewStateMac permite que atacantes modifiquem o ViewState e executem código arbitrário via deserialização.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "ViewState MAC validation disabled. " +
        "Disabling EnableViewStateMac allows attackers to modify ViewState and execute arbitrary code via deserialization.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Nunca desabilite a validação MAC do ViewState.

        ```csharp
        // ERRADO:
        pages.EnableViewStateMac = false;

        // CORRETO — não configure, o padrão (true) é seguro:
        // Remova qualquer atribuição de EnableViewStateMac = false
        ```

        A partir do ASP.NET 4.5.2, EnableViewStateMac é sempre true e a configuração é ignorada,
        mas versões anteriores são vulneráveis.

        Referência: https://learn.microsoft.com/dotnet/api/system.web.configuration.pagessection.enableviewstatemac
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        // Detect: something.EnableViewStateMac = false
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

        // Check if the left side is a member access ending with "EnableViewStateMac"
        if (assignment.Left is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        if (!string.Equals(memberAccess.Name.Identifier.Text, "EnableViewStateMac", StringComparison.Ordinal))
        {
            return;
        }

        // Check if the right side is the literal 'false'
        if (assignment.Right is not LiteralExpressionSyntax literal)
        {
            return;
        }

        if (!literal.IsKind(SyntaxKind.FalseLiteralExpression))
        {
            return;
        }

        // Try symbol resolution first for precision
        var symbolInfo = context.SemanticModel.GetSymbolInfo(memberAccess);
        if (symbolInfo.Symbol is IPropertySymbol propertySymbol)
        {
            var containingType = propertySymbol.ContainingType?.ToDisplayString() ?? string.Empty;
            // Known types: System.Web.UI.Page.EnableViewStateMac, System.Web.Configuration.PagesSection.EnableViewStateMac
            if (!containingType.StartsWith("System.Web", StringComparison.Ordinal))
            {
                return;
            }
        }

        // If symbol cannot be resolved (external library), still flag based on property name pattern
        ReportFinding(context);
    }

    private void ReportFinding(SyntaxNodeAnalysisContext context)
    {
        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var sourceText = context.Node.ToString();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: "EnableViewStateMac definido como false — validação MAC do ViewState desabilitada.",
            MessageEnUs: "EnableViewStateMac set to false — ViewState MAC validation disabled.",
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
            Confidence: 0.9);

        context.ReportFinding(finding);
    }
}
