using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.BR.Pci;

/// <summary>
/// SMOL1018: Detects CVV/CVC stored in any persistent form (database, file, cache).
/// Ref: PCI-DSS Req. 3.2 — Do not store sensitive authentication data after authorization.
/// </summary>
public sealed class CvvStorageRule : SmolerRule
{
    private static readonly string[] CvvFieldNames =
    [
        "cvv", "cvc", "cvv2", "cvc2", "securitycode", "security_code",
        "codigoseguranca", "codigo_seguranca", "cardverification",
    ];

    private static readonly string[] PersistMethods =
    [
        "Save", "SaveAsync", "SaveChanges", "SaveChangesAsync",
        "Insert", "InsertAsync", "Add", "AddAsync",
        "Update", "UpdateAsync", "Write", "WriteAsync",
        "Set", "SetAsync", "Store", "Persist",
    ];

    public override RuleId Id { get; } = new("SMOL1018");
    public override ImmutableArray<int> CweIds { get; } = [312];
    public override string OwaspCategory => "A04:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["pci-dss", "cvv", "storage"];
    public override string DescriptionPtBr => "CVV/CVC armazenado em forma persistente. PCI-DSS Req. 3.2 proíbe armazenamento de dados sensíveis de autenticação após autorização.";
    public override string DescriptionEnUs => "CVV/CVC stored in persistent form. PCI-DSS Req. 3.2 prohibits storing sensitive authentication data after authorization.";
    public override string RemediationGuidancePtBr => "Nunca persista CVV/CVC. Use apenas em memória durante a transação e descarte imediatamente após autorização.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeProperty, SyntaxKind.PropertyDeclaration);
    }

    private static void AnalyzeProperty(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not PropertyDeclarationSyntax property) return;

        var propName = property.Identifier.Text.ToLowerInvariant();
        if (!CvvFieldNames.Any(c => propName.Contains(c, StringComparison.Ordinal))) return;

        // Check if the containing class looks like an entity/model that gets persisted
        var containingClass = property.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
        if (containingClass is null) return;

        var classText = containingClass.ToString().ToLowerInvariant();
        var isPersisted = classText.Contains("entity", StringComparison.Ordinal) ||
                         classText.Contains("model", StringComparison.Ordinal) ||
                         classText.Contains("table", StringComparison.Ordinal) ||
                         classText.Contains("dbset", StringComparison.Ordinal) ||
                         containingClass.AttributeLists.ToString().ToLowerInvariant().Contains("table", StringComparison.Ordinal);

        // Also check if class has property with setter (persisted pattern)
        if (!isPersisted)
        {
            isPersisted = property.AccessorList?.Accessors
                .Any(a => a.IsKind(SyntaxKind.SetAccessorDeclaration)) ?? false;
        }

        if (isPersisted)
        {
            var location = property.Identifier.GetLocation();
            var lineSpan = location.GetLineSpan();
            context.ReportFinding(new Finding(
                new RuleId("SMOL1018"), RuleSeverity.Critical, RulePrecision.Medium,
                $"CVV/CVC '{property.Identifier.Text}' em classe persistida. PCI-DSS Req. 3.2.",
                $"CVV/CVC '{property.Identifier.Text}' in persisted class. PCI-DSS Req. 3.2.",
                new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, property.Identifier.Text),
                [], [312], "A04:2021", ["pci-dss", "cvv", "storage"], 0.75));
        }
    }
}
