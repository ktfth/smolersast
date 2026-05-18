using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0022: Detects <c>System.Random</c> used in security-sensitive contexts.
/// System.Random is not cryptographically secure and must not be used for
/// generating tokens, keys, salts, nonces, or passwords — CWE-338.
/// </summary>
public sealed class SystemRandomSecurityContextRule : SmolerRule
{
    private const string SystemRandomFullName = "System.Random";

    private static readonly ImmutableHashSet<string> SecurityKeywords = ImmutableHashSet.Create(
        StringComparer.OrdinalIgnoreCase,
        "token", "key", "secret", "password", "salt", "nonce",
        "credential", "auth", "crypto", "encrypt", "cipher");

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0022");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [338];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.Medium;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "weak-random"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de System.Random em contexto de segurança detectado. " +
        "System.Random não é criptograficamente seguro e não deve ser usado para gerar tokens, chaves, salts ou nonces.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "System.Random used in security context detected. " +
        "System.Random is not cryptographically secure and must not be used for generating tokens, keys, salts, or nonces.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Substitua System.Random por RandomNumberGenerator para contextos de segurança.

        ```csharp
        // ANTES (inseguro):
        var random = new Random();
        var token = random.Next().ToString();

        // DEPOIS (seguro):
        var bytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(bytes);
        ```

        Referência: https://learn.microsoft.com/dotnet/api/system.security.cryptography.randomnumbergenerator
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression,
            SyntaxKind.ImplicitObjectCreationExpression);
    }

    private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var typeInfo = context.SemanticModel.GetTypeInfo(context.Node);
        if (typeInfo.Type is null ||
            !string.Equals(typeInfo.Type.ToDisplayString(), SystemRandomFullName, StringComparison.Ordinal))
        {
            return;
        }

        // Check if this is in a security-sensitive context
        if (!IsInSecurityContext(context.Node))
        {
            return;
        }

        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: "Uso de System.Random em contexto de segurança detectado.",
            MessageEnUs: "System.Random used in security-sensitive context detected.",
            Location: new FindingLocation(
                FilePath: lineSpan.Path ?? "Unknown",
                StartLine: lineSpan.StartLinePosition.Line + 1,
                StartColumn: lineSpan.StartLinePosition.Character,
                EndLine: lineSpan.EndLinePosition.Line + 1,
                EndColumn: lineSpan.EndLinePosition.Character,
                CodeExcerpt: context.Node.ToString()),
            AdditionalLocations: [],
            CweIds: CweIds,
            OwaspCategory: OwaspCategory,
            Tags: Tags,
            Confidence: 0.8);

        context.ReportFinding(finding);
    }

    private static bool IsInSecurityContext(SyntaxNode node)
    {
        var current = node.Parent;
        while (current is not null)
        {
            switch (current)
            {
                case MethodDeclarationSyntax method:
                    if (ContainsSecurityKeyword(method.Identifier.Text))
                    {
                        return true;
                    }

                    break;

                case ClassDeclarationSyntax classDecl:
                    if (ContainsSecurityKeyword(classDecl.Identifier.Text))
                    {
                        return true;
                    }

                    break;

                case LocalDeclarationStatementSyntax localDecl:
                    foreach (var variable in localDecl.Declaration.Variables)
                    {
                        if (ContainsSecurityKeyword(variable.Identifier.Text))
                        {
                            return true;
                        }
                    }

                    break;

                case FieldDeclarationSyntax fieldDecl:
                    foreach (var variable in fieldDecl.Declaration.Variables)
                    {
                        if (ContainsSecurityKeyword(variable.Identifier.Text))
                        {
                            return true;
                        }
                    }

                    break;

                case PropertyDeclarationSyntax propDecl:
                    if (ContainsSecurityKeyword(propDecl.Identifier.Text))
                    {
                        return true;
                    }

                    break;
            }

            current = current.Parent;
        }

        return false;
    }

    private static bool ContainsSecurityKeyword(string identifier)
    {
        foreach (var keyword in SecurityKeywords)
        {
            if (identifier.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
