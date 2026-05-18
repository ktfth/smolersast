using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Configuration;

/// <summary>
/// SMOL0033: Detects hardcoded API keys, connection strings with passwords, and other secrets in code.
/// </summary>
public sealed class HardcodedSecretRule : SmolerRule
{
    private static readonly string[] SecretPatterns =
    [
        "password", "passwd", "pwd", "secret", "apikey", "api_key", "api-key",
        "connectionstring", "conn_str", "token", "bearer", "authorization",
        "private_key", "privatekey", "access_key", "accesskey",
    ];

    public override RuleId Id { get; } = new("SMOL0033");
    public override ImmutableArray<int> CweIds { get; } = [798];
    public override string OwaspCategory => "A07:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["secrets", "configuration"];
    public override string DescriptionPtBr => "Segredo hardcoded detectado no código-fonte. Credenciais não devem ser armazenadas em código.";
    public override string DescriptionEnUs => "Hardcoded secret detected in source code. Credentials must not be stored in code.";
    public override string RemediationGuidancePtBr => "Use variáveis de ambiente, User Secrets (desenvolvimento) ou Azure Key Vault / AWS Secrets Manager (produção).";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
        context.RegisterSyntaxNodeAction(AnalyzeFieldDeclaration, SyntaxKind.FieldDeclaration);
        context.RegisterSyntaxNodeAction(AnalyzeLocalDeclaration, SyntaxKind.LocalDeclarationStatement);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AssignmentExpressionSyntax assignment) return;
        if (assignment.Right is not LiteralExpressionSyntax literal || !literal.IsKind(SyntaxKind.StringLiteralExpression)) return;

        var varName = assignment.Left.ToString();
        if (IsSecretName(varName) && literal.Token.ValueText.Length >= 8)
        {
            Report(context, assignment, varName);
        }
    }

    private static void AnalyzeFieldDeclaration(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not FieldDeclarationSyntax field) return;
        foreach (var variable in field.Declaration.Variables)
        {
            if (variable.Initializer?.Value is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression) &&
                IsSecretName(variable.Identifier.Text) &&
                literal.Token.ValueText.Length >= 8)
            {
                Report(context, field, variable.Identifier.Text);
            }
        }
    }

    private static void AnalyzeLocalDeclaration(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not LocalDeclarationStatementSyntax local) return;
        foreach (var variable in local.Declaration.Variables)
        {
            if (variable.Initializer?.Value is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression) &&
                IsSecretName(variable.Identifier.Text) &&
                literal.Token.ValueText.Length >= 8)
            {
                Report(context, local, variable.Identifier.Text);
            }
        }
    }

    private static bool IsSecretName(string name)
    {
        var lower = name.ToLowerInvariant();
        return SecretPatterns.Any(p => lower.Contains(p, StringComparison.Ordinal));
    }

    private static void Report(SyntaxNodeAnalysisContext context, SyntaxNode node, string varName)
    {
        var location = node.GetLocation();
        var lineSpan = location.GetLineSpan();
        context.ReportFinding(new Finding(
            new RuleId("SMOL0033"), RuleSeverity.Critical, RulePrecision.Medium,
            $"Segredo hardcoded em '{varName}'. Use variáveis de ambiente ou secret manager.",
            $"Hardcoded secret in '{varName}'. Use environment variables or secret manager.",
            new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, node.ToString()),
            [], [798], "A07:2021", ["secrets", "configuration"], 0.8));
    }
}
