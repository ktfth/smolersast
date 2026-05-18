using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.AspNet;

/// <summary>
/// SMOL0029: Detects CustomErrors mode=Off or equivalent in code.
/// </summary>
public sealed class CustomErrorsOffRule : SmolerRule
{
    public override RuleId Id { get; } = new("SMOL0029");
    public override ImmutableArray<int> CweIds { get; } = [209];
    public override string OwaspCategory => "A05:2021";
    public override RuleSeverity Severity => RuleSeverity.Medium;
    public override RulePrecision Precision => RulePrecision.Medium;
    public override ImmutableArray<string> Tags { get; } = ["aspnet", "error-handling"];
    public override string DescriptionPtBr => "CustomErrors desabilitado. Stack traces e detalhes de erros podem ser expostos a atacantes.";
    public override string DescriptionEnUs => "CustomErrors disabled. Stack traces and error details may be exposed to attackers.";
    public override string RemediationGuidancePtBr => "Configure CustomErrors mode=\"RemoteOnly\" ou \"On\" em produção. Use app.UseDeveloperExceptionPage() apenas em ambiente de desenvolvimento.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression.ToString();
        if (methodName.Contains("UseDeveloperExceptionPage", StringComparison.Ordinal) ||
            methodName.Contains("UseDatabaseErrorPage", StringComparison.Ordinal))
        {
            // Check if it's NOT inside an IsDevelopment() check
            var parent = invocation.Parent;
            var inDevCheck = false;
            while (parent is not null)
            {
                if (parent is IfStatementSyntax ifStmt &&
                    ifStmt.Condition.ToString().Contains("IsDevelopment", StringComparison.Ordinal))
                {
                    inDevCheck = true;
                    break;
                }

                parent = parent.Parent;
            }

            if (!inDevCheck)
            {
                var location = invocation.GetLocation();
                var lineSpan = location.GetLineSpan();
                context.ReportFinding(new Finding(
                    new RuleId("SMOL0029"), RuleSeverity.Medium, RulePrecision.Medium,
                    "UseDeveloperExceptionPage() chamado sem verificação de ambiente de desenvolvimento.",
                    "UseDeveloperExceptionPage() called without development environment check.",
                    new FindingLocation(lineSpan.Path ?? "Unknown", lineSpan.StartLinePosition.Line + 1, lineSpan.StartLinePosition.Character, lineSpan.EndLinePosition.Line + 1, lineSpan.EndLinePosition.Character, invocation.ToString()),
                    [], [209], "A05:2021", ["aspnet", "error-handling"], 0.75));
            }
        }
    }
}
