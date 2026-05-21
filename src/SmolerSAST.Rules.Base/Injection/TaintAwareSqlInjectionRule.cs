using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;
using SmolerSAST.Core.Taint;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0041: Taint-aware SQL injection detection.
/// Traces user input from controller parameters through method bodies to SQL execution sinks.
/// Higher confidence than pattern-matching rules because it verifies the data flow path.
/// </summary>
public sealed class TaintAwareSqlInjectionRule : SmolerRule
{
    private static readonly IntraproceduralTaintAnalyzer Analyzer = new(
        TaintSourceRegistry.CreateDefault(),
        TaintSinkRegistry.CreateDefault(),
        TaintSanitizerRegistry.CreateDefault());

    public override RuleId Id { get; } = new("SMOL0041");
    public override ImmutableArray<int> CweIds { get; } = [89];
    public override string OwaspCategory => "A03:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.High;
    public override ImmutableArray<string> Tags { get; } = ["injection", "sql", "taint"];
    public override string DescriptionPtBr => "SQL injection detectada via análise de fluxo de dados (taint analysis). Input do usuário flui para execução SQL sem sanitização.";
    public override string DescriptionEnUs => "SQL injection detected via data flow analysis (taint analysis). User input flows to SQL execution without sanitization.";
    public override string RemediationGuidancePtBr => "Use queries parametrizadas (SqlParameter, Dapper @param, EF Core). Nunca concatene input do usuário em SQL.";

    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MethodDeclarationSyntax method) return;
        if (method.Body is null && method.ExpressionBody is null) return;

        var flows = Analyzer.AnalyzeMethod(method, context.SemanticModel);

        foreach (var flow in flows)
        {
            if (flow.SinkDescriptor.Category != "sql-injection") continue;

            var pathDescription = BuildPathDescription(flow);
            var additionalLocations = flow.Source.PropagationPath
                .Select(p => new FindingLocation(p.FilePath, p.Line, p.Column, p.Line, p.Column, p.Description))
                .ToImmutableArray();

            var location = new FindingLocation(
                flow.Sink.FilePath,
                flow.Sink.Line,
                flow.Sink.Column,
                flow.Sink.Line,
                flow.Sink.Column,
                flow.Sink.Description);

            context.ReportFinding(new Finding(
                new RuleId("SMOL0041"), RuleSeverity.Critical, RulePrecision.High,
                $"SQL injection via taint analysis: {pathDescription}",
                $"SQL injection via taint analysis: {pathDescription}",
                location,
                additionalLocations,
                [89], "A03:2021", ["injection", "sql", "taint"],
                flow.Confidence));
        }
    }

    private static string BuildPathDescription(TaintFlow flow)
    {
        var source = flow.Source.Source.Description;
        var sink = flow.Sink.Description;
        var steps = flow.Source.PropagationPath.Length;
        return $"{source} → ({steps} step(s)) → {sink}";
    }
}
