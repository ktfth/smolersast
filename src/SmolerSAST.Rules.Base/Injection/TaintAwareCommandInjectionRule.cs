using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;
using SmolerSAST.Core.Taint;

namespace SmolerSAST.Rules.Base.Injection;

/// <summary>
/// SMOL0042: Taint-aware command injection detection.
/// Traces user input to Process.Start and similar command execution sinks.
/// </summary>
public sealed class TaintAwareCommandInjectionRule : SmolerRule
{
    private static readonly IntraproceduralTaintAnalyzer Analyzer = new(
        TaintSourceRegistry.CreateDefault(),
        TaintSinkRegistry.CreateDefault(),
        TaintSanitizerRegistry.CreateDefault());

    public override RuleId Id { get; } = new("SMOL0042");
    public override ImmutableArray<int> CweIds { get; } = [78];
    public override string OwaspCategory => "A03:2021";
    public override RuleSeverity Severity => RuleSeverity.Critical;
    public override RulePrecision Precision => RulePrecision.High;
    public override ImmutableArray<string> Tags { get; } = ["injection", "command", "taint"];
    public override string DescriptionPtBr => "Command injection detectada via análise de fluxo de dados. Input do usuário flui para execução de comando do sistema.";
    public override string DescriptionEnUs => "Command injection detected via data flow analysis. User input flows to system command execution.";
    public override string RemediationGuidancePtBr => "Nunca passe input do usuário para Process.Start ou cmd.exe. Use allowlists e validação estrita de argumentos.";

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
            if (flow.SinkDescriptor.Category != "command-injection") continue;

            var additionalLocations = flow.Source.PropagationPath
                .Select(p => new FindingLocation(p.FilePath, p.Line, p.Column, p.Line, p.Column, p.Description))
                .ToImmutableArray();

            var location = new FindingLocation(
                flow.Sink.FilePath, flow.Sink.Line, flow.Sink.Column,
                flow.Sink.Line, flow.Sink.Column, flow.Sink.Description);

            context.ReportFinding(new Finding(
                new RuleId("SMOL0042"), RuleSeverity.Critical, RulePrecision.High,
                $"Command injection via taint: {flow.Source.Source.Description} → {flow.Sink.Description}",
                $"Command injection via taint: {flow.Source.Source.Description} → {flow.Sink.Description}",
                location, additionalLocations, [78], "A03:2021",
                ["injection", "command", "taint"], flow.Confidence));
        }
    }
}
