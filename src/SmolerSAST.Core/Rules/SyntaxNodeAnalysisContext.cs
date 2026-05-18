using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Context provided to rule callbacks for syntax node analysis.
/// Wraps a <see cref="SyntaxNode"/> with its <see cref="SemanticModel"/>.
/// </summary>
/// <param name="Node">The syntax node being analyzed.</param>
/// <param name="SemanticModel">The semantic model for the containing document.</param>
/// <param name="ReportFinding">Callback to report a finding. Thread-safe.</param>
public sealed record SyntaxNodeAnalysisContext(
    SyntaxNode Node,
    SemanticModel SemanticModel,
    Action<Finding> ReportFinding);
