using Microsoft.CodeAnalysis;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Context provided to rule callbacks for symbol analysis.
/// </summary>
/// <param name="Symbol">The symbol being analyzed.</param>
/// <param name="Compilation">The compilation containing the symbol.</param>
/// <param name="ReportFinding">Callback to report a finding. Thread-safe.</param>
public sealed record SymbolAnalysisContext(
    ISymbol Symbol,
    Microsoft.CodeAnalysis.Compilation Compilation,
    Action<Finding> ReportFinding);
