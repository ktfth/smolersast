using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Pipeline;

/// <summary>
/// The result of an analysis pipeline run, containing all findings and run metadata.
/// </summary>
/// <param name="Findings">All security findings detected during the analysis.</param>
/// <param name="BuildDiagnostics">Build diagnostics (warnings/errors) encountered during compilation acquisition.</param>
/// <param name="Duration">Total wall-clock duration of the analysis.</param>
/// <param name="PeakMemoryBytes">Peak memory usage in bytes during the analysis.</param>
/// <param name="Mode">How the compilation was acquired.</param>
/// <param name="RulesExecuted">Number of rules that were executed.</param>
/// <param name="SyntaxTreesAnalyzed">Number of syntax trees that were analyzed.</param>
public sealed record PipelineResult(
    ImmutableArray<Finding> Findings,
    ImmutableArray<Diagnostic> BuildDiagnostics,
    TimeSpan Duration,
    long PeakMemoryBytes,
    CompilationMode Mode,
    int RulesExecuted,
    int SyntaxTreesAnalyzed);
