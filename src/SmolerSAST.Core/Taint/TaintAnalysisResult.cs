using System.Collections.Immutable;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Taint;

/// <summary>
/// Result of a taint analysis on a single method.
/// Contains all detected taint flows from source to sink.
/// </summary>
public sealed record TaintFlow(
    TaintedValue Source,
    TaintLocation Sink,
    SinkDescriptor SinkDescriptor,
    double Confidence);

/// <summary>
/// Aggregated taint analysis result for the entire compilation.
/// </summary>
public sealed record TaintAnalysisResult(
    ImmutableArray<TaintFlow> Flows,
    int MethodsAnalyzed);
