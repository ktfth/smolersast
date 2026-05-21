using System.Collections.Immutable;

namespace SmolerSAST.Core.Taint;

/// <summary>
/// Represents a tainted value flowing through the program.
/// Tracks the taint label, source location, and propagation path.
/// </summary>
public sealed record TaintedValue(
    string SymbolName,
    TaintLabel Label,
    TaintLocation Source,
    ImmutableArray<TaintLocation> PropagationPath)
{
    /// <summary>
    /// Creates a new tainted value with an additional step in the propagation path.
    /// </summary>
    public TaintedValue WithStep(TaintLocation step)
    {
        return this with { PropagationPath = PropagationPath.Add(step) };
    }
}

/// <summary>
/// A location in the taint propagation path.
/// </summary>
public sealed record TaintLocation(
    string FilePath,
    int Line,
    int Column,
    string Description);
