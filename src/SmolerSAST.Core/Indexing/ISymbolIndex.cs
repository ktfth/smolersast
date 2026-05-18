using Microsoft.CodeAnalysis;

namespace SmolerSAST.Core.Indexing;

/// <summary>
/// Provides indexing and lookup of symbols across a compilation.
/// Supports incremental analysis by persisting the index.
/// </summary>
public interface ISymbolIndex
{
    /// <summary>
    /// Indexes all symbols from the given compilation.
    /// </summary>
    /// <param name="compilation">The compilation to index.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task IndexAsync(Microsoft.CodeAnalysis.Compilation compilation, CancellationToken cancellationToken = default);

    /// <summary>
    /// Looks up a symbol by its fully qualified name.
    /// </summary>
    /// <param name="fullyQualifiedName">The fully qualified symbol name.</param>
    /// <returns>The symbol entries matching the name, or empty if not found.</returns>
    IReadOnlyList<SymbolEntry> Lookup(string fullyQualifiedName);

    /// <summary>
    /// Gets the total number of indexed symbols.
    /// </summary>
    int Count { get; }
}
