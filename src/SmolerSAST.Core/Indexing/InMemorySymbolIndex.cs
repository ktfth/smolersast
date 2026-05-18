using Microsoft.CodeAnalysis;

namespace SmolerSAST.Core.Indexing;

/// <summary>
/// In-memory symbol index for fast lookups during analysis.
/// Does not persist to disk — suitable for single-run analysis and testing.
/// </summary>
public sealed class InMemorySymbolIndex : ISymbolIndex
{
    private readonly Dictionary<string, List<SymbolEntry>> _index = [];

    /// <inheritdoc />
    public int Count { get; private set; }

    /// <inheritdoc />
    public Task IndexAsync(Microsoft.CodeAnalysis.Compilation compilation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(compilation);

        var visitor = new SymbolIndexVisitor(this);
        visitor.Visit(compilation.GlobalNamespace);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public IReadOnlyList<SymbolEntry> Lookup(string fullyQualifiedName)
    {
        ArgumentNullException.ThrowIfNull(fullyQualifiedName);

        return _index.TryGetValue(fullyQualifiedName, out var entries)
            ? entries
            : [];
    }

    private void AddEntry(SymbolEntry entry)
    {
        if (!_index.TryGetValue(entry.FullyQualifiedName, out var list))
        {
            list = [];
            _index[entry.FullyQualifiedName] = list;
        }

        list.Add(entry);
        Count++;
    }

    private sealed class SymbolIndexVisitor(InMemorySymbolIndex index) : SymbolVisitor
    {
        public override void VisitNamespace(INamespaceSymbol symbol)
        {
            foreach (var member in symbol.GetMembers())
            {
                member.Accept(this);
            }
        }

        public override void VisitNamedType(INamedTypeSymbol symbol)
        {
            var location = symbol.Locations.FirstOrDefault();
            index.AddEntry(new SymbolEntry(
                symbol.ToDisplayString(),
                SymbolEntryKind.Type,
                symbol.ContainingAssembly?.Name ?? "Unknown",
                symbol.ContainingType?.ToDisplayString(),
                location?.SourceTree?.FilePath,
                location?.GetLineSpan().StartLinePosition.Line));

            foreach (var member in symbol.GetMembers())
            {
                member.Accept(this);
            }
        }

        public override void VisitMethod(IMethodSymbol symbol)
        {
            if (symbol.MethodKind is MethodKind.Ordinary or MethodKind.Constructor)
            {
                var location = symbol.Locations.FirstOrDefault();
                index.AddEntry(new SymbolEntry(
                    symbol.ToDisplayString(),
                    SymbolEntryKind.Method,
                    symbol.ContainingAssembly?.Name ?? "Unknown",
                    symbol.ContainingType?.ToDisplayString(),
                    location?.SourceTree?.FilePath,
                    location?.GetLineSpan().StartLinePosition.Line));
            }
        }

        public override void VisitProperty(IPropertySymbol symbol)
        {
            var location = symbol.Locations.FirstOrDefault();
            index.AddEntry(new SymbolEntry(
                symbol.ToDisplayString(),
                SymbolEntryKind.Property,
                symbol.ContainingAssembly?.Name ?? "Unknown",
                symbol.ContainingType?.ToDisplayString(),
                location?.SourceTree?.FilePath,
                location?.GetLineSpan().StartLinePosition.Line));
        }

        public override void VisitField(IFieldSymbol symbol)
        {
            if (!symbol.IsImplicitlyDeclared)
            {
                var location = symbol.Locations.FirstOrDefault();
                index.AddEntry(new SymbolEntry(
                    symbol.ToDisplayString(),
                    SymbolEntryKind.Field,
                    symbol.ContainingAssembly?.Name ?? "Unknown",
                    symbol.ContainingType?.ToDisplayString(),
                    location?.SourceTree?.FilePath,
                    location?.GetLineSpan().StartLinePosition.Line));
            }
        }
    }
}
