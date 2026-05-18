namespace SmolerSAST.Core.Indexing;

/// <summary>
/// Represents an indexed symbol for fast lookup across the project.
/// </summary>
/// <param name="FullyQualifiedName">The fully qualified name (e.g., "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter").</param>
/// <param name="Kind">The kind of symbol (Type, Method, Property, Field).</param>
/// <param name="ContainingAssembly">The assembly containing this symbol.</param>
/// <param name="ContainingType">The containing type, if applicable.</param>
/// <param name="FilePath">Source file path, if available.</param>
/// <param name="Line">Line number in source, if available.</param>
public sealed record SymbolEntry(
    string FullyQualifiedName,
    SymbolEntryKind Kind,
    string ContainingAssembly,
    string? ContainingType,
    string? FilePath,
    int? Line);

/// <summary>
/// The kind of an indexed symbol.
/// </summary>
public enum SymbolEntryKind
{
    /// <summary>A named type (class, struct, interface, enum).</summary>
    Type,

    /// <summary>A method or function.</summary>
    Method,

    /// <summary>A property.</summary>
    Property,

    /// <summary>A field.</summary>
    Field,
}
