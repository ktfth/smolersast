using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Compilation;

/// <summary>
/// The result of compilation acquisition — a Roslyn <see cref="CSharpCompilation"/>
/// with its syntax trees and the mode indicating how it was obtained.
/// </summary>
/// <param name="Compilation">The Roslyn compilation with full semantic model.</param>
/// <param name="SyntaxTrees">All syntax trees in the compilation.</param>
/// <param name="Mode">How the compilation was acquired (source or binary).</param>
/// <param name="Diagnostics">Any build diagnostics encountered during acquisition.</param>
public sealed record AcquiredCompilation(
    CSharpCompilation Compilation,
    ImmutableArray<SyntaxTree> SyntaxTrees,
    CompilationMode Mode,
    ImmutableArray<Diagnostic> Diagnostics);
