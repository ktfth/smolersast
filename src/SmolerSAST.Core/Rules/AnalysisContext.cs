using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Provides registration methods for rules to subscribe to analysis callbacks.
/// Rules register their analysis actions during initialization; the pipeline
/// then invokes those actions during the analysis pass.
/// </summary>
public sealed class AnalysisContext
{
    private readonly List<SyntaxNodeRegistration> _syntaxNodeActions = [];
    private readonly List<SymbolRegistration> _symbolActions = [];

    /// <summary>
    /// Registers a callback to be invoked for every syntax node of the specified kind.
    /// </summary>
    /// <param name="action">The analysis callback.</param>
    /// <param name="syntaxKinds">The syntax kinds to match.</param>
    public void RegisterSyntaxNodeAction(
        Action<SyntaxNodeAnalysisContext> action,
        params SyntaxKind[] syntaxKinds)
    {
        ArgumentNullException.ThrowIfNull(action);
        _syntaxNodeActions.Add(new SyntaxNodeRegistration(action, syntaxKinds));
    }

    /// <summary>
    /// Registers a callback to be invoked for every symbol of the specified kinds.
    /// </summary>
    /// <param name="action">The analysis callback.</param>
    /// <param name="symbolKinds">The symbol kinds to match.</param>
    public void RegisterSymbolAction(
        Action<SymbolAnalysisContext> action,
        params SymbolKind[] symbolKinds)
    {
        ArgumentNullException.ThrowIfNull(action);
        _symbolActions.Add(new SymbolRegistration(action, symbolKinds));
    }

    /// <summary>
    /// Gets all registered syntax node actions.
    /// </summary>
    internal IReadOnlyList<SyntaxNodeRegistration> SyntaxNodeActions => _syntaxNodeActions;

    /// <summary>
    /// Gets all registered symbol actions.
    /// </summary>
    internal IReadOnlyList<SymbolRegistration> SymbolActions => _symbolActions;

    /// <summary>
    /// A registered syntax node analysis action with its matching kinds.
    /// </summary>
    internal sealed record SyntaxNodeRegistration(
        Action<SyntaxNodeAnalysisContext> Action,
        SyntaxKind[] SyntaxKinds);

    /// <summary>
    /// A registered symbol analysis action with its matching kinds.
    /// </summary>
    internal sealed record SymbolRegistration(
        Action<SymbolAnalysisContext> Action,
        SymbolKind[] SymbolKinds);
}
