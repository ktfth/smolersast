using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Registry of all available <see cref="SmolerRule"/> instances.
/// Populated at startup, frozen after initialization.
/// </summary>
public interface IRuleRegistry
{
    /// <summary>
    /// Registers a rule instance. Must be called before the registry is frozen.
    /// </summary>
    /// <param name="rule">The rule to register.</param>
    /// <exception cref="InvalidOperationException">Thrown if a rule with the same ID is already registered.</exception>
    void Register(SmolerRule rule);

    /// <summary>
    /// Gets all registered rules.
    /// </summary>
    ImmutableArray<SmolerRule> GetAll();

    /// <summary>
    /// Tries to get a rule by its identifier.
    /// </summary>
    /// <param name="id">The rule ID to look up.</param>
    /// <param name="rule">The found rule, or null.</param>
    /// <returns>True if the rule was found.</returns>
    bool TryGetById(RuleId id, [NotNullWhen(true)] out SmolerRule? rule);
}
