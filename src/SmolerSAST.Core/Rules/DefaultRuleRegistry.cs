using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace SmolerSAST.Core.Rules;

/// <summary>
/// Default implementation of <see cref="IRuleRegistry"/>.
/// Rules are registered during initialization; the registry is immutable after that.
/// </summary>
public sealed class DefaultRuleRegistry : IRuleRegistry
{
    private readonly Dictionary<RuleId, SmolerRule> _rules = [];
    private ImmutableArray<SmolerRule>? _frozen;

    /// <inheritdoc />
    public void Register(SmolerRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        if (_frozen.HasValue)
        {
            throw new InvalidOperationException("Cannot register rules after the registry has been read.");
        }

        if (!_rules.TryAdd(rule.Id, rule))
        {
            throw new InvalidOperationException($"A rule with ID '{rule.Id}' is already registered.");
        }
    }

    /// <inheritdoc />
    public ImmutableArray<SmolerRule> GetAll()
    {
        _frozen ??= [.. _rules.Values.OrderBy(r => r.Id)];
        return _frozen.Value;
    }

    /// <inheritdoc />
    public bool TryGetById(RuleId id, [NotNullWhen(true)] out SmolerRule? rule) =>
        _rules.TryGetValue(id, out rule);

    /// <summary>
    /// Discovers and registers all <see cref="SmolerRule"/> subclasses in the given assemblies.
    /// </summary>
    /// <param name="assemblyMarkerTypes">Marker types whose assemblies will be scanned for rule implementations.</param>
    public void DiscoverRules(params Type[] assemblyMarkerTypes)
    {
        foreach (var markerType in assemblyMarkerTypes)
        {
            var assembly = markerType.Assembly;
            foreach (var type in assembly.GetTypes())
            {
                if (type.IsAbstract || !type.IsSubclassOf(typeof(SmolerRule)))
                {
                    continue;
                }

                if (Activator.CreateInstance(type) is SmolerRule rule)
                {
                    Register(rule);
                }
            }
        }
    }
}
