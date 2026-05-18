using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Deserialization;

namespace SmolerSAST.Core.Tests.Rules;

public sealed class DefaultRuleRegistryTests
{
    [Fact]
    public void Register_ValidRule_Succeeds()
    {
        var registry = new DefaultRuleRegistry();
        var rule = new BinaryFormatterUsageRule();

        registry.Register(rule);

        Assert.True(registry.TryGetById(new RuleId("SMOL0009"), out var found));
        Assert.Same(rule, found);
    }

    [Fact]
    public void Register_DuplicateId_ThrowsInvalidOperation()
    {
        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());

        Assert.Throws<InvalidOperationException>(() =>
            registry.Register(new BinaryFormatterUsageRule()));
    }

    [Fact]
    public void Register_Null_ThrowsArgumentNull()
    {
        var registry = new DefaultRuleRegistry();
        Assert.Throws<ArgumentNullException>(() => registry.Register(null!));
    }

    [Fact]
    public void GetAll_ReturnsRegisteredRules_SortedById()
    {
        var registry = new DefaultRuleRegistry();
        var rule = new BinaryFormatterUsageRule();
        registry.Register(rule);

        var all = registry.GetAll();

        Assert.Single(all);
        Assert.Equal(new RuleId("SMOL0009"), all[0].Id);
    }

    [Fact]
    public void Register_AfterGetAll_ThrowsInvalidOperation()
    {
        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());
        _ = registry.GetAll(); // Freezes the registry

        Assert.Throws<InvalidOperationException>(() =>
            registry.Register(new BinaryFormatterUsageRule()));
    }

    [Fact]
    public void TryGetById_NotRegistered_ReturnsFalse()
    {
        var registry = new DefaultRuleRegistry();

        Assert.False(registry.TryGetById(new RuleId("SMOL0001"), out var rule));
        Assert.Null(rule);
    }
}
