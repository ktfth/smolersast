using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Tests.Rules;

public sealed class RuleIdTests
{
    [Theory]
    [InlineData("SMOL0001")]
    [InlineData("SMOL0009")]
    [InlineData("SMOL1234")]
    [InlineData("SMOL9999")]
    public void Constructor_ValidFormat_Succeeds(string value)
    {
        var id = new RuleId(value);
        Assert.Equal(value, id.Value);
        Assert.Equal(value, id.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("SMOL")]
    [InlineData("SMOL000")]
    [InlineData("SMOL00001")]
    [InlineData("smol0001")]
    [InlineData("RULE0001")]
    [InlineData("SMOLABCD")]
    [InlineData("SMOL 001")]
    public void Constructor_InvalidFormat_ThrowsArgumentException(string value)
    {
        Assert.Throws<ArgumentException>(() => new RuleId(value));
    }

    [Fact]
    public void Constructor_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new RuleId(null!));
    }

    [Fact]
    public void Equality_SameValue_AreEqual()
    {
        var a = new RuleId("SMOL0009");
        var b = new RuleId("SMOL0009");

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Equality_DifferentValue_AreNotEqual()
    {
        var a = new RuleId("SMOL0001");
        var b = new RuleId("SMOL0009");

        Assert.NotEqual(a, b);
        Assert.True(a != b);
    }

    [Fact]
    public void CompareTo_OrdersCorrectly()
    {
        var a = new RuleId("SMOL0001");
        var b = new RuleId("SMOL0009");
        var c = new RuleId("SMOL1001");

        var a2 = new RuleId("SMOL0001");
        var c2 = new RuleId("SMOL1001");

        Assert.True(a < b);
        Assert.True(b < c);
        Assert.True(a <= a2);
        Assert.True(c > b);
        Assert.True(c >= c2);
    }
}
