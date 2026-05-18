using System.Collections.Immutable;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Tests.Rules;

public sealed class FindingTests
{
    [Fact]
    public void Finding_IsImmutableRecord()
    {
        var finding = CreateSampleFinding();

        Assert.Equal("SMOL0009", finding.RuleId.ToString());
        Assert.Equal(RuleSeverity.Critical, finding.Severity);
        Assert.Equal(1.0, finding.Confidence);
        Assert.Equal("Test message pt-BR", finding.MessagePtBr);
    }

    [Fact]
    public void Finding_WithExpression_CreatesNewInstance()
    {
        var original = CreateSampleFinding();
        var modified = original with { Confidence = 0.5 };

        Assert.Equal(1.0, original.Confidence);
        Assert.Equal(0.5, modified.Confidence);
        Assert.NotEqual(original, modified);
    }

    [Fact]
    public void Finding_SameData_HasConsistentProperties()
    {
        var a = CreateSampleFinding();
        var b = CreateSampleFinding();

        Assert.Equal(a.RuleId, b.RuleId);
        Assert.Equal(a.Severity, b.Severity);
        Assert.Equal(a.Confidence, b.Confidence);
        Assert.Equal(a.Location, b.Location);
        Assert.Equal(a.MessagePtBr, b.MessagePtBr);
    }

    [Fact]
    public void FindingLocation_RecordsProperties()
    {
        var loc = new FindingLocation("test.cs", 10, 5, 10, 30, "var x = 1;");

        Assert.Equal("test.cs", loc.FilePath);
        Assert.Equal(10, loc.StartLine);
        Assert.Equal(5, loc.StartColumn);
        Assert.Equal(10, loc.EndLine);
        Assert.Equal(30, loc.EndColumn);
        Assert.Equal("var x = 1;", loc.CodeExcerpt);
    }

    private static Finding CreateSampleFinding() => new(
        RuleId: new RuleId("SMOL0009"),
        Severity: RuleSeverity.Critical,
        Precision: RulePrecision.High,
        MessagePtBr: "Test message pt-BR",
        MessageEnUs: "Test message en-US",
        Location: new FindingLocation("test.cs", 1, 0, 1, 10, "test code"),
        AdditionalLocations: ImmutableArray<FindingLocation>.Empty,
        CweIds: [502],
        OwaspCategory: "A08:2021",
        Tags: ["deserialization"],
        Confidence: 1.0);
}
