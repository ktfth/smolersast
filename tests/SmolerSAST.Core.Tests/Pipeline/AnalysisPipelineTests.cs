using System.Collections.Immutable;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Core.Tests.Helpers;
using SmolerSAST.Rules.Base.Deserialization;

namespace SmolerSAST.Core.Tests.Pipeline;

public sealed class AnalysisPipelineTests
{
    [Fact]
    public async Task RunAsync_WithBinaryFormatterRule_DetectsVulnerability()
    {
        const string vulnerableSource = """
            #pragma warning disable SYSLIB0011
            using System.IO;
            using System.Runtime.Serialization.Formatters.Binary;

            public class Vulnerable
            {
                public object? Read(Stream s)
                {
                    var bf = new BinaryFormatter();
                    return bf.Deserialize(s);
                }
            }
            """;

        var references = InMemoryCompilationAcquirer.GetRuntimeReferences();
        var acquirer = new InMemoryCompilationAcquirer(
            [vulnerableSource],
            references);

        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());

        var symbolIndex = new InMemorySymbolIndex();
        var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);
        var options = new AnalysisPipelineOptions("test");

        var result = await pipeline.RunAsync(options);

        Assert.True(result.Findings.Length > 0, "Should detect BinaryFormatter usage");
        Assert.All(result.Findings, f => Assert.Equal(new RuleId("SMOL0009"), f.RuleId));
        Assert.Equal(1, result.RulesExecuted);
        Assert.True(result.Duration > TimeSpan.Zero);
    }

    [Fact]
    public async Task RunAsync_SafeCode_NoFindings()
    {
        const string safeSource = """
            using System.Text.Json;

            public class Safe
            {
                public T? Read<T>(string json) => JsonSerializer.Deserialize<T>(json);
            }
            """;

        var references = InMemoryCompilationAcquirer.GetRuntimeReferences();
        var acquirer = new InMemoryCompilationAcquirer([safeSource], references);

        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());

        var symbolIndex = new InMemorySymbolIndex();
        var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);
        var options = new AnalysisPipelineOptions("test");

        var result = await pipeline.RunAsync(options);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task RunAsync_NullOptions_ThrowsArgumentNull()
    {
        var references = InMemoryCompilationAcquirer.GetRuntimeReferences();
        var acquirer = new InMemoryCompilationAcquirer(["class A {}"], references);
        var registry = new DefaultRuleRegistry();
        var symbolIndex = new InMemorySymbolIndex();
        var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);

        await Assert.ThrowsAsync<ArgumentNullException>(() => pipeline.RunAsync(null!));
    }

    [Fact]
    public void Constructor_NullAcquirer_ThrowsArgumentNull()
    {
        var registry = new DefaultRuleRegistry();
        var symbolIndex = new InMemorySymbolIndex();

        Assert.Throws<ArgumentNullException>(() =>
            new AnalysisPipeline(null!, registry, symbolIndex));
    }
}
