using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Deserialization;

namespace SmolerSAST.Rules.Base.Tests.Deserialization;

public sealed class BinaryFormatterUsageRuleTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // POSITIVE CASES — MUST detect
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Positive1_DirectInstantiation_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0011
            using System.IO;
            using System.Runtime.Serialization.Formatters.Binary;

            public class Test
            {
                public object? Read(Stream s)
                {
                    var formatter = new BinaryFormatter();
                    return formatter.Deserialize(s);
                }
            }
            """;

        var findings = await RunAnalysis(source);

        // Should detect both: new BinaryFormatter() and .Deserialize()
        Assert.True(findings.Length >= 2, $"Expected >= 2 findings, got {findings.Length}");
        Assert.All(findings, f =>
        {
            Assert.Equal(new RuleId("SMOL0009"), f.RuleId);
            Assert.Equal(RuleSeverity.Critical, f.Severity);
            Assert.Equal(1.0, f.Confidence);
        });
    }

    [Fact]
    public async Task Positive2_IndirectUsage_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0011
            using System.IO;
            using System.Runtime.Serialization.Formatters.Binary;

            public class Test
            {
                public void Write(Stream s, object data)
                {
                    BinaryFormatter bf = new();
                    bf.Serialize(s, data);
                }
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.True(findings.Length >= 2, $"Expected >= 2 findings (new + Serialize), got {findings.Length}");
    }

    [Fact]
    public async Task Positive3_TypeOfBinaryFormatter_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0011
            using System;
            using System.Runtime.Serialization.Formatters.Binary;

            public class Test
            {
                public Type GetType() => typeof(BinaryFormatter);
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.Contains(findings, f =>
            f.MessageEnUs.Contains("typeof", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Positive4_HelperMethod_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0011
            using System.IO;
            using System.Runtime.Serialization.Formatters.Binary;

            public static class Helper
            {
                public static object? Deserialize(Stream input)
                {
                    var fmt = new BinaryFormatter();
                    return fmt.Deserialize(input);
                }
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.True(findings.Length >= 1, "Should detect BinaryFormatter in helper methods");
    }

    [Fact]
    public async Task Positive5_WithSurrogateSelector_StillDetected()
    {
        const string source = """
            #pragma warning disable SYSLIB0011
            #pragma warning disable SYSLIB0050
            using System.IO;
            using System.Runtime.Serialization;
            using System.Runtime.Serialization.Formatters.Binary;

            public class Test
            {
                public object? Read(Stream s)
                {
                    var formatter = new BinaryFormatter
                    {
                        SurrogateSelector = new SurrogateSelector()
                    };
                    return formatter.Deserialize(s);
                }
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.True(findings.Length >= 1,
            "BinaryFormatter with SurrogateSelector is still insecure and must be detected");
    }

    // ═══════════════════════════════════════════════════════
    // NEGATIVE CASES — MUST NOT detect
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Negative1_JsonSerializer_NotDetected()
    {
        const string source = """
            using System.Text.Json;

            public class Test
            {
                public T? Read<T>(string json) => JsonSerializer.Deserialize<T>(json);
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative2_UserDefinedBinaryFormatter_NotDetected()
    {
        // This is the CRITICAL test — proves we use symbol resolution, not string matching.
        // A user-defined class named "BinaryFormatter" in a different namespace
        // MUST NOT be flagged.
        const string source = """
            namespace MyApp.Formatting
            {
                public class BinaryFormatter
                {
                    public string Format(byte[] data) => System.Convert.ToBase64String(data);
                }

                public class Consumer
                {
                    public string Use(byte[] data)
                    {
                        var formatter = new BinaryFormatter();
                        return formatter.Format(data);
                    }
                }
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative3_CommentMention_NotDetected()
    {
        const string source = """
            public class Test
            {
                // We used to use BinaryFormatter but switched to JSON.
                // BinaryFormatter is dangerous and should never be used.
                /// <summary>BinaryFormatter replacement method.</summary>
                public string Safe() => "safe";
            }
            """;

        var findings = await RunAnalysis(source);

        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // Rule metadata
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void RuleMetadata_IsCorrect()
    {
        var rule = new BinaryFormatterUsageRule();

        Assert.Equal(new RuleId("SMOL0009"), rule.Id);
        Assert.Contains(502, rule.CweIds);
        Assert.Equal("A08:2021", rule.OwaspCategory);
        Assert.Equal(RuleSeverity.Critical, rule.Severity);
        Assert.Equal(RulePrecision.High, rule.Precision);
        Assert.Contains("deserialization", rule.Tags);
        Assert.False(string.IsNullOrEmpty(rule.DescriptionPtBr));
        Assert.False(string.IsNullOrEmpty(rule.DescriptionEnUs));
        Assert.False(string.IsNullOrEmpty(rule.RemediationGuidancePtBr));
    }

    // ═══════════════════════════════════════════════════════
    // Helper
    // ═══════════════════════════════════════════════════════

    private static async Task<ImmutableArray<Finding>> RunAnalysis(string source)
    {
        var acquirer = new InMemoryCompilationAcquirer([source], References);
        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());

        var symbolIndex = new InMemorySymbolIndex();
        var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);
        var options = new AnalysisPipelineOptions("test");

        var result = await pipeline.RunAsync(options);
        return result.Findings;
    }
}
