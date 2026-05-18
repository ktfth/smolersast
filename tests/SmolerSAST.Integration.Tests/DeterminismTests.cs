using Xunit;
using System.Text.RegularExpressions;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Reporting;
using SmolerSAST.Rules.Base.Cryptography;
using SmolerSAST.Rules.Base.Deserialization;
using SmolerSAST.Rules.Base.Injection;
using SmolerSAST.Rules.Base.Configuration;

namespace SmolerSAST.Integration.Tests;

/// <summary>
/// Phase 5: Determinism — scanning the same code twice MUST produce identical findings.
/// </summary>
public sealed partial class DeterminismTests
{
    private const string SampleCode = """
        #pragma warning disable SYSLIB0011
        using System;
        using System.IO;
        using System.Security.Cryptography;
        using System.Runtime.Serialization.Formatters.Binary;

        namespace TestApp
        {
            public class Service
            {
                private const string ApiKey = "sk-live-1234567890abcdef";

                public object? Deserialize(Stream s) => new BinaryFormatter().Deserialize(s);

                public byte[] Hash(byte[] data) => MD5.HashData(data);

                public void Process(string userInput)
                {
                    var cmd = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + userInput);
                }
            }
        }
        """;

    [Fact]
    public async Task ScanTwice_ProducesIdenticalSarif()
    {
        var scanTime = new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

        var sarif1 = await RunScanAndGetSarif(scanTime);
        var sarif2 = await RunScanAndGetSarif(scanTime);

        // Strip non-deterministic fields (endTimeUtc varies with Duration)
        var normalized1 = StripTimestamps(sarif1);
        var normalized2 = StripTimestamps(sarif2);

        Assert.Equal(normalized1, normalized2);
    }

    [Fact]
    public async Task ScanTwice_ProducesIdenticalFindingCount()
    {
        var result1 = await RunScan();
        var result2 = await RunScan();

        Assert.Equal(result1.Findings.Length, result2.Findings.Length);
        Assert.True(result1.Findings.Length > 0, "Should detect vulnerabilities");
    }

    [Fact]
    public async Task ScanTwice_FindingsAreSortedIdentically()
    {
        var result1 = await RunScan();
        var result2 = await RunScan();

        for (var i = 0; i < result1.Findings.Length; i++)
        {
            Assert.Equal(result1.Findings[i].RuleId, result2.Findings[i].RuleId);
            Assert.Equal(result1.Findings[i].Location.StartLine, result2.Findings[i].Location.StartLine);
            Assert.Equal(result1.Findings[i].Location.StartColumn, result2.Findings[i].Location.StartColumn);
            Assert.Equal(result1.Findings[i].MessagePtBr, result2.Findings[i].MessagePtBr);
        }
    }

    [Fact]
    public async Task ScanTwice_MarkdownFindingSectionsIdentical()
    {
        var scanTime = new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var result1 = await RunScan();
        var result2 = await RunScan();
        var registry = CreateRegistry();
        var rules = registry.GetAll().ToArray();

        var md1 = MarkdownReportEmitter.Emit(result1, rules, scanTime, "test");
        var md2 = MarkdownReportEmitter.Emit(result2, rules, scanTime, "test");

        // Strip duration line which varies between runs
        var normalized1 = StripDuration(md1);
        var normalized2 = StripDuration(md2);

        Assert.Equal(normalized1, normalized2);
    }

    private static async Task<string> RunScanAndGetSarif(DateTimeOffset scanTime)
    {
        var result = await RunScan();
        var registry = CreateRegistry();
        return SarifEmitter.Emit(result, registry.GetAll().ToArray(), scanTime);
    }

    private static async Task<PipelineResult> RunScan()
    {
        var registry = CreateRegistry();
        var acquirer = new InMemoryCompilationAcquirer(
            [SampleCode],
            InMemoryCompilationAcquirer.GetRuntimeReferences());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        return await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
    }

    private static DefaultRuleRegistry CreateRegistry()
    {
        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());
        registry.Register(new WeakHashAlgorithmRule());
        registry.Register(new CommandInjectionRule());
        registry.Register(new HardcodedSecretRule());
        return registry;
    }

    private static string StripTimestamps(string sarif) =>
        TimestampRegex().Replace(sarif, "\"TIMESTAMP\"");

    private static string StripDuration(string md) =>
        DurationRegex().Replace(md, "**Duração**: STRIPPED");

    [GeneratedRegex(@"""20\d{2}-\d{2}-\d{2}T[\d:.]+Z""")]
    private static partial Regex TimestampRegex();

    [GeneratedRegex(@"\*\*Duração\*\*: [\d.]+s")]
    private static partial Regex DurationRegex();
}
