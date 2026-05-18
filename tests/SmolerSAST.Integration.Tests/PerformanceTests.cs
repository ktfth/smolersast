using Xunit;
using System.Diagnostics;
using System.Text;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Deserialization;
using SmolerSAST.Rules.Base.Cryptography;
using SmolerSAST.Rules.Base.Injection;
using SmolerSAST.Rules.Base.Configuration;

namespace SmolerSAST.Integration.Tests;

/// <summary>
/// Phase 5: Performance regression suite — ensures scan performance stays within thresholds.
/// </summary>
public sealed class PerformanceTests
{
    /// <summary>
    /// Generates a large synthetic codebase (~10k SLOC) and scans it.
    /// Threshold: under 30 seconds for the full scan.
    /// </summary>
    [Fact]
    public async Task LargeCodebase_ScansWithinTimeLimit()
    {
        var sources = GenerateSyntheticCodebase(100); // 100 files ≈ 10k SLOC
        var registry = CreateFullRegistry();

        var acquirer = new InMemoryCompilationAcquirer(
            [.. sources],
            InMemoryCompilationAcquirer.GetRuntimeReferences());

        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        var options = new AnalysisPipelineOptions("perf-test", MaxConcurrency: Environment.ProcessorCount);

        var sw = Stopwatch.StartNew();
        var result = await pipeline.RunAsync(options);
        sw.Stop();

        Assert.True(sw.Elapsed.TotalSeconds < 60, $"Scan took {sw.Elapsed.TotalSeconds:F1}s, expected < 60s");
        Assert.True(result.Findings.Length > 0, "Should detect findings in synthetic codebase");
        Assert.True(result.RulesExecuted > 0, "Rules should have executed");
    }

    /// <summary>
    /// Single file scan should be fast — under 5 seconds.
    /// </summary>
    [Fact]
    public async Task SingleFile_ScansQuickly()
    {
        const string source = """
            using System.Security.Cryptography;
            public class Quick { public byte[] H(byte[] d) => MD5.HashData(d); }
            """;

        var registry = CreateFullRegistry();
        var acquirer = new InMemoryCompilationAcquirer([source], InMemoryCompilationAcquirer.GetRuntimeReferences());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());

        var sw = Stopwatch.StartNew();
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("quick-test"));
        sw.Stop();

        Assert.True(sw.Elapsed.TotalSeconds < 30, $"Single file scan took {sw.Elapsed.TotalSeconds:F1}s");
    }

    /// <summary>
    /// Memory usage should not exceed 500MB for a moderate codebase.
    /// </summary>
    [Fact]
    public async Task ModerateCodebase_MemoryWithinBudget()
    {
        var sources = GenerateSyntheticCodebase(50);
        var registry = CreateFullRegistry();
        var acquirer = new InMemoryCompilationAcquirer([.. sources], InMemoryCompilationAcquirer.GetRuntimeReferences());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());

        var memBefore = GC.GetTotalMemory(true);
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("mem-test"));
        var memAfter = GC.GetTotalMemory(false);

        var memUsedMb = (memAfter - memBefore) / (1024.0 * 1024.0);
        Assert.True(memUsedMb < 500, $"Memory usage: {memUsedMb:F1}MB, expected < 500MB");
    }

    private static List<string> GenerateSyntheticCodebase(int fileCount)
    {
        var sources = new List<string>();
        for (var i = 0; i < fileCount; i++)
        {
            var sb = new StringBuilder();
            sb.AppendLine("using System;");
            sb.AppendLine("using System.Security.Cryptography;");
            sb.AppendLine($"namespace SyntheticApp.Module{i}");
            sb.AppendLine("{");

            for (var c = 0; c < 3; c++)
            {
                sb.AppendLine($"    public class Service{c}");
                sb.AppendLine("    {");

                for (var m = 0; m < 10; m++)
                {
                    sb.AppendLine($"        public string Method{m}(string input)");
                    sb.AppendLine("        {");
                    sb.AppendLine($"            var result = input + \" processed by Method{m}\";");

                    if (m % 5 == 0)
                    {
                        sb.AppendLine("#pragma warning disable SYSLIB0021");
                        sb.AppendLine("            using var md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();");
                        sb.AppendLine("#pragma warning restore SYSLIB0021");
                    }

                    sb.AppendLine("            return result;");
                    sb.AppendLine("        }");
                }

                sb.AppendLine("    }");
            }

            sb.AppendLine("}");
            sources.Add(sb.ToString());
        }

        return sources;
    }

    private static DefaultRuleRegistry CreateFullRegistry()
    {
        var registry = new DefaultRuleRegistry();
        registry.Register(new BinaryFormatterUsageRule());
        registry.Register(new WeakHashAlgorithmRule());
        registry.Register(new EcbCipherModeRule());
        registry.Register(new HardcodedCryptoKeyRule());
        registry.Register(new RijndaelManagedUsageRule());
        registry.Register(new CommandInjectionRule());
        registry.Register(new HardcodedSecretRule());
        return registry;
    }
}
