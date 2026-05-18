using System.CommandLine;
using System.Collections.Immutable;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Reporting;
using SmolerSAST.Rules.Base.Deserialization;

var rootCommand = new RootCommand("SmolerSAST — Static Application Security Testing for .NET");

var scanCommand = new Command("scan", "Scan a project or assembly for security vulnerabilities");

var pathOption = new Option<string>(
    "--path",
    "Path to .sln, .csproj, or .cs file(s) to scan")
{
    IsRequired = true,
};

var outputOption = new Option<string>(
    "--output",
    () => "scan-results.sarif",
    "Output file path for the SARIF report");

scanCommand.AddOption(pathOption);
scanCommand.AddOption(outputOption);

scanCommand.SetHandler(async (string path, string output) =>
{
    Console.WriteLine($"SmolerSAST v0.1.0 — Scanning: {path}");

    // Build registry
    var registry = new DefaultRuleRegistry();
    registry.Register(new BinaryFormatterUsageRule());

    // For Phase 1, use InMemoryCompilationAcquirer for .cs files
    var sources = new List<string>();
    if (Directory.Exists(path))
    {
        foreach (var file in Directory.GetFiles(path, "*.cs", SearchOption.AllDirectories))
        {
            sources.Add(await File.ReadAllTextAsync(file).ConfigureAwait(false));
        }
    }
    else if (File.Exists(path) && path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
    {
        sources.Add(await File.ReadAllTextAsync(path).ConfigureAwait(false));
    }

    if (sources.Count == 0)
    {
        Console.Error.WriteLine("No .cs files found at the specified path.");
        return;
    }

    var acquirer = new InMemoryCompilationAcquirer(
        [.. sources],
        InMemoryCompilationAcquirer.GetRuntimeReferences());

    var symbolIndex = new InMemorySymbolIndex();
    var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);
    var options = new AnalysisPipelineOptions(path);

    var result = await pipeline.RunAsync(options).ConfigureAwait(false);

    Console.WriteLine($"Analysis complete: {result.Findings.Length} finding(s) in {result.Duration.TotalMilliseconds:F0}ms");
    Console.WriteLine($"  Rules executed: {result.RulesExecuted}");
    Console.WriteLine($"  Syntax trees: {result.SyntaxTreesAnalyzed}");

    // Emit SARIF
    var scanTime = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    await SarifEmitter.WriteAsync(
        result,
        registry.GetAll().ToArray(),
        scanTime,
        output).ConfigureAwait(false);

    Console.WriteLine($"SARIF report written to: {output}");

    foreach (var finding in result.Findings)
    {
        Console.WriteLine($"  [{finding.Severity}] {finding.RuleId}: {finding.MessagePtBr}");
        Console.WriteLine($"    at {finding.Location.FilePath}:{finding.Location.StartLine}:{finding.Location.StartColumn}");
    }
}, pathOption, outputOption);

rootCommand.AddCommand(scanCommand);

var versionCommand = new Command("version", "Display SmolerSAST version");
versionCommand.SetHandler(() => Console.WriteLine("SmolerSAST v0.1.0"));
rootCommand.AddCommand(versionCommand);

return await rootCommand.InvokeAsync(args).ConfigureAwait(false);
