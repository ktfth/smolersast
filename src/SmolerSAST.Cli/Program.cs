using System.CommandLine;
using SmolerSAST.Cli;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Reporting;

const string Version = "0.3.0";

var rootCommand = new RootCommand("SmolerSAST — Static Application Security Testing for .NET");

// ── scan ──────────────────────────────────────────────
var scanCommand = new Command("scan", "Scan a project or assembly for security vulnerabilities");
var pathOption = new Option<string>("--path", "Path to directory with .cs files or a single .cs file") { IsRequired = true };
var outputOption = new Option<string>("--output", () => "scan-results.sarif", "Output file path for the SARIF report");
var formatOption = new Option<string>("--format", () => "sarif", "Output format: sarif, markdown, or both");
scanCommand.AddOption(pathOption);
scanCommand.AddOption(outputOption);
scanCommand.AddOption(formatOption);

scanCommand.SetHandler(async (string path, string output, string format) =>
{
    Console.WriteLine($"SmolerSAST v{Version} — Scanning: {path}");

    var registry = RuleRegistration.CreateRegistry();
    var sources = await LoadSourcesAsync(path).ConfigureAwait(false);

    if (sources.Count == 0)
    {
        Console.Error.WriteLine("No .cs files found at the specified path.");
        Environment.ExitCode = 1;
        return;
    }

    var acquirer = new InMemoryCompilationAcquirer([.. sources], InMemoryCompilationAcquirer.GetRuntimeReferences());
    var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
    var result = await pipeline.RunAsync(new AnalysisPipelineOptions(path)).ConfigureAwait(false);
    var scanTime = DateTimeOffset.UtcNow;
    var rules = registry.GetAll().ToArray();

    Console.WriteLine($"Analysis complete: {result.Findings.Length} finding(s) in {result.Duration.TotalMilliseconds:F0}ms");
    Console.WriteLine($"  Rules executed: {result.RulesExecuted}");
    Console.WriteLine($"  Syntax trees: {result.SyntaxTreesAnalyzed}");

    var artifacts = new List<string>();

    if (format is "sarif" or "both")
    {
        await SarifEmitter.WriteAsync(result, rules, scanTime, output).ConfigureAwait(false);
        Console.WriteLine($"  SARIF report: {output}");
        artifacts.Add(output);
    }

    if (format is "markdown" or "both")
    {
        var mdPath = Path.ChangeExtension(output, ".md");
        await MarkdownReportEmitter.WriteAsync(result, rules, scanTime, path, mdPath).ConfigureAwait(false);
        Console.WriteLine($"  Markdown report: {mdPath}");
        artifacts.Add(mdPath);
    }

    // Emit manifest
    if (artifacts.Count > 0)
    {
        var manifestPath = Path.Combine(Path.GetDirectoryName(output) ?? ".", "manifest.json");
        await ManifestEmitter.WriteAsync(artifacts, scanTime, manifestPath).ConfigureAwait(false);
    }

    foreach (var finding in result.Findings)
    {
        Console.WriteLine($"  [{finding.Severity}] {finding.RuleId}: {finding.MessagePtBr}");
        Console.WriteLine($"    at {finding.Location.FilePath}:{finding.Location.StartLine}:{finding.Location.StartColumn}");
    }

    Environment.ExitCode = result.Findings.Any(f => f.Severity >= SmolerSAST.Core.Rules.RuleSeverity.High) ? 1 : 0;
}, pathOption, outputOption, formatOption);

rootCommand.AddCommand(scanCommand);

// ── rules ─────────────────────────────────────────────
var rulesCommand = new Command("rules", "List all available security rules");
rulesCommand.SetHandler(() =>
{
    var registry = RuleRegistration.CreateRegistry();
    var all = registry.GetAll();

    Console.WriteLine($"SmolerSAST v{Version} — {all.Length} rules available\n");
    Console.WriteLine($"{"ID",-10} {"Severity",-10} {"Precision",-10} {"CWE",-12} {"OWASP",-10} Description");
    Console.WriteLine(new string('-', 100));

    foreach (var rule in all)
    {
        var cwe = string.Join(",", rule.CweIds.Select(id => $"{id}"));
        Console.WriteLine($"{rule.Id,-10} {rule.Severity,-10} {rule.Precision,-10} {cwe,-12} {rule.OwaspCategory,-10} {rule.DescriptionEnUs[..Math.Min(50, rule.DescriptionEnUs.Length)]}");
    }
});
rootCommand.AddCommand(rulesCommand);

// ── verify ────────────────────────────────────────────
var verifyCommand = new Command("verify", "Verify scan artifacts integrity via manifest");
var manifestOption = new Option<string>("--manifest", () => "manifest.json", "Path to manifest.json");
verifyCommand.AddOption(manifestOption);

verifyCommand.SetHandler(async (string manifestPath) =>
{
    if (!File.Exists(manifestPath))
    {
        Console.Error.WriteLine($"Manifest not found: {manifestPath}");
        Environment.ExitCode = 1;
        return;
    }

    var json = await File.ReadAllTextAsync(manifestPath).ConfigureAwait(false);
    var manifest = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(json);

    Console.WriteLine($"SmolerSAST v{Version} — Verifying manifest: {manifestPath}\n");

    var allValid = true;
    foreach (var artifact in manifest.GetProperty("artifacts").EnumerateArray())
    {
        var path = artifact.GetProperty("path").GetString()!;
        var expectedHash = artifact.GetProperty("sha256").GetString()!;

        if (!File.Exists(path))
        {
            Console.WriteLine($"  MISSING  {path}");
            allValid = false;
            continue;
        }

        var bytes = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
        var actualHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));

        if (actualHash == expectedHash)
        {
            Console.WriteLine($"  OK       {path}");
        }
        else
        {
            Console.WriteLine($"  MISMATCH {path}");
            Console.WriteLine($"           expected: {expectedHash}");
            Console.WriteLine($"           actual:   {actualHash}");
            allValid = false;
        }
    }

    Console.WriteLine(allValid ? "\nAll artifacts verified." : "\nVerification FAILED.");
    Environment.ExitCode = allValid ? 0 : 1;
}, manifestOption);
rootCommand.AddCommand(verifyCommand);

// ── report ────────────────────────────────────────────
var reportCommand = new Command("report", "Generate a pt-BR Markdown report from a SARIF file");
var sarifOption = new Option<string>("--sarif", "Path to .sarif input file") { IsRequired = true };
var reportOutputOption = new Option<string>("--output", () => "report.pt-BR.md", "Output Markdown file path");
reportCommand.AddOption(sarifOption);
reportCommand.AddOption(reportOutputOption);

reportCommand.SetHandler((string sarifPath, string reportOutput) =>
{
    if (!File.Exists(sarifPath))
    {
        Console.Error.WriteLine($"SARIF file not found: {sarifPath}");
        Environment.ExitCode = 1;
        return;
    }

    Console.WriteLine($"SmolerSAST v{Version} — Use 'scan --format both' to generate SARIF and Markdown simultaneously.");
    Console.WriteLine($"  Or scan again with: smolersast scan --path <target> --output {sarifPath} --format both");
}, sarifOption, reportOutputOption);
rootCommand.AddCommand(reportCommand);

// ── version ───────────────────────────────────────────
var versionCommand = new Command("version", "Display SmolerSAST version");
versionCommand.SetHandler(() =>
{
    Console.WriteLine($"SmolerSAST v{Version}");
    Console.WriteLine($"Runtime: .NET {Environment.Version}");
    Console.WriteLine($"OS: {Environment.OSVersion}");

    var registry = RuleRegistration.CreateRegistry();
    Console.WriteLine($"Rules: {registry.GetAll().Length}");
});
rootCommand.AddCommand(versionCommand);

return await rootCommand.InvokeAsync(args).ConfigureAwait(false);

// ── helpers ───────────────────────────────────────────
static async Task<List<string>> LoadSourcesAsync(string path)
{
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

    return sources;
}
