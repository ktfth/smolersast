using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Pipeline;

/// <summary>
/// Orchestrates the full analysis pipeline: acquire compilation, index symbols,
/// register rules, execute analysis passes, and collect findings.
/// </summary>
public sealed class AnalysisPipeline
{
    private readonly ICompilationAcquirer _acquirer;
    private readonly IRuleRegistry _ruleRegistry;
    private readonly ISymbolIndex _symbolIndex;
    private readonly ILogger<AnalysisPipeline> _logger;

    /// <summary>
    /// Initializes a new <see cref="AnalysisPipeline"/>.
    /// </summary>
    /// <param name="acquirer">The compilation acquirer to use.</param>
    /// <param name="ruleRegistry">The registry of rules to execute.</param>
    /// <param name="symbolIndex">The symbol index for cross-reference queries.</param>
    /// <param name="logger">Optional logger.</param>
    public AnalysisPipeline(
        ICompilationAcquirer acquirer,
        IRuleRegistry ruleRegistry,
        ISymbolIndex symbolIndex,
        ILogger<AnalysisPipeline>? logger = null)
    {
        _acquirer = acquirer ?? throw new ArgumentNullException(nameof(acquirer));
        _ruleRegistry = ruleRegistry ?? throw new ArgumentNullException(nameof(ruleRegistry));
        _symbolIndex = symbolIndex ?? throw new ArgumentNullException(nameof(symbolIndex));
        _logger = logger ?? NullLogger<AnalysisPipeline>.Instance;
    }

    /// <summary>
    /// Runs the analysis pipeline and returns the results.
    /// </summary>
    /// <param name="options">Pipeline configuration options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The pipeline result with all findings.</returns>
    public async Task<PipelineResult> RunAsync(
        AnalysisPipelineOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var stopwatch = Stopwatch.StartNew();
        var startMemory = GC.GetTotalMemory(forceFullCollection: false);

        // Step 1: Acquire compilation
        _logger.LogInformation("Acquiring compilation from {Path}", options.Path);
        var acquired = await _acquirer.AcquireAsync(options.Path, cancellationToken).ConfigureAwait(false);

        // Step 2: Index symbols
        _logger.LogInformation("Indexing symbols ({TreeCount} syntax trees)", acquired.SyntaxTrees.Length);
        await _symbolIndex.IndexAsync(acquired.Compilation, cancellationToken).ConfigureAwait(false);

        // Step 3: Select and register rules
        var rules = SelectRules(options.EnabledRuleIds);
        _logger.LogInformation("Executing {RuleCount} rules", rules.Length);

        var contexts = new List<(SmolerRule Rule, AnalysisContext Context)>();
        foreach (var rule in rules)
        {
            var context = new AnalysisContext();
            rule.RegisterActions(context);
            contexts.Add((rule, context));
        }

        // Step 4: Execute analysis — run syntax node actions across all trees
        var findings = new ConcurrentBag<Finding>();

        await Parallel.ForEachAsync(
            acquired.SyntaxTrees,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = options.EffectiveMaxConcurrency,
                CancellationToken = cancellationToken,
            },
            (tree, ct) =>
            {
                var semanticModel = acquired.Compilation.GetSemanticModel(tree);
                var root = tree.GetRoot(ct);

                foreach (var (rule, context) in contexts)
                {
                    ExecuteSyntaxNodeActions(context, root, semanticModel, findings);
                }

                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);

        // Step 5: Collect and deduplicate findings
        var peakMemory = GC.GetTotalMemory(forceFullCollection: false) - startMemory;
        stopwatch.Stop();

        var sortedFindings = findings
            .OrderBy(f => f.RuleId)
            .ThenBy(f => f.Location.FilePath, StringComparer.Ordinal)
            .ThenBy(f => f.Location.StartLine)
            .ThenBy(f => f.Location.StartColumn)
            .ToImmutableArray();

        _logger.LogInformation(
            "Analysis complete: {FindingCount} findings in {Duration}ms",
            sortedFindings.Length,
            stopwatch.ElapsedMilliseconds);

        return new PipelineResult(
            sortedFindings,
            acquired.Diagnostics,
            stopwatch.Elapsed,
            peakMemory > 0 ? peakMemory : 0,
            acquired.Mode,
            rules.Length,
            acquired.SyntaxTrees.Length);
    }

    private ImmutableArray<SmolerRule> SelectRules(ImmutableHashSet<RuleId>? enabledIds)
    {
        var allRules = _ruleRegistry.GetAll();

        if (enabledIds is null)
        {
            return allRules;
        }

        return [.. allRules.Where(r => enabledIds.Contains(r.Id))];
    }

    private static void ExecuteSyntaxNodeActions(
        AnalysisContext context,
        SyntaxNode root,
        SemanticModel semanticModel,
        ConcurrentBag<Finding> findings)
    {
        foreach (var registration in context.SyntaxNodeActions)
        {
            var kindSet = new HashSet<SyntaxKind>(registration.SyntaxKinds);

            foreach (var node in root.DescendantNodesAndSelf())
            {
                if (kindSet.Contains(node.Kind()))
                {
                    var nodeContext = new SyntaxNodeAnalysisContext(
                        node,
                        semanticModel,
                        finding => findings.Add(finding));

                    registration.Action(nodeContext);
                }
            }
        }
    }
}
