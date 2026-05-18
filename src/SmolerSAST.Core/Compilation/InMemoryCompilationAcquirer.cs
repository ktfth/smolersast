using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Core.Compilation;

/// <summary>
/// Creates a compilation from in-memory source code strings.
/// Primarily used for testing and for the analysis pipeline when processing code snippets.
/// </summary>
public sealed class InMemoryCompilationAcquirer : ICompilationAcquirer
{
    private readonly ImmutableArray<string> _sources;
    private readonly ImmutableArray<MetadataReference> _references;

    /// <summary>
    /// Initializes a new instance with the given source code strings and metadata references.
    /// </summary>
    /// <param name="sources">C# source code strings to compile.</param>
    /// <param name="references">Assembly references for the compilation.</param>
    public InMemoryCompilationAcquirer(
        ImmutableArray<string> sources,
        ImmutableArray<MetadataReference> references)
    {
        _sources = sources;
        _references = references;
    }

    /// <inheritdoc />
    public Task<AcquiredCompilation> AcquireAsync(string path, CancellationToken cancellationToken = default)
    {
        var trees = _sources
            .Select((source, i) => CSharpSyntaxTree.ParseText(
                source,
                CSharpParseOptions.Default.WithLanguageVersion(LanguageVersion.CSharp12),
                path: $"Source{i}.cs",
                cancellationToken: cancellationToken))
            .ToImmutableArray();

        var compilation = CSharpCompilation.Create(
            "InMemoryAssembly",
            trees,
            _references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var diagnostics = compilation.GetDiagnostics(cancellationToken)
            .Where(d => d.Severity == DiagnosticSeverity.Error)
            .ToImmutableArray();

        var result = new AcquiredCompilation(
            compilation,
            trees.Cast<SyntaxTree>().ToImmutableArray(),
            CompilationMode.Source,
            diagnostics);

        return Task.FromResult(result);
    }

    /// <summary>
    /// Gets the standard metadata references for the current runtime (System.Runtime, System.Private.CoreLib, etc.).
    /// </summary>
    public static ImmutableArray<MetadataReference> GetRuntimeReferences()
    {
        var assemblies = new[]
        {
            typeof(object).Assembly,
            typeof(Console).Assembly,
            typeof(Enumerable).Assembly,
        };

        var references = new List<MetadataReference>();

        foreach (var assembly in assemblies)
        {
            references.Add(MetadataReference.CreateFromFile(assembly.Location));
        }

        // Add System.Runtime for core types
        var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var systemRuntime = Path.Combine(runtimeDir, "System.Runtime.dll");
        if (File.Exists(systemRuntime))
        {
            references.Add(MetadataReference.CreateFromFile(systemRuntime));
        }

        var systemCollections = Path.Combine(runtimeDir, "System.Collections.dll");
        if (File.Exists(systemCollections))
        {
            references.Add(MetadataReference.CreateFromFile(systemCollections));
        }

        // BinaryFormatter lives here
        var runtimeSerialization = Path.Combine(runtimeDir, "System.Runtime.Serialization.Formatters.dll");
        if (File.Exists(runtimeSerialization))
        {
            references.Add(MetadataReference.CreateFromFile(runtimeSerialization));
        }

        return [.. references];
    }
}
