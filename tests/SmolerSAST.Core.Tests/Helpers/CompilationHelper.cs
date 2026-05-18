using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace SmolerSAST.Core.Tests.Helpers;

/// <summary>
/// Creates in-memory Roslyn compilations for testing.
/// </summary>
internal static class CompilationHelper
{
    private static readonly Lazy<ImmutableArray<MetadataReference>> RuntimeReferences = new(LoadRuntimeReferences);

    /// <summary>
    /// Creates a CSharpCompilation from a single source string with all standard references.
    /// </summary>
    public static CSharpCompilation CreateCompilation(string source, string fileName = "Test.cs")
    {
        var tree = CSharpSyntaxTree.ParseText(
            source,
            CSharpParseOptions.Default.WithLanguageVersion(LanguageVersion.CSharp12),
            path: fileName);

        return CSharpCompilation.Create(
            "TestAssembly",
            [tree],
            RuntimeReferences.Value,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    }

    /// <summary>
    /// Creates a CSharpCompilation from multiple source strings.
    /// </summary>
    public static CSharpCompilation CreateCompilation(params (string Source, string FileName)[] sources)
    {
        var trees = sources.Select(s => CSharpSyntaxTree.ParseText(
            s.Source,
            CSharpParseOptions.Default.WithLanguageVersion(LanguageVersion.CSharp12),
            path: s.FileName)).ToArray();

        return CSharpCompilation.Create(
            "TestAssembly",
            trees,
            RuntimeReferences.Value,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    }

    private static ImmutableArray<MetadataReference> LoadRuntimeReferences()
    {
        var references = new List<MetadataReference>();
        var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;

        var assemblyNames = new[]
        {
            "System.Runtime.dll",
            "System.Private.CoreLib.dll",
            "System.Collections.dll",
            "System.Linq.dll",
            "System.IO.dll",
            "System.Console.dll",
            "System.Runtime.Serialization.Formatters.dll",
            "System.Text.Json.dll",
            "System.Security.Cryptography.dll",
            "System.Security.Cryptography.Algorithms.dll",
            "System.Security.Cryptography.Primitives.dll",
            "System.Security.Cryptography.Csp.dll",
            "System.Net.Primitives.dll",
            "System.Net.Security.dll",
            "netstandard.dll",
        };

        foreach (var name in assemblyNames)
        {
            var path = Path.Combine(runtimeDir, name);
            if (File.Exists(path))
            {
                references.Add(MetadataReference.CreateFromFile(path));
            }
        }

        // Add the main runtime assembly
        references.Add(MetadataReference.CreateFromFile(typeof(object).Assembly.Location));

        return [.. references];
    }
}
