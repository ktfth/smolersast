namespace SmolerSAST.Core.Rules;

/// <summary>
/// Indicates how the compilation was acquired. Findings from binary mode have reduced fidelity.
/// </summary>
public enum CompilationMode
{
    /// <summary>Source code was compiled from .sln/.csproj via MSBuildWorkspace. Full semantic model available.</summary>
    Source = 0,

    /// <summary>Assembly was decompiled from .dll/.exe. Reduced expression-level data flow.</summary>
    Binary = 1,
}
