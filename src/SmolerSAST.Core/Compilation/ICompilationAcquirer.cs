namespace SmolerSAST.Core.Compilation;

/// <summary>
/// Acquires a Roslyn compilation from a given path (solution, project, or assembly).
/// </summary>
public interface ICompilationAcquirer
{
    /// <summary>
    /// Acquires a compilation from the specified path.
    /// </summary>
    /// <param name="path">Path to a .sln, .csproj, .dll, or .exe file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The acquired compilation with metadata.</returns>
    Task<AcquiredCompilation> AcquireAsync(string path, CancellationToken cancellationToken = default);
}
