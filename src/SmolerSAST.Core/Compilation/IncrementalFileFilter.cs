using System.Diagnostics;

namespace SmolerSAST.Core.Compilation;

/// <summary>
/// Filters source files to only those changed since a git ref (branch, commit, HEAD~N).
/// Enables incremental analysis in CI pipelines for faster scan times.
/// </summary>
public static class IncrementalFileFilter
{
    /// <summary>
    /// Gets the list of .cs files changed relative to a git ref.
    /// Returns null if git is not available or the path is not a git repo.
    /// </summary>
    public static async Task<IReadOnlyList<string>?> GetChangedFilesAsync(
        string directoryPath,
        string baseRef = "HEAD~1",
        CancellationToken cancellationToken = default)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    Arguments = $"diff --name-only --diff-filter=ACMR {baseRef} -- \"*.cs\"",
                    WorkingDirectory = directoryPath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                },
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            if (process.ExitCode != 0) return null;

            var files = output
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(f => Path.GetFullPath(Path.Combine(directoryPath, f)))
                .Where(f => File.Exists(f))
                .ToList();

            return files;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Loads only the changed source files, or all files if incremental is not available.
    /// </summary>
    public static async Task<(List<string> Sources, bool IsIncremental)> LoadSourcesAsync(
        string directoryPath,
        string? baseRef,
        CancellationToken cancellationToken = default)
    {
        if (baseRef is not null)
        {
            var changedFiles = await GetChangedFilesAsync(directoryPath, baseRef, cancellationToken).ConfigureAwait(false);
            if (changedFiles is not null && changedFiles.Count > 0)
            {
                var sources = new List<string>();
                foreach (var file in changedFiles)
                {
                    sources.Add(await File.ReadAllTextAsync(file, cancellationToken).ConfigureAwait(false));
                }
                return (sources, true);
            }
        }

        // Fallback: load all .cs files
        var allSources = new List<string>();
        if (Directory.Exists(directoryPath))
        {
            foreach (var file in Directory.GetFiles(directoryPath, "*.cs", SearchOption.AllDirectories))
            {
                allSources.Add(await File.ReadAllTextAsync(file, cancellationToken).ConfigureAwait(false));
            }
        }

        return (allSources, false);
    }
}
