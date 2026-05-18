namespace SmolerSAST.Core.Rules;

/// <summary>
/// Represents a specific location in source code where a finding was detected.
/// </summary>
/// <param name="FilePath">Absolute or relative path to the source file.</param>
/// <param name="StartLine">1-based start line number.</param>
/// <param name="StartColumn">0-based start column.</param>
/// <param name="EndLine">1-based end line number.</param>
/// <param name="EndColumn">0-based end column.</param>
/// <param name="CodeExcerpt">The source code excerpt at this location.</param>
public sealed record FindingLocation(
    string FilePath,
    int StartLine,
    int StartColumn,
    int EndLine,
    int EndColumn,
    string CodeExcerpt);
