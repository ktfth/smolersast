using System.Collections.Immutable;

namespace SmolerSAST.Core.Taint;

/// <summary>
/// Registry of known sanitizers — methods that remove taint from data.
/// </summary>
public sealed class TaintSanitizerRegistry
{
    private readonly ImmutableHashSet<string> _sanitizers;

    private TaintSanitizerRegistry(ImmutableHashSet<string> sanitizers)
    {
        _sanitizers = sanitizers;
    }

    public bool IsSanitizer(string methodName)
    {
        return _sanitizers.Contains(methodName);
    }

    /// <summary>
    /// Creates the default sanitizer registry for .NET applications.
    /// </summary>
    public static TaintSanitizerRegistry CreateDefault()
    {
        var sanitizers = ImmutableHashSet.CreateBuilder<string>();

        // HTML encoding
        sanitizers.Add("HtmlEncode");
        sanitizers.Add("JavaScriptStringEncode");
        sanitizers.Add("UrlEncode");
        sanitizers.Add("UrlPathEncode");
        sanitizers.Add("Encode");

        // SQL parameterization indicators
        sanitizers.Add("AddWithValue");
        sanitizers.Add("Add"); // SqlParameterCollection.Add

        // Input validation
        sanitizers.Add("IsMatch"); // Regex validation
        sanitizers.Add("TryParse");
        sanitizers.Add("Parse"); // Strongly typed parsing
        sanitizers.Add("Validate");
        sanitizers.Add("Sanitize");
        sanitizers.Add("Escape");
        sanitizers.Add("Clean");
        sanitizers.Add("Strip");
        sanitizers.Add("Filter");

        // .NET security APIs
        sanitizers.Add("Protect");
        sanitizers.Add("Encrypt");
        sanitizers.Add("Hash");
        sanitizers.Add("ComputeHash");
        sanitizers.Add("Mask");
        sanitizers.Add("Redact");
        sanitizers.Add("Truncate");

        // Type conversion (converts to safe types)
        sanitizers.Add("ToInt32");
        sanitizers.Add("ToInt64");
        sanitizers.Add("ToDecimal");
        sanitizers.Add("ToDouble");
        sanitizers.Add("ToBoolean");
        sanitizers.Add("ToDateTime");
        sanitizers.Add("ToGuid");

        return new TaintSanitizerRegistry(sanitizers.ToImmutable());
    }
}
