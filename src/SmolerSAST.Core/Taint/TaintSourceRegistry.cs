using System.Collections.Immutable;

namespace SmolerSAST.Core.Taint;

/// <summary>
/// Registry of known taint sources — methods, properties, and parameters that introduce tainted data.
/// </summary>
public sealed class TaintSourceRegistry
{
    private readonly ImmutableDictionary<string, TaintLabel> _methodSources;
    private readonly ImmutableDictionary<string, TaintLabel> _propertySources;
    private readonly ImmutableDictionary<string, TaintLabel> _parameterTypeSources;

    private TaintSourceRegistry(
        ImmutableDictionary<string, TaintLabel> methodSources,
        ImmutableDictionary<string, TaintLabel> propertySources,
        ImmutableDictionary<string, TaintLabel> parameterTypeSources)
    {
        _methodSources = methodSources;
        _propertySources = propertySources;
        _parameterTypeSources = parameterTypeSources;
    }

    public bool IsSource(string memberName, out TaintLabel label)
    {
        if (_methodSources.TryGetValue(memberName, out label)) return true;
        if (_propertySources.TryGetValue(memberName, out label)) return true;
        return false;
    }

    public bool IsParameterTypeSource(string typeName, out TaintLabel label)
    {
        return _parameterTypeSources.TryGetValue(typeName, out label);
    }

    /// <summary>
    /// Creates the default taint source registry for .NET / ASP.NET applications.
    /// </summary>
    public static TaintSourceRegistry CreateDefault()
    {
        var methods = ImmutableDictionary.CreateBuilder<string, TaintLabel>();
        // HttpRequest methods
        methods["ReadFormAsync"] = TaintLabel.UserInput;
        methods["ReadFromJsonAsync"] = TaintLabel.UserInput;
        methods["ReadAsStringAsync"] = TaintLabel.UserInput;
        methods["ReadAsStreamAsync"] = TaintLabel.UserInput;
        methods["GetQueryParameterValues"] = TaintLabel.UserInput;

        // Database readers
        methods["ExecuteReader"] = TaintLabel.ExternalData;
        methods["ExecuteReaderAsync"] = TaintLabel.ExternalData;
        methods["ExecuteScalar"] = TaintLabel.ExternalData;
        methods["ExecuteScalarAsync"] = TaintLabel.ExternalData;
        methods["Read"] = TaintLabel.ExternalData;
        methods["GetString"] = TaintLabel.ExternalData;
        methods["GetValue"] = TaintLabel.ExternalData;

        // Configuration
        methods["GetConnectionString"] = TaintLabel.Configuration;
        methods["GetSection"] = TaintLabel.Configuration;
        methods["GetValue"] = TaintLabel.Configuration;

        // File I/O
        methods["ReadAllText"] = TaintLabel.ExternalData;
        methods["ReadAllTextAsync"] = TaintLabel.ExternalData;
        methods["ReadAllBytes"] = TaintLabel.ExternalData;
        methods["ReadAllLines"] = TaintLabel.ExternalData;
        methods["ReadLine"] = TaintLabel.ExternalData;

        var properties = ImmutableDictionary.CreateBuilder<string, TaintLabel>();
        // HttpRequest properties
        properties["QueryString"] = TaintLabel.UserInput;
        properties["Query"] = TaintLabel.UserInput;
        properties["Form"] = TaintLabel.UserInput;
        properties["Body"] = TaintLabel.UserInput;
        properties["Headers"] = TaintLabel.UserInput;
        properties["Cookies"] = TaintLabel.UserInput;
        properties["Path"] = TaintLabel.UserInput;
        properties["RawUrl"] = TaintLabel.UserInput;
        properties["UserAgent"] = TaintLabel.UserInput;
        properties["ContentType"] = TaintLabel.UserInput;
        properties["InputStream"] = TaintLabel.UserInput;

        // Environment
        properties["CommandLine"] = TaintLabel.ExternalData;

        var paramTypes = ImmutableDictionary.CreateBuilder<string, TaintLabel>();
        // ASP.NET parameter types that are always user-controlled
        paramTypes["IFormFile"] = TaintLabel.UserInput;
        paramTypes["IFormCollection"] = TaintLabel.UserInput;
        paramTypes["HttpRequest"] = TaintLabel.UserInput;

        return new TaintSourceRegistry(
            methods.ToImmutable(),
            properties.ToImmutable(),
            paramTypes.ToImmutable());
    }
}
