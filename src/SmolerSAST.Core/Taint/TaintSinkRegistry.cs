using System.Collections.Immutable;

namespace SmolerSAST.Core.Taint;

/// <summary>
/// Registry of known taint sinks — methods where tainted data can cause vulnerabilities.
/// </summary>
public sealed class TaintSinkRegistry
{
    private readonly ImmutableDictionary<string, SinkDescriptor> _sinks;

    private TaintSinkRegistry(ImmutableDictionary<string, SinkDescriptor> sinks)
    {
        _sinks = sinks;
    }

    public bool IsSink(string methodName, out SinkDescriptor descriptor)
    {
        return _sinks.TryGetValue(methodName, out descriptor!);
    }

    /// <summary>
    /// Creates the default sink registry for .NET applications.
    /// </summary>
    public static TaintSinkRegistry CreateDefault()
    {
        var sinks = ImmutableDictionary.CreateBuilder<string, SinkDescriptor>();

        // SQL Injection sinks
        sinks["ExecuteNonQuery"] = new SinkDescriptor("sql-injection", 89, "A03:2021", [0]);
        sinks["ExecuteNonQueryAsync"] = new SinkDescriptor("sql-injection", 89, "A03:2021", [0]);
        sinks["ExecuteReader"] = new SinkDescriptor("sql-injection", 89, "A03:2021", [0]);
        sinks["ExecuteReaderAsync"] = new SinkDescriptor("sql-injection", 89, "A03:2021", [0]);
        sinks["ExecuteScalar"] = new SinkDescriptor("sql-injection", 89, "A03:2021", [0]);
        sinks["ExecuteScalarAsync"] = new SinkDescriptor("sql-injection", 89, "A03:2021", [0]);

        // Command Injection sinks
        sinks["Start"] = new SinkDescriptor("command-injection", 78, "A03:2021", [0]);

        // XSS sinks
        sinks["Write"] = new SinkDescriptor("xss", 79, "A03:2021", [0]);
        sinks["WriteLiteral"] = new SinkDescriptor("xss", 79, "A03:2021", [0]);
        sinks["WriteAsync"] = new SinkDescriptor("xss", 79, "A03:2021", [0]);

        // Path Traversal sinks
        sinks["OpenRead"] = new SinkDescriptor("path-traversal", 22, "A01:2021", [0]);
        sinks["OpenWrite"] = new SinkDescriptor("path-traversal", 22, "A01:2021", [0]);
        sinks["ReadAllText"] = new SinkDescriptor("path-traversal", 22, "A01:2021", [0]);
        sinks["Delete"] = new SinkDescriptor("path-traversal", 22, "A01:2021", [0]);

        // LDAP Injection
        sinks["FindAll"] = new SinkDescriptor("ldap-injection", 90, "A03:2021", [0]);
        sinks["FindOne"] = new SinkDescriptor("ldap-injection", 90, "A03:2021", [0]);

        // Log Injection
        sinks["LogInformation"] = new SinkDescriptor("log-injection", 117, "A09:2021", [0]);
        sinks["LogWarning"] = new SinkDescriptor("log-injection", 117, "A09:2021", [0]);
        sinks["LogError"] = new SinkDescriptor("log-injection", 117, "A09:2021", [0]);

        // Redirect / SSRF
        sinks["Redirect"] = new SinkDescriptor("open-redirect", 601, "A01:2021", [0]);
        sinks["RedirectPermanent"] = new SinkDescriptor("open-redirect", 601, "A01:2021", [0]);

        // Deserialization
        sinks["Deserialize"] = new SinkDescriptor("deserialization", 502, "A08:2021", [0]);
        sinks["DeserializeObject"] = new SinkDescriptor("deserialization", 502, "A08:2021", [0]);

        return new TaintSinkRegistry(sinks.ToImmutable());
    }
}

/// <summary>
/// Describes a taint sink with its vulnerability category and affected parameter indices.
/// </summary>
public sealed record SinkDescriptor(
    string Category,
    int CweId,
    string OwaspCategory,
    ImmutableArray<int> TaintedParameterIndices);
