using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.BR.Lgpd;

namespace SmolerSAST.Rules.BR.Tests.Lgpd;

public sealed class PiiInCookieWithoutEncryptionRuleTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    [Fact]
    public async Task Positive1_CpfInCookieAppend_Detected()
    {
        const string source = """
            public interface ICookies { void Append(string key, string value); }
            public class Response { public ICookies Cookies { get; set; } }
            public class Test
            {
                public void SetCookie(Response response, string cpf)
                {
                    response.Cookies.Append("cpf", cpf);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1005"));
    }

    [Fact]
    public async Task Positive2_EmailInCookieAdd_Detected()
    {
        const string source = """
            public class CookieCollection { public void Add(string name, string value) { } }
            public class Response { public CookieCollection Cookies { get; set; } }
            public class Test
            {
                public void SetCookie(Response response, string email)
                {
                    response.Cookies.Add("email", email);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1005"));
    }

    [Fact]
    public async Task Positive3_NomeInCookie_Detected()
    {
        const string source = """
            public interface ICookies { void Append(string key, string value); }
            public class Response { public ICookies Cookies { get; set; } }
            public class Test
            {
                public void SetCookie(Response response)
                {
                    response.Cookies.Append("nome", "João Silva");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1005"));
    }

    [Fact]
    public async Task Negative1_NonPiiCookie_NotDetected()
    {
        const string source = """
            public interface ICookies { void Append(string key, string value); }
            public class Response { public ICookies Cookies { get; set; } }
            public class Test
            {
                public void SetCookie(Response response)
                {
                    response.Cookies.Append("theme", "dark");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative2_NotCookieContext_NotDetected()
    {
        const string source = """
            public class Service { public void Append(string key, string value) { } }
            public class Test
            {
                public void Process(Service service, string cpf)
                {
                    service.Append("cpf", cpf);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative3_DifferentMethod_NotDetected()
    {
        const string source = """
            public interface ICookies { void Delete(string key); }
            public class Response { public ICookies Cookies { get; set; } }
            public class Test
            {
                public void DeleteCookie(Response response)
                {
                    response.Cookies.Delete("cpf");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    private static async Task<ImmutableArray<Finding>> RunAnalysis(string source)
    {
        var acquirer = new InMemoryCompilationAcquirer([source], References);
        var registry = new DefaultRuleRegistry();
        registry.Register(new PiiInCookieWithoutEncryptionRule());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
        return result.Findings;
    }
}
