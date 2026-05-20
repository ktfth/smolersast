using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.BR.Lgpd;

namespace SmolerSAST.Rules.BR.Tests.Lgpd;

public sealed class PiiInCacheWithoutEncryptionRuleTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    [Fact]
    public async Task Positive1_CpfInCacheSet_Detected()
    {
        const string source = """
            public interface ICache { void Set(string key, string value); }
            public class Test
            {
                public void Store(ICache cache, string cpf)
                {
                    cache.Set("user_cpf", cpf);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1004"));
    }

    [Fact]
    public async Task Positive2_EmailInDistributedCache_Detected()
    {
        const string source = """
            public interface IDistributedCache { void SetString(string key, string value); }
            public class Test
            {
                private readonly IDistributedCache _cache;
                public Test(IDistributedCache cache) => _cache = cache;
                public void CacheUser(string email)
                {
                    _cache.SetString("email", email);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1004"));
    }

    [Fact]
    public async Task Positive3_NomeInMemoryCache_Detected()
    {
        const string source = """
            public interface IMemoryCache { void Set(string key, object value); }
            public class Test
            {
                public void CacheProfile(IMemoryCache cache, string nome)
                {
                    cache.Set("user_nome", nome);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1004"));
    }

    [Fact]
    public async Task Negative1_CacheWithEncryption_NotDetected()
    {
        const string source = """
            public interface ICache { void Set(string key, string value); }
            public class Test
            {
                public void Store(ICache cache, string cpf)
                {
                    var encrypted = Encrypt(cpf);
                    cache.Set("user_cpf", encrypted);
                }
                private string Encrypt(string data) => data;
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative2_NonPiiInCache_NotDetected()
    {
        const string source = """
            public interface ICache { void Set(string key, string value); }
            public class Test
            {
                public void Store(ICache cache, string productId)
                {
                    cache.Set("product", productId);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative3_NotCacheContext_NotDetected()
    {
        const string source = """
            public class Repository
            {
                public void Set(string key, string cpf) { }
            }
            public class Test
            {
                public void Store(Repository repo, string cpf)
                {
                    repo.Set("cpf", cpf);
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
        registry.Register(new PiiInCacheWithoutEncryptionRule());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
        return result.Findings;
    }
}
