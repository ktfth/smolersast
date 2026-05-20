using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.BR.Bacen;

namespace SmolerSAST.Rules.BR.Tests.Bacen;

public sealed class BacenRulesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // SMOL1010 — MutualTlsNotEnforced
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1010_Positive1_NoCertificate_Detected()
    {
        const string source = """
            public enum ClientCertificateMode { NoCertificate, RequireCertificate }
            public class KestrelOptions { public ClientCertificateMode ClientCertificateMode { get; set; } }
            public class Test
            {
                public void Configure(KestrelOptions opts)
                {
                    opts.ClientCertificateMode = ClientCertificateMode.NoCertificate;
                }
            }
            """;

        var findings = await RunAnalysis(source, new MutualTlsNotEnforcedRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1010"));
    }

    [Fact]
    public async Task SMOL1010_Positive2_DangerousAcceptAny_Detected()
    {
        const string source = """
            using System.Net.Http;
            public class Test
            {
                public HttpClient Create()
                {
                    var handler = new HttpClientHandler();
                    handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    return new HttpClient(handler);
                }
            }
            """;

        var findings = await RunAnalysis(source, new MutualTlsNotEnforcedRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1010"));
    }

    [Fact]
    public async Task SMOL1010_Positive3_LambdaTrue_Detected()
    {
        const string source = """
            using System.Net.Http;
            public class Test
            {
                public HttpClient Create()
                {
                    var handler = new HttpClientHandler();
                    handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
                    return new HttpClient(handler);
                }
            }
            """;

        var findings = await RunAnalysis(source, new MutualTlsNotEnforcedRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1010"));
    }

    [Fact]
    public async Task SMOL1010_Negative1_RequireCertificate_NotDetected()
    {
        const string source = """
            public enum ClientCertificateMode { NoCertificate, RequireCertificate }
            public class KestrelOptions { public ClientCertificateMode ClientCertificateMode { get; set; } }
            public class Test
            {
                public void Configure(KestrelOptions opts)
                {
                    opts.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                }
            }
            """;

        var findings = await RunAnalysis(source, new MutualTlsNotEnforcedRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1010_Negative2_UnrelatedAssignment_NotDetected()
    {
        const string source = """
            public class Test
            {
                public string Name { get; set; }
                public void Configure()
                {
                    Name = "test";
                }
            }
            """;

        var findings = await RunAnalysis(source, new MutualTlsNotEnforcedRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1010_Negative3_NoAssignment_NotDetected()
    {
        const string source = """
            public class Test
            {
                public string GetName() => "test";
            }
            """;

        var findings = await RunAnalysis(source, new MutualTlsNotEnforcedRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1013 — OAuthWithoutPkce
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1013_Positive1_UsePkceFalse_Detected()
    {
        const string source = """
            public class OidcOptions { public bool UsePkce { get; set; } }
            public class Test
            {
                public void Configure(OidcOptions opts)
                {
                    opts.UsePkce = false;
                }
            }
            """;

        var findings = await RunAnalysis(source, new OAuthWithoutPkceRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1013"));
    }

    [Fact]
    public async Task SMOL1013_Positive2_AddOpenIdConnectWithoutPkce_Detected()
    {
        const string source = """
            public static class AuthExtensions
            {
                public static void AddOpenIdConnect(string scheme, System.Action<object> configure) { }
            }
            public class Startup
            {
                public void ConfigureServices()
                {
                    AuthExtensions.AddOpenIdConnect("oidc", opts => { });
                }
            }
            """;

        var findings = await RunAnalysis(source, new OAuthWithoutPkceRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1013"));
    }

    [Fact]
    public async Task SMOL1013_Positive3_ExplicitPkceFalseInConfig_Detected()
    {
        const string source = """
            public class OpenIdConnectOptions { public bool UsePkce { get; set; } }
            public class Test
            {
                public OpenIdConnectOptions Create()
                {
                    var opts = new OpenIdConnectOptions();
                    opts.UsePkce = false;
                    return opts;
                }
            }
            """;

        var findings = await RunAnalysis(source, new OAuthWithoutPkceRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1013"));
    }

    [Fact]
    public async Task SMOL1013_Negative1_UsePkceTrue_NotDetected()
    {
        const string source = """
            public class OidcOptions { public bool UsePkce { get; set; } }
            public class Test
            {
                public void Configure(OidcOptions opts)
                {
                    opts.UsePkce = true;
                }
            }
            """;

        var findings = await RunAnalysis(source, new OAuthWithoutPkceRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1013_Negative2_UnrelatedFalse_NotDetected()
    {
        const string source = """
            public class Settings { public bool Enabled { get; set; } }
            public class Test
            {
                public void Configure(Settings s) { s.Enabled = false; }
            }
            """;

        var findings = await RunAnalysis(source, new OAuthWithoutPkceRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1013_Negative3_NoOAuth_NotDetected()
    {
        const string source = """
            public class Test
            {
                public int Calculate() => 42;
            }
            """;

        var findings = await RunAnalysis(source, new OAuthWithoutPkceRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1014 — PixKeyExposure
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1014_Positive1_PixKeyInLog_Detected()
    {
        const string source = """
            public interface ILogger { void LogInformation(string message, params object[] args); }
            public class Test
            {
                public void Process(ILogger logger, string pixKey)
                {
                    logger.LogInformation("Chave PIX: {PixKey}", pixKey);
                }
            }
            """;

        var findings = await RunAnalysis(source, new PixKeyExposureRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1014"));
    }

    [Fact]
    public async Task SMOL1014_Positive2_ChavePixInDebug_Detected()
    {
        const string source = """
            public interface ILogger { void Debug(string message); }
            public class Test
            {
                public void Process(ILogger logger, string chavePix)
                {
                    logger.Debug($"Processando chavePix: {chavePix}");
                }
            }
            """;

        var findings = await RunAnalysis(source, new PixKeyExposureRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1014"));
    }

    [Fact]
    public async Task SMOL1014_Positive3_EndToEndIdInLog_Detected()
    {
        const string source = """
            public interface ILogger { void LogWarning(string message, params object[] args); }
            public class Test
            {
                public void Warn(ILogger logger, string endToEndId)
                {
                    logger.LogWarning("E2E ID: {EndToEndId}", endToEndId);
                }
            }
            """;

        var findings = await RunAnalysis(source, new PixKeyExposureRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1014"));
    }

    [Fact]
    public async Task SMOL1014_Negative1_NonPixFieldInLog_NotDetected()
    {
        const string source = """
            public interface ILogger { void LogInformation(string message, params object[] args); }
            public class Test
            {
                public void Process(ILogger logger, string orderId)
                {
                    logger.LogInformation("Order: {OrderId}", orderId);
                }
            }
            """;

        var findings = await RunAnalysis(source, new PixKeyExposureRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1014_Negative2_NotLogMethod_NotDetected()
    {
        const string source = """
            public class Service { public void Process(string pixKey) { } }
            public class Test
            {
                public void Run(Service svc) { svc.Process("abc"); }
            }
            """;

        var findings = await RunAnalysis(source, new PixKeyExposureRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1014_Negative3_NoArgs_NotDetected()
    {
        const string source = """
            public interface ILogger { void LogInformation(string message); }
            public class Test
            {
                public void Process(ILogger logger)
                {
                    logger.LogInformation("Payment processed successfully");
                }
            }
            """;

        var findings = await RunAnalysis(source, new PixKeyExposureRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1015 — SessionTimeoutExcessive
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1015_Positive1_30MinTimeout_Detected()
    {
        const string source = """
            using System;
            public class SessionOptions { public TimeSpan IdleTimeout { get; set; } }
            public class Test
            {
                public void Configure(SessionOptions opts)
                {
                    opts.IdleTimeout = TimeSpan.FromMinutes(30);
                }
            }
            """;

        var findings = await RunAnalysis(source, new SessionTimeoutExcessiveRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1015"));
    }

    [Fact]
    public async Task SMOL1015_Positive2_HourTimeout_Detected()
    {
        const string source = """
            using System;
            public class AuthOptions { public TimeSpan ExpireTimeSpan { get; set; } }
            public class Test
            {
                public void Configure(AuthOptions opts)
                {
                    opts.ExpireTimeSpan = TimeSpan.FromHours(1);
                }
            }
            """;

        var findings = await RunAnalysis(source, new SessionTimeoutExcessiveRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1015"));
    }

    [Fact]
    public async Task SMOL1015_Positive3_60MinTimeout_Detected()
    {
        const string source = """
            using System;
            public class SessionOptions { public TimeSpan IdleTimeout { get; set; } }
            public class Test
            {
                public void Configure(SessionOptions opts)
                {
                    opts.IdleTimeout = TimeSpan.FromMinutes(60);
                }
            }
            """;

        var findings = await RunAnalysis(source, new SessionTimeoutExcessiveRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1015"));
    }

    [Fact]
    public async Task SMOL1015_Negative1_15MinTimeout_NotDetected()
    {
        const string source = """
            using System;
            public class SessionOptions { public TimeSpan IdleTimeout { get; set; } }
            public class Test
            {
                public void Configure(SessionOptions opts)
                {
                    opts.IdleTimeout = TimeSpan.FromMinutes(15);
                }
            }
            """;

        var findings = await RunAnalysis(source, new SessionTimeoutExcessiveRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1015_Negative2_5MinTimeout_NotDetected()
    {
        const string source = """
            using System;
            public class SessionOptions { public TimeSpan IdleTimeout { get; set; } }
            public class Test
            {
                public void Configure(SessionOptions opts)
                {
                    opts.IdleTimeout = TimeSpan.FromMinutes(5);
                }
            }
            """;

        var findings = await RunAnalysis(source, new SessionTimeoutExcessiveRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1015_Negative3_UnrelatedProperty_NotDetected()
    {
        const string source = """
            using System;
            public class Options { public TimeSpan Delay { get; set; } }
            public class Test
            {
                public void Configure(Options opts)
                {
                    opts.Delay = TimeSpan.FromMinutes(60);
                }
            }
            """;

        var findings = await RunAnalysis(source, new SessionTimeoutExcessiveRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1016 — FinancialOperationWithoutIdempotency
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1016_Positive1_TransferWithoutIdempotency_Detected()
    {
        const string source = """
            public class PaymentService
            {
                public void ProcessTransfer(decimal amount, string destination)
                {
                    // process transfer
                }
            }
            """;

        var findings = await RunAnalysis(source, new FinancialOperationWithoutIdempotencyRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1016"));
    }

    [Fact]
    public async Task SMOL1016_Positive2_PixPaymentWithoutKey_Detected()
    {
        const string source = """
            public class PixService
            {
                public void ExecutePixPayment(decimal amount, string recipientKey)
                {
                    // process PIX
                }
            }
            """;

        var findings = await RunAnalysis(source, new FinancialOperationWithoutIdempotencyRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1016"));
    }

    [Fact]
    public async Task SMOL1016_Positive3_RefundWithoutIdempotency_Detected()
    {
        const string source = """
            public class OrderService
            {
                public void ProcessRefund(int orderId, decimal amount)
                {
                    // process refund
                }
            }
            """;

        var findings = await RunAnalysis(source, new FinancialOperationWithoutIdempotencyRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1016"));
    }

    [Fact]
    public async Task SMOL1016_Negative1_TransferWithIdempotencyKey_NotDetected()
    {
        const string source = """
            public class PaymentService
            {
                public void ProcessTransfer(decimal amount, string destination, string idempotencyKey)
                {
                    // process transfer
                }
            }
            """;

        var findings = await RunAnalysis(source, new FinancialOperationWithoutIdempotencyRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1016_Negative2_NonFinancialMethod_NotDetected()
    {
        const string source = """
            public class UserService
            {
                public void UpdateProfile(string name, string email)
                {
                    // update profile
                }
            }
            """;

        var findings = await RunAnalysis(source, new FinancialOperationWithoutIdempotencyRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1016_Negative3_TransferWithRequestId_NotDetected()
    {
        const string source = """
            public class PaymentService
            {
                public void ProcessTransfer(decimal amount, string destination, string requestId)
                {
                    // process transfer with request ID
                }
            }
            """;

        var findings = await RunAnalysis(source, new FinancialOperationWithoutIdempotencyRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // Helper
    // ═══════════════════════════════════════════════════════

    private static async Task<ImmutableArray<Finding>> RunAnalysis(string source, SmolerRule rule)
    {
        var acquirer = new InMemoryCompilationAcquirer([source], References);
        var registry = new DefaultRuleRegistry();
        registry.Register(rule);
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
        return result.Findings;
    }
}
