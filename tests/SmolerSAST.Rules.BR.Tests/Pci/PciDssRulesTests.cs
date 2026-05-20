using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.BR.Pci;

namespace SmolerSAST.Rules.BR.Tests.Pci;

public sealed class PciDssRulesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // SMOL1017 — PanInLog
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1017_Positive1_CardNumberInLog_Detected()
    {
        const string source = """
            public interface ILogger { void LogInformation(string message, params object[] args); }
            public class Test
            {
                public void Process(ILogger logger, string cardNumber)
                {
                    logger.LogInformation("Processing card: {CardNumber}", cardNumber);
                }
            }
            """;

        var findings = await RunAnalysis(source, new PanInLogRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1017"));
    }

    [Fact]
    public async Task SMOL1017_Positive2_PanInDebugLog_Detected()
    {
        const string source = """
            public interface ILogger { void Debug(string message); }
            public class Test
            {
                public void Process(ILogger logger, string pan)
                {
                    logger.Debug($"PAN value: {pan}");
                }
            }
            """;

        var findings = await RunAnalysis(source, new PanInLogRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1017"));
    }

    [Fact]
    public async Task SMOL1017_Positive3_CreditCardInError_Detected()
    {
        const string source = """
            public interface ILogger { void LogError(string message, params object[] args); }
            public class Test
            {
                public void OnError(ILogger logger, string creditCard)
                {
                    logger.LogError("Failed for creditCard: {CreditCard}", creditCard);
                }
            }
            """;

        var findings = await RunAnalysis(source, new PanInLogRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1017"));
    }

    [Fact]
    public async Task SMOL1017_Negative1_MaskedPan_NotDetected()
    {
        const string source = """
            public interface ILogger { void LogInformation(string message, params object[] args); }
            public class Test
            {
                public void Process(ILogger logger, string cardNumber)
                {
                    logger.LogInformation("Card: {MaskedCard}", MaskCardNumber(cardNumber));
                }
                private string MaskCardNumber(string card) => "****" + card[^4..];
            }
            """;

        var findings = await RunAnalysis(source, new PanInLogRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1017_Negative2_NonCardInLog_NotDetected()
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

        var findings = await RunAnalysis(source, new PanInLogRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1017_Negative3_RedactedCard_NotDetected()
    {
        const string source = """
            public interface ILogger { void LogInformation(string message, params object[] args); }
            public class Test
            {
                public void Process(ILogger logger, string cardNumber)
                {
                    var redacted = Redact(cardNumber);
                    logger.LogInformation("Card: {Redacted}", redacted);
                }
                private string Redact(string v) => "***";
            }
            """;

        var findings = await RunAnalysis(source, new PanInLogRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1018 — CvvStorage
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1018_Positive1_CvvPropertyInEntity_Detected()
    {
        const string source = """
            public class PaymentEntity
            {
                public string CardNumber { get; set; }
                public string Cvv { get; set; }
                public decimal Amount { get; set; }
            }
            """;

        var findings = await RunAnalysis(source, new CvvStorageRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1018"));
    }

    [Fact]
    public async Task SMOL1018_Positive2_SecurityCodeInModel_Detected()
    {
        const string source = """
            public class CardModel
            {
                public string Number { get; set; }
                public string SecurityCode { get; set; }
            }
            """;

        var findings = await RunAnalysis(source, new CvvStorageRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1018"));
    }

    [Fact]
    public async Task SMOL1018_Positive3_CvcInTableEntity_Detected()
    {
        const string source = """
            [System.ComponentModel.DataAnnotations.Schema.Table("payments")]
            public class PaymentRecord
            {
                public int Id { get; set; }
                public string Cvc { get; set; }
            }
            """;

        var findings = await RunAnalysis(source, new CvvStorageRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1018"));
    }

    [Fact]
    public async Task SMOL1018_Negative1_CvvReadOnlyProperty_NotDetected()
    {
        const string source = """
            public class PaymentRequest
            {
                public string Cvv { get; }
                public PaymentRequest(string cvv) => Cvv = cvv;
            }
            """;

        var findings = await RunAnalysis(source, new CvvStorageRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1018_Negative2_NoCvvProperty_NotDetected()
    {
        const string source = """
            public class Order
            {
                public string Id { get; set; }
                public decimal Amount { get; set; }
            }
            """;

        var findings = await RunAnalysis(source, new CvvStorageRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1018_Negative3_CvvInMethodNotProperty_NotDetected()
    {
        const string source = """
            public class Validator
            {
                public bool ValidateCvv(string cvv) => cvv.Length == 3;
            }
            """;

        var findings = await RunAnalysis(source, new CvvStorageRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1020 — CardDataWithoutTls
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1020_Positive1_HttpUrlForPayment_Detected()
    {
        const string source = """
            using System.Net.Http;
            public class PaymentGateway
            {
                public void ProcessPayment()
                {
                    var client = new HttpClient();
                    var url = "http://gateway.example.com/payment";
                }
            }
            """;

        var findings = await RunAnalysis(source, new CardDataWithoutTlsRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1020"));
    }

    [Fact]
    public async Task SMOL1020_Positive2_HttpUrlForCheckout_Detected()
    {
        const string source = """
            public class CheckoutService
            {
                public void SubmitCheckout()
                {
                    var endpoint = "http://api.example.com/checkout";
                }
            }
            """;

        var findings = await RunAnalysis(source, new CardDataWithoutTlsRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1020"));
    }

    [Fact]
    public async Task SMOL1020_Positive3_HttpWithCardVariable_Detected()
    {
        const string source = """
            public class Gateway
            {
                public void SendCardData(string cardNumber)
                {
                    var url = "http://legacy.bank.com/card";
                }
            }
            """;

        var findings = await RunAnalysis(source, new CardDataWithoutTlsRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1020"));
    }

    [Fact]
    public async Task SMOL1020_Negative1_HttpsUrl_NotDetected()
    {
        const string source = """
            public class PaymentGateway
            {
                public void ProcessPayment()
                {
                    var url = "https://gateway.example.com/payment";
                }
            }
            """;

        var findings = await RunAnalysis(source, new CardDataWithoutTlsRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1020_Negative2_HttpNonCardContext_NotDetected()
    {
        const string source = """
            public class WeatherService
            {
                public void GetWeather()
                {
                    var url = "http://api.weather.com/forecast";
                }
            }
            """;

        var findings = await RunAnalysis(source, new CardDataWithoutTlsRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1020_Negative3_NoUrl_NotDetected()
    {
        const string source = """
            public class PaymentService
            {
                public decimal Calculate(decimal amount, decimal tax) => amount + tax;
            }
            """;

        var findings = await RunAnalysis(source, new CardDataWithoutTlsRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1021 — AdminWithoutMfa
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1021_Positive1_AdminControllerNoMfa_Detected()
    {
        const string source = """
            public class AdminController
            {
                public void Dashboard() { }
            }
            """;

        var findings = await RunAnalysis(source, new AdminWithoutMfaRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1021"));
    }

    [Fact]
    public async Task SMOL1021_Positive2_BackofficeControllerNoMfa_Detected()
    {
        const string source = """
            public class BackofficeController
            {
                public void Index() { }
            }
            """;

        var findings = await RunAnalysis(source, new AdminWithoutMfaRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1021"));
    }

    [Fact]
    public async Task SMOL1021_Positive3_ManageControllerNoMfa_Detected()
    {
        const string source = """
            public class ManageDashboardController
            {
                public void Users() { }
            }
            """;

        var findings = await RunAnalysis(source, new AdminWithoutMfaRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1021"));
    }

    [Fact]
    public async Task SMOL1021_Negative1_AdminControllerWithMfa_NotDetected()
    {
        const string source = """
            public class RequireMfaAttribute : System.Attribute { }

            [RequireMfa]
            public class AdminController
            {
                public void Dashboard() { }
            }
            """;

        var findings = await RunAnalysis(source, new AdminWithoutMfaRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1021_Negative2_NonAdminController_NotDetected()
    {
        const string source = """
            public class ProductController
            {
                public void Index() { }
            }
            """;

        var findings = await RunAnalysis(source, new AdminWithoutMfaRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1021_Negative3_NotAController_NotDetected()
    {
        const string source = """
            public class AdminService
            {
                public void Process() { }
            }
            """;

        var findings = await RunAnalysis(source, new AdminWithoutMfaRule());
        Assert.Empty(findings);
    }

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
