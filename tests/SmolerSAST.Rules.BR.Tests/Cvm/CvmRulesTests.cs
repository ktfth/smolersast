using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.BR.Cvm;

namespace SmolerSAST.Rules.BR.Tests.Cvm;

public sealed class CvmRulesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // SMOL1022 — MarketOperationWithoutAuditTrail
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1022_Positive1_PlaceOrderNoAudit_Detected()
    {
        const string source = """
            public class TradingService
            {
                public void PlaceOrder(string symbol, int quantity, decimal price)
                {
                    // execute order directly
                    var filled = true;
                }
            }
            """;

        var findings = await RunAnalysis(source, new MarketOperationWithoutAuditTrailRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1022"));
    }

    [Fact]
    public async Task SMOL1022_Positive2_CancelOrderNoAudit_Detected()
    {
        const string source = """
            public class OrderService
            {
                public void CancelOrder(int orderId)
                {
                    var cancelled = true;
                }
            }
            """;

        var findings = await RunAnalysis(source, new MarketOperationWithoutAuditTrailRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1022"));
    }

    [Fact]
    public async Task SMOL1022_Positive3_SettleTradeNoAudit_Detected()
    {
        const string source = """
            public class SettlementService
            {
                public void SettleTrade(int tradeId)
                {
                    // settle directly
                    var settled = true;
                }
            }
            """;

        var findings = await RunAnalysis(source, new MarketOperationWithoutAuditTrailRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1022"));
    }

    [Fact]
    public async Task SMOL1022_Negative1_OrderWithAuditLog_NotDetected()
    {
        const string source = """
            public interface IAuditLogger { void Log(string message); }
            public class TradingService
            {
                private readonly IAuditLogger _audit;
                public TradingService(IAuditLogger audit) => _audit = audit;
                public void PlaceOrder(string symbol, int quantity)
                {
                    _audit.Log($"Placing order: {symbol} x {quantity}");
                    var filled = true;
                }
            }
            """;

        var findings = await RunAnalysis(source, new MarketOperationWithoutAuditTrailRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1022_Negative2_NonMarketMethod_NotDetected()
    {
        const string source = """
            public class UserService
            {
                public void UpdateProfile(string name)
                {
                    // update profile
                }
            }
            """;

        var findings = await RunAnalysis(source, new MarketOperationWithoutAuditTrailRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1022_Negative3_OrderWithEventTracking_NotDetected()
    {
        const string source = """
            public class TradingService
            {
                public void ExecuteOrder(string symbol)
                {
                    TrackEvent("order_executed");
                }
                private void TrackEvent(string evento) { }
            }
            """;

        var findings = await RunAnalysis(source, new MarketOperationWithoutAuditTrailRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1023 — DataIntegrityWithoutValidation
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1023_Positive1_ProcessQuoteNoIntegrity_Detected()
    {
        const string source = """
            public class QuoteData { public decimal Price { get; set; } }
            public class MarketService
            {
                public void ProcessQuote(QuoteData quote)
                {
                    var price = quote.Price;
                }
            }
            """;

        var findings = await RunAnalysis(source, new DataIntegrityWithoutValidationRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1023"));
    }

    [Fact]
    public async Task SMOL1023_Positive2_HandleOrderNoCheck_Detected()
    {
        const string source = """
            public class Order { public int Quantity { get; set; } }
            public class Processor
            {
                public void HandleOrder(Order order)
                {
                    var qty = order.Quantity;
                }
            }
            """;

        var findings = await RunAnalysis(source, new DataIntegrityWithoutValidationRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1023"));
    }

    [Fact]
    public async Task SMOL1023_Positive3_ReceiveTradeNoValidation_Detected()
    {
        const string source = """
            public class Trade { public decimal Price { get; set; } }
            public class TradeProcessor
            {
                public void ReceiveTrade(Trade trade)
                {
                    var p = trade.Price;
                }
            }
            """;

        var findings = await RunAnalysis(source, new DataIntegrityWithoutValidationRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1023"));
    }

    [Fact]
    public async Task SMOL1023_Negative1_ProcessWithChecksum_NotDetected()
    {
        const string source = """
            public class QuoteData { public decimal Price { get; set; } public string Checksum { get; set; } }
            public class MarketService
            {
                public void ProcessQuote(QuoteData quote)
                {
                    VerifyChecksum(quote);
                    var price = quote.Price;
                }
                private void VerifyChecksum(QuoteData q) { }
            }
            """;

        var findings = await RunAnalysis(source, new DataIntegrityWithoutValidationRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1023_Negative2_NonMarketProcess_NotDetected()
    {
        const string source = """
            public class UserService
            {
                public void ProcessUser(string name) { }
            }
            """;

        var findings = await RunAnalysis(source, new DataIntegrityWithoutValidationRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1023_Negative3_WithHashVerification_NotDetected()
    {
        const string source = """
            public class Trade { public decimal Price { get; set; } }
            public class TradeProcessor
            {
                public void ProcessTrade(Trade trade)
                {
                    var hash = ComputeHash(trade);
                    ValidateIntegrity(hash);
                }
                private string ComputeHash(Trade t) => "";
                private void ValidateIntegrity(string h) { }
            }
            """;

        var findings = await RunAnalysis(source, new DataIntegrityWithoutValidationRule());
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL1024 — RegulatoryReportWithoutDigitalSignature
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL1024_Positive1_GenerateReportNoSignature_Detected()
    {
        const string source = """
            public class ReportService
            {
                public byte[] GenerateReport(string data)
                {
                    return System.Text.Encoding.UTF8.GetBytes(data);
                }
            }
            """;

        var findings = await RunAnalysis(source, new RegulatoryReportWithoutDigitalSignatureRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1024"));
    }

    [Fact]
    public async Task SMOL1024_Positive2_ExportRegulatoryReportNoSign_Detected()
    {
        const string source = """
            public class CvmReporting
            {
                public void ExportRegulatoryReport(string path)
                {
                    System.IO.File.WriteAllText(path, "report data");
                }
            }
            """;

        var findings = await RunAnalysis(source, new RegulatoryReportWithoutDigitalSignatureRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1024"));
    }

    [Fact]
    public async Task SMOL1024_Positive3_GerarRelatorioNoSign_Detected()
    {
        const string source = """
            public class RelatorioService
            {
                public string GerarRelatorio()
                {
                    return "dados do relatório";
                }
            }
            """;

        var findings = await RunAnalysis(source, new RegulatoryReportWithoutDigitalSignatureRule());
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1024"));
    }

    [Fact]
    public async Task SMOL1024_Negative1_ReportWithSignature_NotDetected()
    {
        const string source = """
            public class ReportService
            {
                public byte[] GenerateReport(string data)
                {
                    var bytes = System.Text.Encoding.UTF8.GetBytes(data);
                    var signed = SignWithCertificate(bytes);
                    return signed;
                }
                private byte[] SignWithCertificate(byte[] data) => data;
            }
            """;

        var findings = await RunAnalysis(source, new RegulatoryReportWithoutDigitalSignatureRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1024_Negative2_NonReportMethod_NotDetected()
    {
        const string source = """
            public class DataService
            {
                public string ProcessData(string input) => input.ToUpper();
            }
            """;

        var findings = await RunAnalysis(source, new RegulatoryReportWithoutDigitalSignatureRule());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL1024_Negative3_ReportWithX509_NotDetected()
    {
        const string source = """
            public class CvmReporting
            {
                public void GenerateReport(string data)
                {
                    var x509 = LoadCertificate();
                    SignDocument(data, x509);
                }
                private object LoadCertificate() => null;
                private void SignDocument(string d, object cert) { }
            }
            """;

        var findings = await RunAnalysis(source, new RegulatoryReportWithoutDigitalSignatureRule());
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
