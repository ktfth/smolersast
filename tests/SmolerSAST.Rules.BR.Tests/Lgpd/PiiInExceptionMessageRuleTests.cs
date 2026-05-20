using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.BR.Lgpd;

namespace SmolerSAST.Rules.BR.Tests.Lgpd;

public sealed class PiiInExceptionMessageRuleTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // POSITIVE CASES — MUST detect
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Positive1_CpfInException_Detected()
    {
        const string source = """
            public class Test
            {
                public void Validate(string cpf)
                {
                    throw new ArgumentException($"CPF inválido: {cpf}");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1003"));
    }

    [Fact]
    public async Task Positive2_EmailInInvalidOperationException_Detected()
    {
        const string source = """
            using System;
            public class Test
            {
                public void Process(string email)
                {
                    throw new InvalidOperationException("Email não encontrado: " + email);
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1003"));
    }

    [Fact]
    public async Task Positive3_DocumentoInApplicationException_Detected()
    {
        const string source = """
            using System;
            public class Test
            {
                public void Check(string documento)
                {
                    throw new ApplicationException($"Documento inválido: {documento}");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL1003"));
    }

    // ═══════════════════════════════════════════════════════
    // NEGATIVE CASES — MUST NOT detect
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Negative1_GenericExceptionMessage_NotDetected()
    {
        const string source = """
            using System;
            public class Test
            {
                public void Process()
                {
                    throw new InvalidOperationException("Operação não permitida");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative2_ExceptionWithId_NotDetected()
    {
        const string source = """
            using System;
            public class Test
            {
                public void Process(int orderId)
                {
                    throw new ArgumentException($"Order {orderId} not found");
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Negative3_NoExceptionCreation_NotDetected()
    {
        const string source = """
            public class Test
            {
                public string GetCpf() => "123.456.789-00";
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Empty(findings);
    }

    [Fact]
    public void RuleMetadata_IsCorrect()
    {
        var rule = new PiiInExceptionMessageRule();
        Assert.Equal(new RuleId("SMOL1003"), rule.Id);
        Assert.Contains(209, rule.CweIds);
        Assert.Equal(RuleSeverity.High, rule.Severity);
        Assert.False(string.IsNullOrEmpty(rule.DescriptionPtBr));
        Assert.False(string.IsNullOrEmpty(rule.DescriptionEnUs));
    }

    private static async Task<ImmutableArray<Finding>> RunAnalysis(string source)
    {
        var acquirer = new InMemoryCompilationAcquirer([source], References);
        var registry = new DefaultRuleRegistry();
        registry.Register(new PiiInExceptionMessageRule());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
        return result.Findings;
    }
}
