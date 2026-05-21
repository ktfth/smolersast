using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Injection;

namespace SmolerSAST.Rules.Base.Tests.Injection;

public sealed class TaintAwareSqlInjectionRuleTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // POSITIVE CASES — MUST detect taint flow
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Positive1_DirectParameterToSql_Detected()
    {
        const string source = """
            using System;
            using System.Data;
            using System.Data.SqlClient;

            public class UserController
            {
                public void Search([FromQuery] string query)
                {
                    var cmd = new SqlCommand();
                    cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + query + "'";
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromQueryAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Positive2_TaintThroughVariable_Detected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class Controller
            {
                public void Delete([FromBody] string userId)
                {
                    var sql = "DELETE FROM Users WHERE Id = '" + userId + "'";
                    var cmd = new SqlCommand();
                    cmd.CommandText = sql;
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromBodyAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Positive3_InterpolatedString_Detected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class Api
            {
                public void GetById([FromRoute] string id)
                {
                    var cmd = new SqlCommand();
                    cmd.CommandText = $"SELECT * FROM Products WHERE Id = '{id}'";
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromRouteAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Positive4_TaintThroughMultipleSteps_Detected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class Handler
            {
                public void Process([FromForm] string input)
                {
                    var trimmed = input.Trim();
                    var lower = trimmed.ToLower();
                    var sql = "SELECT * FROM Data WHERE Val = '" + lower + "'";
                    var cmd = new SqlCommand();
                    cmd.CommandText = sql;
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromFormAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Positive5_FileReadToSql_Detected()
    {
        const string source = """
            using System.IO;
            using System.Data.SqlClient;

            public class Importer
            {
                public void ImportFile(string path)
                {
                    var content = File.ReadAllText(path);
                    var cmd = new SqlCommand();
                    cmd.CommandText = "INSERT INTO Logs VALUES ('" + content + "')";
                    cmd.ExecuteNonQuery();
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.Contains(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    // ═══════════════════════════════════════════════════════
    // NEGATIVE CASES — MUST NOT detect (sanitized or safe)
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Negative1_ParameterizedQuery_NotDetected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class SafeController
            {
                public void Search([FromQuery] string query)
                {
                    var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name");
                    cmd.Parameters.AddWithValue("@name", query);
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromQueryAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.DoesNotContain(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Negative2_ParsedToInt_NotDetected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class SafeApi
            {
                public void GetById([FromQuery] string id)
                {
                    var safeId = int.Parse(id);
                    var cmd = new SqlCommand();
                    cmd.CommandText = "SELECT * FROM Products WHERE Id = " + safeId;
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromQueryAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.DoesNotContain(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Negative3_HtmlEncoded_NotDetected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class SafeHandler
            {
                public void Process([FromBody] string input)
                {
                    var safe = Sanitize(input);
                    var cmd = new SqlCommand();
                    cmd.CommandText = "SELECT * FROM Data WHERE Val = '" + safe + "'";
                    cmd.ExecuteNonQuery();
                }

                private string Sanitize(string v) => v.Replace("'", "''");
            }

            public class FromBodyAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.DoesNotContain(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Negative4_NoTaintSource_NotDetected()
    {
        const string source = """
            using System.Data.SqlClient;

            public class InternalService
            {
                public void RunQuery()
                {
                    var cmd = new SqlCommand();
                    cmd.CommandText = "SELECT COUNT(*) FROM Users";
                    cmd.ExecuteNonQuery();
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.DoesNotContain(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Negative5_ConstantSql_NotDetected()
    {
        const string source = """
            using System.Data.SqlClient;

            public class Repository
            {
                private const string Query = "SELECT * FROM Users WHERE Active = 1";
                public void GetActive()
                {
                    var cmd = new SqlCommand();
                    cmd.CommandText = Query;
                    cmd.ExecuteNonQuery();
                }
            }
            """;

        var findings = await RunAnalysis(source);
        Assert.DoesNotContain(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    [Fact]
    public async Task Negative6_ValidatedInput_NotDetected()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class ValidatedController
            {
                public void Search([FromQuery] string query)
                {
                    var validated = Validate(query);
                    var cmd = new SqlCommand();
                    cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + validated + "'";
                    cmd.ExecuteNonQuery();
                }

                private string Validate(string input) => input;
            }

            public class FromQueryAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        Assert.DoesNotContain(findings, f => f.RuleId == new RuleId("SMOL0041"));
    }

    // ═══════════════════════════════════════════════════════
    // METADATA
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void RuleMetadata_IsCorrect()
    {
        var rule = new TaintAwareSqlInjectionRule();
        Assert.Equal(new RuleId("SMOL0041"), rule.Id);
        Assert.Contains(89, rule.CweIds);
        Assert.Equal(RuleSeverity.Critical, rule.Severity);
        Assert.Equal(RulePrecision.High, rule.Precision);
        Assert.Contains("taint", rule.Tags);
    }

    // ═══════════════════════════════════════════════════════
    // CONFIDENCE SCORING
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Confidence_DirectFlow_IsHigh()
    {
        const string source = """
            using System;
            using System.Data.SqlClient;

            public class Api
            {
                public void Run([FromQuery] string input)
                {
                    var cmd = new SqlCommand();
                    cmd.CommandText = "SELECT * FROM T WHERE X = '" + input + "'";
                    cmd.ExecuteNonQuery();
                }
            }

            public class FromQueryAttribute : Attribute { }
            """;

        var findings = await RunAnalysis(source);
        var taintFinding = findings.FirstOrDefault(f => f.RuleId == new RuleId("SMOL0041"));
        Assert.NotNull(taintFinding);
        Assert.True(taintFinding.Confidence >= 0.75, $"Confidence {taintFinding.Confidence} should be >= 0.75");
    }

    private static async Task<ImmutableArray<Finding>> RunAnalysis(string source)
    {
        var acquirer = new InMemoryCompilationAcquirer([source], References);
        var registry = new DefaultRuleRegistry();
        registry.Register(new TaintAwareSqlInjectionRule());
        var pipeline = new AnalysisPipeline(acquirer, registry, new InMemorySymbolIndex());
        var result = await pipeline.RunAsync(new AnalysisPipelineOptions("test"));
        return result.Findings;
    }
}
