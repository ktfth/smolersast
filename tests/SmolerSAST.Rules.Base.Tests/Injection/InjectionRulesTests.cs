using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Injection;

namespace SmolerSAST.Rules.Base.Tests.Injection;

public sealed class InjectionRulesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // SMOL0001 — Raw SQL concatenation in SqlCommand
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0001_Positive1_CommandText_ConcatenatedSql_Detected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run(string userId)
                {
                    var cmd = new System.Data.SqlClient.SqlCommand();
                    cmd.CommandText = "SELECT * FROM Users WHERE Id = " + userId;
                }
            }
            """;

        var findings = await RunAnalysis<RawSqlConcatenationRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0001"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0001_Positive2_Constructor_ConcatenatedSql_Detected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public SqlCommand(string commandText) { }
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run(string name)
                {
                    var cmd = new System.Data.SqlClient.SqlCommand(
                        "SELECT * FROM Users WHERE Name = '" + name + "'");
                }
            }
            """;

        var findings = await RunAnalysis<RawSqlConcatenationRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0001_Negative1_ParameterizedQuery_NotDetected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run()
                {
                    var cmd = new System.Data.SqlClient.SqlCommand();
                    cmd.CommandText = "SELECT * FROM Users WHERE Id = @id";
                }
            }
            """;

        var findings = await RunAnalysis<RawSqlConcatenationRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0001_Negative2_ConstantConcatenation_NotDetected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run()
                {
                    const string table = "Users";
                    var cmd = new System.Data.SqlClient.SqlCommand();
                    cmd.CommandText = "SELECT * FROM " + table;
                }
            }
            """;

        var findings = await RunAnalysis<RawSqlConcatenationRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0002 — FormattableString.Invariant misuse in SQL
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0002_Positive1_InvariantInCommandText_Detected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run(int userId)
                {
                    var cmd = new System.Data.SqlClient.SqlCommand();
                    cmd.CommandText = FormattableString.Invariant($"SELECT * FROM Users WHERE Id = {userId}");
                }
            }
            """;

        var findings = await RunAnalysis<FormattableStringInvariantSqlRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0002"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0002_Positive2_InvariantInConstructor_Detected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public SqlCommand(string commandText) { }
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run(string name)
                {
                    var cmd = new System.Data.SqlClient.SqlCommand(
                        FormattableString.Invariant($"SELECT * FROM Users WHERE Name = '{name}'"));
                }
            }
            """;

        var findings = await RunAnalysis<FormattableStringInvariantSqlRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0002_Negative1_RegularStringLiteral_NotDetected()
    {
        const string source = """
            namespace System.Data.SqlClient
            {
                public class SqlCommand
                {
                    public string CommandText { get; set; }
                }
            }

            public class Test
            {
                public void Run()
                {
                    var cmd = new System.Data.SqlClient.SqlCommand();
                    cmd.CommandText = "SELECT * FROM Users";
                }
            }
            """;

        var findings = await RunAnalysis<FormattableStringInvariantSqlRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0002_Negative2_InvariantNotOnSqlCommand_NotDetected()
    {
        const string source = """
            public class MyClass
            {
                public string Label { get; set; }
            }

            public class Test
            {
                public void Run(int value)
                {
                    var obj = new MyClass();
                    obj.Label = FormattableString.Invariant($"Value is {value}");
                }
            }
            """;

        var findings = await RunAnalysis<FormattableStringInvariantSqlRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0003 — LDAP injection
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0003_Positive1_DirectoryEntry_ConcatenatedPath_Detected()
    {
        const string source = """
            namespace System.DirectoryServices
            {
                public class DirectoryEntry
                {
                    public DirectoryEntry(string path) { }
                }
            }

            public class Test
            {
                public void Run(string userInput)
                {
                    var entry = new System.DirectoryServices.DirectoryEntry(
                        "LDAP://DC=" + userInput);
                }
            }
            """;

        var findings = await RunAnalysis<LdapInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0003"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0003_Positive2_DirectorySearcher_Filter_Detected()
    {
        const string source = """
            namespace System.DirectoryServices
            {
                public class DirectorySearcher
                {
                    public string Filter { get; set; }
                }
            }

            public class Test
            {
                public void Run(string userName)
                {
                    var searcher = new System.DirectoryServices.DirectorySearcher();
                    searcher.Filter = "(cn=" + userName + ")";
                }
            }
            """;

        var findings = await RunAnalysis<LdapInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0003_Negative1_LiteralPath_NotDetected()
    {
        const string source = """
            namespace System.DirectoryServices
            {
                public class DirectoryEntry
                {
                    public DirectoryEntry(string path) { }
                }
            }

            public class Test
            {
                public void Run()
                {
                    var entry = new System.DirectoryServices.DirectoryEntry(
                        "LDAP://DC=example,DC=com");
                }
            }
            """;

        var findings = await RunAnalysis<LdapInjectionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0003_Negative2_UnrelatedClass_NotDetected()
    {
        const string source = """
            public class DirectorySearcher
            {
                public string Filter { get; set; }
            }

            public class Test
            {
                public void Run(string input)
                {
                    var searcher = new DirectorySearcher();
                    searcher.Filter = "(cn=" + input + ")";
                }
            }
            """;

        var findings = await RunAnalysis<LdapInjectionRule>(source);
        // This user-defined DirectorySearcher is NOT in System.DirectoryServices
        // Symbol resolution should differentiate it
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0004 — XPath injection
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0004_Positive1_SelectNodes_Concatenation_Detected()
    {
        const string source = """
            namespace System.Xml
            {
                public class XmlNode
                {
                    public object SelectNodes(string xpath) => null;
                    public object SelectSingleNode(string xpath) => null;
                }
                public class XmlDocument : XmlNode { }
            }

            public class Test
            {
                public void Run(System.Xml.XmlDocument doc, string userName)
                {
                    var nodes = doc.SelectNodes("//user[@name='" + userName + "']");
                }
            }
            """;

        var findings = await RunAnalysis<XPathInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0004"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0004_Positive2_SelectSingleNode_Concatenation_Detected()
    {
        const string source = """
            namespace System.Xml
            {
                public class XmlNode
                {
                    public object SelectNodes(string xpath) => null;
                    public object SelectSingleNode(string xpath) => null;
                }
                public class XmlDocument : XmlNode { }
            }

            public class Test
            {
                public void Run(System.Xml.XmlDocument doc, string id)
                {
                    var node = doc.SelectSingleNode("//item[@id='" + id + "']");
                }
            }
            """;

        var findings = await RunAnalysis<XPathInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0004_Negative1_LiteralXPath_NotDetected()
    {
        const string source = """
            namespace System.Xml
            {
                public class XmlNode
                {
                    public object SelectNodes(string xpath) => null;
                }
                public class XmlDocument : XmlNode { }
            }

            public class Test
            {
                public void Run(System.Xml.XmlDocument doc)
                {
                    var nodes = doc.SelectNodes("//user[@active='true']");
                }
            }
            """;

        var findings = await RunAnalysis<XPathInjectionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0004_Negative2_ConcatenationOnUnrelatedType_NotDetected()
    {
        const string source = """
            public class MyXmlHelper
            {
                public string SelectNodes(string xpath) => xpath;
            }

            public class Test
            {
                public void Run(string input)
                {
                    var helper = new MyXmlHelper();
                    var result = helper.SelectNodes("//item[@id='" + input + "']");
                }
            }
            """;

        var findings = await RunAnalysis<XPathInjectionRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0005 — Command injection
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0005_Positive1_ProcessStart_ConcatenatedArgs_Detected()
    {
        const string source = """
            namespace System.Diagnostics
            {
                public class ProcessStartInfo
                {
                    public string FileName { get; set; }
                    public string Arguments { get; set; }
                }
                public class Process
                {
                    public static void Start(string fileName, string arguments) { }
                }
            }

            public class Test
            {
                public void Run(string userInput)
                {
                    System.Diagnostics.Process.Start("cmd.exe", "/c " + userInput);
                }
            }
            """;

        var findings = await RunAnalysis<CommandInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0005"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0005_Positive2_ProcessStartInfo_Arguments_Detected()
    {
        const string source = """
            namespace System.Diagnostics
            {
                public class ProcessStartInfo
                {
                    public string FileName { get; set; }
                    public string Arguments { get; set; }
                }
            }

            public class Test
            {
                public void Run(string userInput)
                {
                    var psi = new System.Diagnostics.ProcessStartInfo();
                    psi.Arguments = "/c " + userInput;
                }
            }
            """;

        var findings = await RunAnalysis<CommandInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0005_Negative1_LiteralArgs_NotDetected()
    {
        const string source = """
            namespace System.Diagnostics
            {
                public class Process
                {
                    public static void Start(string fileName, string arguments) { }
                }
            }

            public class Test
            {
                public void Run()
                {
                    System.Diagnostics.Process.Start("notepad.exe", "readme.txt");
                }
            }
            """;

        var findings = await RunAnalysis<CommandInjectionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0005_Negative2_ProcessStartInfo_LiteralFileName_NotDetected()
    {
        const string source = """
            namespace System.Diagnostics
            {
                public class ProcessStartInfo
                {
                    public string FileName { get; set; }
                    public string Arguments { get; set; }
                }
            }

            public class Test
            {
                public void Run()
                {
                    var psi = new System.Diagnostics.ProcessStartInfo();
                    psi.FileName = "notepad.exe";
                    psi.Arguments = "--version";
                }
            }
            """;

        var findings = await RunAnalysis<CommandInjectionRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0006 — LINQ-to-SQL string composition
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0006_Positive1_ExecuteQuery_Concatenation_Detected()
    {
        const string source = """
            namespace System.Data.Linq
            {
                public class DataContext
                {
                    public DataContext(string conn) { }
                    public object ExecuteQuery(System.Type type, string query) => null;
                }
            }

            public class Test
            {
                public void Run(string name)
                {
                    var ctx = new System.Data.Linq.DataContext("connStr");
                    ctx.ExecuteQuery(typeof(object), "SELECT * FROM Users WHERE Name = '" + name + "'");
                }
            }
            """;

        var findings = await RunAnalysis<LinqToSqlInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0006"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0006_Positive2_ExecuteCommand_Concatenation_Detected()
    {
        const string source = """
            namespace System.Data.Linq
            {
                public class DataContext
                {
                    public DataContext(string conn) { }
                    public int ExecuteCommand(string command) => 0;
                }
            }

            public class Test
            {
                public void Run(string table)
                {
                    var ctx = new System.Data.Linq.DataContext("connStr");
                    ctx.ExecuteCommand("DROP TABLE " + table);
                }
            }
            """;

        var findings = await RunAnalysis<LinqToSqlInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0006_Negative1_ParameterizedQuery_NotDetected()
    {
        const string source = """
            namespace System.Data.Linq
            {
                public class DataContext
                {
                    public DataContext(string conn) { }
                    public int ExecuteCommand(string command) => 0;
                }
            }

            public class Test
            {
                public void Run()
                {
                    var ctx = new System.Data.Linq.DataContext("connStr");
                    ctx.ExecuteCommand("SELECT * FROM Users WHERE Id = {0}");
                }
            }
            """;

        var findings = await RunAnalysis<LinqToSqlInjectionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0006_Negative2_UnrelatedExecuteQuery_NotDetected()
    {
        const string source = """
            public class MyContext
            {
                public object ExecuteQuery(string query) => null;
            }

            public class Test
            {
                public void Run(string input)
                {
                    var ctx = new MyContext();
                    ctx.ExecuteQuery("SELECT * FROM " + input);
                }
            }
            """;

        var findings = await RunAnalysis<LinqToSqlInjectionRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0007 — NoSQL injection in MongoDB
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0007_Positive1_BsonDocumentParse_Concatenation_Detected()
    {
        const string source = """
            namespace MongoDB.Bson
            {
                public class BsonDocument
                {
                    public static BsonDocument Parse(string json) => new BsonDocument();
                }
            }

            public class Test
            {
                public void Run(string userInput)
                {
                    var filter = MongoDB.Bson.BsonDocument.Parse("{ name: '" + userInput + "' }");
                }
            }
            """;

        var findings = await RunAnalysis<NoSqlInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0007"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0007_Positive2_BuildersParse_Concatenation_Detected()
    {
        const string source = """
            namespace MongoDB.Bson
            {
                public class BsonDocument
                {
                    public static BsonDocument Parse(string json) => new BsonDocument();
                }
            }

            public class Test
            {
                public void Run(string input)
                {
                    var doc = MongoDB.Bson.BsonDocument.Parse("{ $where: '" + input + "' }");
                }
            }
            """;

        var findings = await RunAnalysis<NoSqlInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0007_Negative1_LiteralParse_NotDetected()
    {
        const string source = """
            namespace MongoDB.Bson
            {
                public class BsonDocument
                {
                    public static BsonDocument Parse(string json) => new BsonDocument();
                }
            }

            public class Test
            {
                public void Run()
                {
                    var doc = MongoDB.Bson.BsonDocument.Parse("{ active: true }");
                }
            }
            """;

        var findings = await RunAnalysis<NoSqlInjectionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0007_Negative2_UnrelatedParse_NotDetected()
    {
        const string source = """
            public class JsonHelper
            {
                public static object Parse(string json) => null;
            }

            public class Test
            {
                public void Run(string input)
                {
                    var result = JsonHelper.Parse("{ name: '" + input + "' }");
                }
            }
            """;

        var findings = await RunAnalysis<NoSqlInjectionRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0008 — Dapper SQL injection
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0008_Positive1_DapperQuery_Concatenation_Detected()
    {
        const string source = """
            namespace Dapper
            {
                public static class SqlMapper
                {
                    public static object Query(object conn, string sql) => null;
                }
            }

            public class Test
            {
                public void Run(object connection, string name)
                {
                    Dapper.SqlMapper.Query(connection, "SELECT * FROM Users WHERE Name = '" + name + "'");
                }
            }
            """;

        var findings = await RunAnalysis<DapperSqlInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0008"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0008_Positive2_DapperExecute_Concatenation_Detected()
    {
        const string source = """
            namespace Dapper
            {
                public static class SqlMapper
                {
                    public static int Execute(object conn, string sql) => 0;
                }
            }

            public class Test
            {
                public void Run(object connection, string table)
                {
                    Dapper.SqlMapper.Execute(connection, "DROP TABLE " + table);
                }
            }
            """;

        var findings = await RunAnalysis<DapperSqlInjectionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 finding, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0008_Negative1_ParameterizedDapper_NotDetected()
    {
        const string source = """
            namespace Dapper
            {
                public static class SqlMapper
                {
                    public static object Query(object conn, string sql) => null;
                }
            }

            public class Test
            {
                public void Run(object connection)
                {
                    Dapper.SqlMapper.Query(connection, "SELECT * FROM Users WHERE Id = @Id");
                }
            }
            """;

        var findings = await RunAnalysis<DapperSqlInjectionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0008_Negative2_UnrelatedExecute_NotDetected()
    {
        const string source = """
            public class MyService
            {
                public void Execute(string command) { }
            }

            public class Test
            {
                public void Run(string input)
                {
                    var svc = new MyService();
                    svc.Execute("action:" + input);
                }
            }
            """;

        var findings = await RunAnalysis<DapperSqlInjectionRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // Rule metadata tests
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllInjectionRules))]
    public void RuleMetadata_HasRequiredFields(SmolerRule rule, string expectedId)
    {
        Assert.Equal(new RuleId(expectedId), rule.Id);
        Assert.False(rule.CweIds.IsEmpty);
        Assert.Equal("A03:2021", rule.OwaspCategory);
        Assert.False(string.IsNullOrEmpty(rule.DescriptionPtBr));
        Assert.False(string.IsNullOrEmpty(rule.DescriptionEnUs));
        Assert.False(string.IsNullOrEmpty(rule.RemediationGuidancePtBr));
        Assert.Contains("injection", rule.Tags);
    }

    public static TheoryData<SmolerRule, string> AllInjectionRules =>
        new()
        {
            { new RawSqlConcatenationRule(), "SMOL0001" },
            { new FormattableStringInvariantSqlRule(), "SMOL0002" },
            { new LdapInjectionRule(), "SMOL0003" },
            { new XPathInjectionRule(), "SMOL0004" },
            { new CommandInjectionRule(), "SMOL0005" },
            { new LinqToSqlInjectionRule(), "SMOL0006" },
            { new NoSqlInjectionRule(), "SMOL0007" },
            { new DapperSqlInjectionRule(), "SMOL0008" },
        };

    // ═══════════════════════════════════════════════════════
    // Helper
    // ═══════════════════════════════════════════════════════

    private static async Task<ImmutableArray<Finding>> RunAnalysis<TRule>(string source)
        where TRule : SmolerRule, new()
    {
        var acquirer = new InMemoryCompilationAcquirer([source], References);
        var registry = new DefaultRuleRegistry();
        registry.Register(new TRule());

        var symbolIndex = new InMemorySymbolIndex();
        var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);
        var options = new AnalysisPipelineOptions("test");

        var result = await pipeline.RunAsync(options);
        return result.Findings;
    }
}
