using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Deserialization;

namespace SmolerSAST.Rules.Base.Tests.Deserialization;

public sealed class DeserializationRulesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        InMemoryCompilationAcquirer.GetRuntimeReferences();

    // ═══════════════════════════════════════════════════════
    // SMOL0010 — NetDataContractSerializer / SoapFormatter
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0010_Positive1_NetDataContractSerializer_Instantiation_Detected()
    {
        const string mockTypes = """
            namespace System.Runtime.Serialization
            {
                public class NetDataContractSerializer
                {
                    public object ReadObject(System.IO.Stream stream) => null;
                }
            }
            """;

        const string source = """
            using System.IO;
            using System.Runtime.Serialization;

            public class Test
            {
                public object Read(Stream s)
                {
                    var ser = new NetDataContractSerializer();
                    return ser.ReadObject(s);
                }
            }
            """;

        var findings = await RunAnalysis<NetDataContractSerializerSoapFormatterRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0010"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0010_Positive2_SoapFormatter_Instantiation_Detected()
    {
        const string mockTypes = """
            namespace System.Runtime.Serialization.Formatters.Soap
            {
                public class SoapFormatter
                {
                    public object Deserialize(System.IO.Stream stream) => null;
                }
            }
            """;

        const string source = """
            using System.IO;
            using System.Runtime.Serialization.Formatters.Soap;

            public class Test
            {
                public object Read(Stream s)
                {
                    var fmt = new SoapFormatter();
                    return fmt.Deserialize(s);
                }
            }
            """;

        var findings = await RunAnalysis<NetDataContractSerializerSoapFormatterRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0010_Negative1_DataContractSerializer_NotDetected()
    {
        const string source = """
            using System.Runtime.Serialization;
            using System.IO;

            public class Test
            {
                public object Read(Stream s)
                {
                    var ser = new DataContractSerializer(typeof(string));
                    return ser.ReadObject(s);
                }
            }
            """;

        var findings = await RunAnalysis<NetDataContractSerializerSoapFormatterRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0010_Negative2_JsonSerializer_NotDetected()
    {
        const string source = """
            using System.Text.Json;

            public class Test
            {
                public string Serialize(object o) => JsonSerializer.Serialize(o);
            }
            """;

        var findings = await RunAnalysis<NetDataContractSerializerSoapFormatterRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0011 — LosFormatter / ObjectStateFormatter
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0011_Positive1_LosFormatter_Detected()
    {
        const string mockTypes = """
            namespace System.Web.UI
            {
                public class LosFormatter
                {
                    public object Deserialize(string input) => null;
                }
            }
            """;

        const string source = """
            using System.Web.UI;

            public class Test
            {
                public object Read(string data)
                {
                    var fmt = new LosFormatter();
                    return fmt.Deserialize(data);
                }
            }
            """;

        var findings = await RunAnalysis<LosFormatterObjectStateFormatterRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0011"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0011_Positive2_ObjectStateFormatter_Detected()
    {
        const string mockTypes = """
            namespace System.Web.UI
            {
                public class ObjectStateFormatter
                {
                    public object Deserialize(string input) => null;
                }
            }
            """;

        const string source = """
            using System.Web.UI;

            public class Test
            {
                public object Read(string data)
                {
                    var fmt = new ObjectStateFormatter();
                    return fmt.Deserialize(data);
                }
            }
            """;

        var findings = await RunAnalysis<LosFormatterObjectStateFormatterRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0011_Negative1_CustomFormatter_NotDetected()
    {
        const string source = """
            namespace MyApp
            {
                public class LosFormatter
                {
                    public string Format(string data) => data;
                }

                public class Consumer
                {
                    public string Use(string data)
                    {
                        var fmt = new LosFormatter();
                        return fmt.Format(data);
                    }
                }
            }
            """;

        var findings = await RunAnalysis<LosFormatterObjectStateFormatterRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0011_Negative2_JsonFormatter_NotDetected()
    {
        const string source = """
            using System.Text.Json;

            public class Test
            {
                public T Read<T>(string json) => JsonSerializer.Deserialize<T>(json);
            }
            """;

        var findings = await RunAnalysis<LosFormatterObjectStateFormatterRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0012 — ViewState MAC validation disabled
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0012_Positive1_EnableViewStateMac_False_Detected()
    {
        const string mockTypes = """
            namespace System.Web.Configuration
            {
                public class PagesSection
                {
                    public bool EnableViewStateMac { get; set; }
                }
            }
            """;

        const string source = """
            using System.Web.Configuration;

            public class Test
            {
                public void Configure(PagesSection pages)
                {
                    pages.EnableViewStateMac = false;
                }
            }
            """;

        var findings = await RunAnalysis<ViewStateMacDisabledRule>(source, mockTypes);
        Assert.Single(findings);
        Assert.Equal(new RuleId("SMOL0012"), findings[0].RuleId);
    }

    [Fact]
    public async Task SMOL0012_Positive2_Page_EnableViewStateMac_False_Detected()
    {
        const string mockTypes = """
            namespace System.Web.UI
            {
                public class Page
                {
                    public bool EnableViewStateMac { get; set; }
                }
            }
            """;

        const string source = """
            using System.Web.UI;

            public class MyPage : Page
            {
                public void Init()
                {
                    this.EnableViewStateMac = false;
                }
            }
            """;

        var findings = await RunAnalysis<ViewStateMacDisabledRule>(source, mockTypes);
        Assert.Single(findings);
    }

    [Fact]
    public async Task SMOL0012_Negative1_EnableViewStateMac_True_NotDetected()
    {
        const string mockTypes = """
            namespace System.Web.Configuration
            {
                public class PagesSection
                {
                    public bool EnableViewStateMac { get; set; }
                }
            }
            """;

        const string source = """
            using System.Web.Configuration;

            public class Test
            {
                public void Configure(PagesSection pages)
                {
                    pages.EnableViewStateMac = true;
                }
            }
            """;

        var findings = await RunAnalysis<ViewStateMacDisabledRule>(source, mockTypes);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0012_Negative2_DifferentProperty_NotDetected()
    {
        const string source = """
            public class Config
            {
                public bool EnableSomething { get; set; }
            }

            public class Test
            {
                public void Configure(Config c)
                {
                    c.EnableSomething = false;
                }
            }
            """;

        var findings = await RunAnalysis<ViewStateMacDisabledRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0013 — Newtonsoft TypeNameHandling != None
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0013_Positive1_TypeNameHandling_All_Detected()
    {
        const string mockTypes = """
            namespace Newtonsoft.Json
            {
                public enum TypeNameHandling
                {
                    None = 0,
                    Objects = 1,
                    Arrays = 2,
                    All = 3,
                    Auto = 4
                }

                public class JsonSerializerSettings
                {
                    public TypeNameHandling TypeNameHandling { get; set; }
                }
            }
            """;

        const string source = """
            using Newtonsoft.Json;

            public class Test
            {
                public JsonSerializerSettings Create()
                {
                    var settings = new JsonSerializerSettings();
                    settings.TypeNameHandling = TypeNameHandling.All;
                    return settings;
                }
            }
            """;

        var findings = await RunAnalysis<NewtonsoftTypeNameHandlingRule>(source, mockTypes);
        Assert.Single(findings);
        Assert.Equal(new RuleId("SMOL0013"), findings[0].RuleId);
    }

    [Fact]
    public async Task SMOL0013_Positive2_TypeNameHandling_Auto_Detected()
    {
        const string mockTypes = """
            namespace Newtonsoft.Json
            {
                public enum TypeNameHandling
                {
                    None = 0,
                    Objects = 1,
                    Arrays = 2,
                    All = 3,
                    Auto = 4
                }

                public class JsonSerializerSettings
                {
                    public TypeNameHandling TypeNameHandling { get; set; }
                }
            }
            """;

        const string source = """
            using Newtonsoft.Json;

            public class Test
            {
                public JsonSerializerSettings Create()
                {
                    var settings = new JsonSerializerSettings();
                    settings.TypeNameHandling = TypeNameHandling.Auto;
                    return settings;
                }
            }
            """;

        var findings = await RunAnalysis<NewtonsoftTypeNameHandlingRule>(source, mockTypes);
        Assert.Single(findings);
    }

    [Fact]
    public async Task SMOL0013_Negative1_TypeNameHandling_None_NotDetected()
    {
        const string mockTypes = """
            namespace Newtonsoft.Json
            {
                public enum TypeNameHandling
                {
                    None = 0,
                    Objects = 1,
                    Arrays = 2,
                    All = 3,
                    Auto = 4
                }

                public class JsonSerializerSettings
                {
                    public TypeNameHandling TypeNameHandling { get; set; }
                }
            }
            """;

        const string source = """
            using Newtonsoft.Json;

            public class Test
            {
                public JsonSerializerSettings Create()
                {
                    var settings = new JsonSerializerSettings();
                    settings.TypeNameHandling = TypeNameHandling.None;
                    return settings;
                }
            }
            """;

        var findings = await RunAnalysis<NewtonsoftTypeNameHandlingRule>(source, mockTypes);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0013_Negative2_UnrelatedProperty_NotDetected()
    {
        const string source = """
            public class MySettings
            {
                public int TypeNameHandling { get; set; }
            }

            public class Test
            {
                public void Configure(MySettings s)
                {
                    s.TypeNameHandling = 3;
                }
            }
            """;

        var findings = await RunAnalysis<NewtonsoftTypeNameHandlingRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0014 — System.Text.Json unsafe JsonConverter
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0014_Positive1_JsonConverter_With_Type_Parameter_Detected()
    {
        const string mockTypes = """
            namespace System.Text.Json
            {
                public class JsonSerializerOptions { }
                public class Utf8JsonReader { }

                public static class JsonSerializer
                {
                    public static object Deserialize(ref Utf8JsonReader reader, System.Type type, JsonSerializerOptions options) => null;
                    public static T Deserialize<T>(ref Utf8JsonReader reader, JsonSerializerOptions options) => default;
                }
            }

            namespace System.Text.Json.Serialization
            {
                public abstract class JsonConverter<T>
                {
                    public abstract T Read(ref System.Text.Json.Utf8JsonReader reader, System.Type typeToConvert, System.Text.Json.JsonSerializerOptions options);
                    public abstract void Write(object writer, T value, System.Text.Json.JsonSerializerOptions options);
                }
            }
            """;

        const string source = """
            using System;
            using System.Text.Json;
            using System.Text.Json.Serialization;

            public class UnsafeConverter : JsonConverter<object>
            {
                public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
                {
                    return JsonSerializer.Deserialize(ref reader, typeToConvert, options);
                }

                public override void Write(object writer, object value, JsonSerializerOptions options) { }
            }
            """;

        var findings = await RunAnalysis<UnsafeJsonConverterRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0014"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0014_Positive2_JsonConverter_With_TypeOf_Detected()
    {
        const string mockTypes = """
            namespace System.Text.Json
            {
                public class JsonSerializerOptions { }
                public class Utf8JsonReader { }

                public static class JsonSerializer
                {
                    public static object Deserialize(ref Utf8JsonReader reader, System.Type type, JsonSerializerOptions options) => null;
                    public static T Deserialize<T>(ref Utf8JsonReader reader, JsonSerializerOptions options) => default;
                }
            }

            namespace System.Text.Json.Serialization
            {
                public abstract class JsonConverter<T>
                {
                    public abstract T Read(ref System.Text.Json.Utf8JsonReader reader, System.Type typeToConvert, System.Text.Json.JsonSerializerOptions options);
                    public abstract void Write(object writer, T value, System.Text.Json.JsonSerializerOptions options);
                }
            }
            """;

        const string source = """
            using System;
            using System.Text.Json;
            using System.Text.Json.Serialization;

            public class UnsafeConverter2 : JsonConverter<object>
            {
                public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
                {
                    var type = typeof(object);
                    return JsonSerializer.Deserialize(ref reader, type, options);
                }

                public override void Write(object writer, object value, JsonSerializerOptions options) { }
            }
            """;

        var findings = await RunAnalysis<UnsafeJsonConverterRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0014_Negative1_GenericDeserialize_NotDetected()
    {
        const string source = """
            using System.Text.Json;

            public class Test
            {
                public string Read(string json) => JsonSerializer.Deserialize<string>(json);
            }
            """;

        var findings = await RunAnalysis<UnsafeJsonConverterRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0014_Negative2_NotInJsonConverter_NotDetected()
    {
        const string mockTypes = """
            namespace System.Text.Json
            {
                public class JsonSerializerOptions { }

                public static class JsonSerializer
                {
                    public static object Deserialize(string json, System.Type type) => null;
                }
            }
            """;

        const string source = """
            using System;
            using System.Text.Json;

            public class RegularClass
            {
                public object Read(string json, Type type)
                {
                    return JsonSerializer.Deserialize(json, type);
                }
            }
            """;

        var findings = await RunAnalysis<UnsafeJsonConverterRule>(source, mockTypes);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0015 — YamlDotNet untyped deserialization
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0015_Positive1_Deserialize_Object_Detected()
    {
        const string mockTypes = """
            namespace YamlDotNet.Serialization
            {
                public class Deserializer
                {
                    public T Deserialize<T>(string yaml) => default;
                }
            }
            """;

        const string source = """
            using YamlDotNet.Serialization;

            public class Test
            {
                public object Read(string yaml)
                {
                    var deserializer = new Deserializer();
                    return deserializer.Deserialize<object>(yaml);
                }
            }
            """;

        var findings = await RunAnalysis<YamlDotNetUntypedDeserializationRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0015"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0015_Positive2_Deserialize_NonGeneric_Detected()
    {
        const string mockTypes = """
            namespace YamlDotNet.Serialization
            {
                public class Deserializer
                {
                    public object Deserialize(string yaml) => null;
                }
            }
            """;

        const string source = """
            using YamlDotNet.Serialization;

            public class Test
            {
                public object Read(string yaml)
                {
                    var deserializer = new Deserializer();
                    return deserializer.Deserialize(yaml);
                }
            }
            """;

        var findings = await RunAnalysis<YamlDotNetUntypedDeserializationRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0015_Negative1_Typed_Deserialize_NotDetected()
    {
        const string mockTypes = """
            namespace YamlDotNet.Serialization
            {
                public class Deserializer
                {
                    public T Deserialize<T>(string yaml) => default;
                }
            }
            """;

        const string source = """
            using YamlDotNet.Serialization;

            public class MyConfig
            {
                public string Name { get; set; }
            }

            public class Test
            {
                public MyConfig Read(string yaml)
                {
                    var deserializer = new Deserializer();
                    return deserializer.Deserialize<MyConfig>(yaml);
                }
            }
            """;

        var findings = await RunAnalysis<YamlDotNetUntypedDeserializationRule>(source, mockTypes);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0015_Negative2_UnrelatedDeserialize_NotDetected()
    {
        const string source = """
            using System.Text.Json;

            public class Test
            {
                public string Read(string json) => JsonSerializer.Deserialize<string>(json);
            }
            """;

        var findings = await RunAnalysis<YamlDotNetUntypedDeserializationRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // SMOL0016 — DataContractSerializer with dynamic KnownTypes
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0016_Positive1_Variable_KnownTypes_Detected()
    {
        const string mockTypes = """
            namespace System.Runtime.Serialization
            {
                public class DataContractSerializer
                {
                    public DataContractSerializer(System.Type type) { }
                    public DataContractSerializer(System.Type type, System.Collections.Generic.IEnumerable<System.Type> knownTypes) { }
                }
            }
            """;

        const string source = """
            using System;
            using System.Collections.Generic;
            using System.Runtime.Serialization;

            public class Test
            {
                public DataContractSerializer Create(IEnumerable<Type> types)
                {
                    return new DataContractSerializer(typeof(object), types);
                }
            }
            """;

        var findings = await RunAnalysis<DataContractSerializerDynamicKnownTypesRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0016"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0016_Positive2_MethodCall_KnownTypes_Detected()
    {
        const string mockTypes = """
            namespace System.Runtime.Serialization
            {
                public class DataContractSerializer
                {
                    public DataContractSerializer(System.Type type) { }
                    public DataContractSerializer(System.Type type, System.Collections.Generic.IEnumerable<System.Type> knownTypes) { }
                }
            }
            """;

        const string source = """
            using System;
            using System.Collections.Generic;
            using System.Runtime.Serialization;

            public class Test
            {
                public DataContractSerializer Create()
                {
                    return new DataContractSerializer(typeof(object), GetTypes());
                }

                private IEnumerable<Type> GetTypes() => new[] { typeof(string) };
            }
            """;

        var findings = await RunAnalysis<DataContractSerializerDynamicKnownTypesRule>(source, mockTypes);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0016_Negative1_Static_KnownTypes_NotDetected()
    {
        const string mockTypes = """
            namespace System.Runtime.Serialization
            {
                public class DataContractSerializer
                {
                    public DataContractSerializer(System.Type type) { }
                    public DataContractSerializer(System.Type type, System.Collections.Generic.IEnumerable<System.Type> knownTypes) { }
                }
            }
            """;

        const string source = """
            using System;
            using System.Runtime.Serialization;

            public class Test
            {
                public DataContractSerializer Create()
                {
                    return new DataContractSerializer(typeof(object), new[] { typeof(string), typeof(int) });
                }
            }
            """;

        var findings = await RunAnalysis<DataContractSerializerDynamicKnownTypesRule>(source, mockTypes);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0016_Negative2_SingleArg_NotDetected()
    {
        const string mockTypes = """
            namespace System.Runtime.Serialization
            {
                public class DataContractSerializer
                {
                    public DataContractSerializer(System.Type type) { }
                }
            }
            """;

        const string source = """
            using System;
            using System.Runtime.Serialization;

            public class Test
            {
                public DataContractSerializer Create()
                {
                    return new DataContractSerializer(typeof(string));
                }
            }
            """;

        var findings = await RunAnalysis<DataContractSerializerDynamicKnownTypesRule>(source, mockTypes);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════
    // Rule metadata tests
    // ═══════════════════════════════════════════════════════

    [Theory]
    [InlineData(typeof(NetDataContractSerializerSoapFormatterRule), "SMOL0010", 502, "A08:2021")]
    [InlineData(typeof(LosFormatterObjectStateFormatterRule), "SMOL0011", 502, "A08:2021")]
    [InlineData(typeof(ViewStateMacDisabledRule), "SMOL0012", 642, "A08:2021")]
    [InlineData(typeof(NewtonsoftTypeNameHandlingRule), "SMOL0013", 502, "A08:2021")]
    [InlineData(typeof(UnsafeJsonConverterRule), "SMOL0014", 502, "A08:2021")]
    [InlineData(typeof(YamlDotNetUntypedDeserializationRule), "SMOL0015", 502, "A08:2021")]
    [InlineData(typeof(DataContractSerializerDynamicKnownTypesRule), "SMOL0016", 502, "A08:2021")]
    public void RuleMetadata_IsCorrect(Type ruleType, string expectedId, int expectedCwe, string expectedOwasp)
    {
        var rule = (SmolerRule)Activator.CreateInstance(ruleType)!;

        Assert.Equal(new RuleId(expectedId), rule.Id);
        Assert.Contains(expectedCwe, rule.CweIds);
        Assert.Equal(expectedOwasp, rule.OwaspCategory);
        Assert.False(string.IsNullOrEmpty(rule.DescriptionPtBr));
        Assert.False(string.IsNullOrEmpty(rule.DescriptionEnUs));
        Assert.False(string.IsNullOrEmpty(rule.RemediationGuidancePtBr));
        Assert.Contains("deserialization", rule.Tags);
    }

    // ═══════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════

    private static async Task<ImmutableArray<Finding>> RunAnalysis<TRule>(string source, string? mockTypes = null)
        where TRule : SmolerRule, new()
    {
        var sources = mockTypes is not null
            ? ImmutableArray.Create(mockTypes, source)
            : ImmutableArray.Create(source);

        var acquirer = new InMemoryCompilationAcquirer(sources, References);
        var registry = new DefaultRuleRegistry();
        registry.Register(new TRule());

        var symbolIndex = new InMemorySymbolIndex();
        var pipeline = new AnalysisPipeline(acquirer, registry, symbolIndex);
        var options = new AnalysisPipelineOptions("test");

        var result = await pipeline.RunAsync(options);
        return result.Findings;
    }
}
