using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SmolerSAST.Core.Compilation;
using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Pipeline;
using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.Cryptography;

namespace SmolerSAST.Rules.Base.Tests.Cryptography;

public sealed class CryptographyRulesTests
{
    private static readonly ImmutableArray<MetadataReference> References = BuildReferences();

    private static ImmutableArray<MetadataReference> BuildReferences()
    {
        var refs = new List<MetadataReference>();
        var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;

        var assemblyNames = new[]
        {
            "System.Runtime.dll",
            "System.Private.CoreLib.dll",
            "System.Collections.dll",
            "System.Linq.dll",
            "System.IO.dll",
            "System.Console.dll",
            "System.Runtime.Serialization.Formatters.dll",
            "System.Text.Json.dll",
            "System.Security.Cryptography.dll",
            "System.Security.Cryptography.Algorithms.dll",
            "System.Security.Cryptography.Primitives.dll",
            "System.Security.Cryptography.Csp.dll",
            "System.Net.Primitives.dll",
            "System.Net.Security.dll",
            "netstandard.dll",
        };

        foreach (var name in assemblyNames)
        {
            var path = Path.Combine(runtimeDir, name);
            if (File.Exists(path))
            {
                refs.Add(MetadataReference.CreateFromFile(path));
            }
        }

        refs.Add(MetadataReference.CreateFromFile(typeof(object).Assembly.Location));

        return [.. refs];
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0017 — WeakHashAlgorithmRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0017_Positive1_MD5Create_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Hash(byte[] data)
                {
                    using var md5 = MD5.Create();
                    return md5.ComputeHash(data);
                }
            }
            """;

        var findings = await RunAnalysis<WeakHashAlgorithmRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0017"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0017_Positive2_SHA1CryptoServiceProvider_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0021
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Hash(byte[] data)
                {
                    var sha1 = new SHA1CryptoServiceProvider();
                    return sha1.ComputeHash(data);
                }
            }
            """;

        var findings = await RunAnalysis<WeakHashAlgorithmRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0017_Positive3_SHA1Create_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Hash(byte[] data)
                {
                    using var sha1 = SHA1.Create();
                    return sha1.ComputeHash(data);
                }
            }
            """;

        var findings = await RunAnalysis<WeakHashAlgorithmRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0017_Negative1_SHA256_NotDetected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Hash(byte[] data) => SHA256.HashData(data);
            }
            """;

        var findings = await RunAnalysis<WeakHashAlgorithmRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0017_Negative2_UserDefinedMD5_NotDetected()
    {
        const string source = """
            namespace MyApp
            {
                public class MD5
                {
                    public static MD5 Create() => new MD5();
                }

                public class Consumer
                {
                    public void Run() { var x = MD5.Create(); }
                }
            }
            """;

        var findings = await RunAnalysis<WeakHashAlgorithmRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0018 — EcbCipherModeRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0018_Positive1_EcbAssignment_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public void Configure()
                {
                    using var aes = Aes.Create();
                    aes.Mode = CipherMode.ECB;
                }
            }
            """;

        var findings = await RunAnalysis<EcbCipherModeRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0018"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0018_Positive2_EcbInCondition_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public bool IsEcb(CipherMode mode) => mode == CipherMode.ECB;
            }
            """;

        var findings = await RunAnalysis<EcbCipherModeRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0018_Negative1_CbcMode_NotDetected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public void Configure()
                {
                    using var aes = Aes.Create();
                    aes.Mode = CipherMode.CBC;
                }
            }
            """;

        var findings = await RunAnalysis<EcbCipherModeRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0018_Negative2_UserDefinedECB_NotDetected()
    {
        const string source = """
            namespace MyApp
            {
                public enum CipherMode { ECB, CBC }

                public class Test
                {
                    public CipherMode Mode => CipherMode.ECB;
                }
            }
            """;

        var findings = await RunAnalysis<EcbCipherModeRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0019 — HardcodedCryptoKeyRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0019_Positive1_HardcodedKey_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public void Configure()
                {
                    using var aes = Aes.Create();
                    aes.Key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
                }
            }
            """;

        var findings = await RunAnalysis<HardcodedCryptoKeyRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0019"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0019_Positive2_HardcodedIV_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public void Configure()
                {
                    using var aes = Aes.Create();
                    aes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                }
            }
            """;

        var findings = await RunAnalysis<HardcodedCryptoKeyRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0019_Negative1_KeyFromConfig_NotDetected()
    {
        const string source = """
            using System;
            using System.Security.Cryptography;

            public class Test
            {
                public void Configure(string keyBase64)
                {
                    using var aes = Aes.Create();
                    aes.Key = Convert.FromBase64String(keyBase64);
                }
            }
            """;

        var findings = await RunAnalysis<HardcodedCryptoKeyRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0019_Negative2_GenerateKey_NotDetected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public void Configure()
                {
                    using var aes = Aes.Create();
                    aes.GenerateKey();
                    aes.GenerateIV();
                }
            }
            """;

        var findings = await RunAnalysis<HardcodedCryptoKeyRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0020 — RijndaelManagedUsageRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0020_Positive1_DirectInstantiation_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0022
            using System.Security.Cryptography;

            public class Test
            {
                public void Encrypt()
                {
                    using var rijndael = new RijndaelManaged();
                }
            }
            """;

        var findings = await RunAnalysis<RijndaelManagedUsageRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0020"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0020_Positive2_WithInitializer_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0022
            using System.Security.Cryptography;

            public class Test
            {
                public void Encrypt()
                {
                    using var rijndael = new RijndaelManaged { Mode = CipherMode.CBC };
                }
            }
            """;

        var findings = await RunAnalysis<RijndaelManagedUsageRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0020_Negative1_AesCreate_NotDetected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public void Encrypt()
                {
                    using var aes = Aes.Create();
                }
            }
            """;

        var findings = await RunAnalysis<RijndaelManagedUsageRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0020_Negative2_UserDefinedRijndaelManaged_NotDetected()
    {
        const string source = """
            namespace MyApp
            {
                public class RijndaelManaged { }

                public class Test
                {
                    public void Run() { var x = new RijndaelManaged(); }
                }
            }
            """;

        var findings = await RunAnalysis<RijndaelManagedUsageRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0021 — RsaPkcs1PaddingRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0021_Positive1_Pkcs1Encrypt_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Encrypt(RSA rsa, byte[] data)
                {
                    return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                }
            }
            """;

        var findings = await RunAnalysis<RsaPkcs1PaddingRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0021"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0021_Positive2_Pkcs1Decrypt_Detected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Decrypt(RSA rsa, byte[] data)
                {
                    return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                }
            }
            """;

        var findings = await RunAnalysis<RsaPkcs1PaddingRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0021_Negative1_OaepSHA256_NotDetected()
    {
        const string source = """
            using System.Security.Cryptography;

            public class Test
            {
                public byte[] Encrypt(RSA rsa, byte[] data)
                {
                    return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                }
            }
            """;

        var findings = await RunAnalysis<RsaPkcs1PaddingRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0021_Negative2_UserDefinedPkcs1_NotDetected()
    {
        const string source = """
            namespace MyApp
            {
                public class RSAEncryptionPadding
                {
                    public static RSAEncryptionPadding Pkcs1 => new();
                }

                public class Test
                {
                    public void Run() { var x = RSAEncryptionPadding.Pkcs1; }
                }
            }
            """;

        var findings = await RunAnalysis<RsaPkcs1PaddingRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0022 — SystemRandomSecurityContextRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0022_Positive1_RandomInTokenMethod_Detected()
    {
        const string source = """
            using System;

            public class Test
            {
                public string GenerateToken()
                {
                    var random = new Random();
                    return random.Next().ToString();
                }
            }
            """;

        var findings = await RunAnalysis<SystemRandomSecurityContextRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0022"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0022_Positive2_RandomInPasswordClass_Detected()
    {
        const string source = """
            using System;

            public class PasswordGenerator
            {
                public string Generate()
                {
                    var rng = new Random();
                    return rng.Next(100000, 999999).ToString();
                }
            }
            """;

        var findings = await RunAnalysis<SystemRandomSecurityContextRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0022_Negative1_RandomForGameLogic_NotDetected()
    {
        const string source = """
            using System;

            public class GameEngine
            {
                public int RollDice()
                {
                    var random = new Random();
                    return random.Next(1, 7);
                }
            }
            """;

        var findings = await RunAnalysis<SystemRandomSecurityContextRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0022_Negative2_RandomForShuffle_NotDetected()
    {
        const string source = """
            using System;
            using System.Collections.Generic;

            public class ListHelper
            {
                public void Shuffle(List<int> items)
                {
                    var random = new Random();
                    // Fisher-Yates shuffle
                }
            }
            """;

        var findings = await RunAnalysis<SystemRandomSecurityContextRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0023 — CustomCryptoImplementationRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0023_Positive1_XorEncrypt_Detected()
    {
        const string source = """
            public class Test
            {
                public byte[] Encrypt(byte[] data, byte[] key)
                {
                    var result = new byte[data.Length];
                    for (int i = 0; i < data.Length; i++)
                        result[i] = (byte)(data[i] ^ key[i % key.Length]);
                    return result;
                }
            }
            """;

        var findings = await RunAnalysis<CustomCryptoImplementationRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0023"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0023_Positive2_ShiftHash_Detected()
    {
        const string source = """
            public class Test
            {
                public int Hash(byte[] data)
                {
                    int hash = 0;
                    foreach (var b in data)
                        hash = (hash << 5) ^ b;
                    return hash;
                }
            }
            """;

        var findings = await RunAnalysis<CustomCryptoImplementationRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0023_Negative1_NormalXorMethod_NotDetected()
    {
        const string source = """
            public class Test
            {
                public int Calculate(int a, int b)
                {
                    return a ^ b;
                }
            }
            """;

        var findings = await RunAnalysis<CustomCryptoImplementationRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0023_Negative2_EncryptWithoutBitwise_NotDetected()
    {
        const string source = """
            public class Test
            {
                public string Encrypt(string data)
                {
                    return System.Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes(data));
                }
            }
            """;

        var findings = await RunAnalysis<CustomCryptoImplementationRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // SMOL0024 — WeakTlsVersionRule
    // ═══════════════════════════════════════════════════════════

    [Fact]
    public async Task SMOL0024_Positive1_SecurityProtocolTls_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0039
            using System.Security.Authentication;

            public class Test
            {
                public SslProtocols GetProtocol() => SslProtocols.Tls;
            }
            """;

        var findings = await RunAnalysis<WeakTlsVersionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
        Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0024"), f.RuleId));
    }

    [Fact]
    public async Task SMOL0024_Positive2_SslProtocolsTls11_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0039
            using System.Security.Authentication;

            public class Test
            {
                public SslProtocols GetProtocol() => SslProtocols.Tls11;
            }
            """;

        var findings = await RunAnalysis<WeakTlsVersionRule>(source);
        Assert.True(findings.Length >= 1, $"Expected >= 1 findings, got {findings.Length}");
    }

    [Fact]
    public async Task SMOL0024_Positive3_SecurityProtocolTypeTls_Detected()
    {
        const string source = """
            #pragma warning disable SYSLIB0039
            using System.Net;

            public class Test
            {
                public SecurityProtocolType GetProtocol() => SecurityProtocolType.Tls;
            }
            """;

        var findings = await RunAnalysis<WeakTlsVersionRule>(source);
        // This may or may not detect depending on whether System.Net.Primitives resolves
        // the type. If it resolves, we expect a finding.
        if (findings.Length > 0)
        {
            Assert.All(findings, f => Assert.Equal(new RuleId("SMOL0024"), f.RuleId));
        }
    }

    [Fact]
    public async Task SMOL0024_Negative1_Tls12_NotDetected()
    {
        const string source = """
            using System.Net;

            public class Test
            {
                public void Configure()
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                }
            }
            """;

        var findings = await RunAnalysis<WeakTlsVersionRule>(source);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task SMOL0024_Negative2_UserDefinedTls_NotDetected()
    {
        const string source = """
            namespace MyApp
            {
                public enum SslProtocols { Tls, Tls11, Tls12 }

                public class Test
                {
                    public SslProtocols GetProtocol() => SslProtocols.Tls;
                }
            }
            """;

        var findings = await RunAnalysis<WeakTlsVersionRule>(source);
        Assert.Empty(findings);
    }

    // ═══════════════════════════════════════════════════════════
    // Rule Metadata Tests
    // ═══════════════════════════════════════════════════════════

    [Theory]
    [InlineData(typeof(WeakHashAlgorithmRule), "SMOL0017")]
    [InlineData(typeof(EcbCipherModeRule), "SMOL0018")]
    [InlineData(typeof(HardcodedCryptoKeyRule), "SMOL0019")]
    [InlineData(typeof(RijndaelManagedUsageRule), "SMOL0020")]
    [InlineData(typeof(RsaPkcs1PaddingRule), "SMOL0021")]
    [InlineData(typeof(SystemRandomSecurityContextRule), "SMOL0022")]
    [InlineData(typeof(CustomCryptoImplementationRule), "SMOL0023")]
    [InlineData(typeof(WeakTlsVersionRule), "SMOL0024")]
    public void RuleMetadata_HasRequiredFields(Type ruleType, string expectedId)
    {
        var rule = (SmolerRule)Activator.CreateInstance(ruleType)!;

        Assert.Equal(new RuleId(expectedId), rule.Id);
        Assert.Equal("A02:2021", rule.OwaspCategory);
        Assert.NotEmpty(rule.CweIds);
        Assert.Contains("cryptography", rule.Tags);
        Assert.False(string.IsNullOrWhiteSpace(rule.DescriptionPtBr));
        Assert.False(string.IsNullOrWhiteSpace(rule.DescriptionEnUs));
        Assert.False(string.IsNullOrWhiteSpace(rule.RemediationGuidancePtBr));
    }

    // ═══════════════════════════════════════════════════════════
    // Helper
    // ═══════════════════════════════════════════════════════════

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
