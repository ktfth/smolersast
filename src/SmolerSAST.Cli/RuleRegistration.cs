using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.AspNet;
using SmolerSAST.Rules.Base.Configuration;
using SmolerSAST.Rules.Base.Cryptography;
using SmolerSAST.Rules.Base.Deserialization;
using SmolerSAST.Rules.Base.Injection;
using SmolerSAST.Rules.BR.Bacen;
using SmolerSAST.Rules.BR.Cvm;
using SmolerSAST.Rules.BR.Lgpd;

namespace SmolerSAST.Cli;

/// <summary>
/// Registers all available rules into a <see cref="DefaultRuleRegistry"/>.
/// </summary>
internal static class RuleRegistration
{
    internal static DefaultRuleRegistry CreateRegistry()
    {
        var registry = new DefaultRuleRegistry();

        // Injection (SMOL0001-0008)
        registry.Register(new RawSqlConcatenationRule());
        registry.Register(new FormattableStringInvariantSqlRule());
        registry.Register(new LdapInjectionRule());
        registry.Register(new XPathInjectionRule());
        registry.Register(new CommandInjectionRule());
        registry.Register(new LinqToSqlInjectionRule());
        registry.Register(new NoSqlInjectionRule());
        registry.Register(new DapperSqlInjectionRule());

        // Deserialization (SMOL0009-0016)
        registry.Register(new BinaryFormatterUsageRule());
        registry.Register(new NetDataContractSerializerSoapFormatterRule());
        registry.Register(new LosFormatterObjectStateFormatterRule());
        registry.Register(new ViewStateMacDisabledRule());
        registry.Register(new NewtonsoftTypeNameHandlingRule());
        registry.Register(new UnsafeJsonConverterRule());
        registry.Register(new YamlDotNetUntypedDeserializationRule());
        registry.Register(new DataContractSerializerDynamicKnownTypesRule());

        // Cryptography (SMOL0017-0024)
        registry.Register(new WeakHashAlgorithmRule());
        registry.Register(new EcbCipherModeRule());
        registry.Register(new HardcodedCryptoKeyRule());
        registry.Register(new RijndaelManagedUsageRule());
        registry.Register(new RsaPkcs1PaddingRule());
        registry.Register(new SystemRandomSecurityContextRule());
        registry.Register(new CustomCryptoImplementationRule());
        registry.Register(new WeakTlsVersionRule());

        // ASP.NET (SMOL0025-0032)
        registry.Register(new AllowAnonymousSensitiveVerbRule());
        registry.Register(new MissingAntiforgeryRule());
        registry.Register(new ViewStateMacDisabledCodeRule());
        registry.Register(new DebugEnabledRule());
        registry.Register(new CustomErrorsOffRule());
        registry.Register(new InsecureCookieRule());
        registry.Register(new AuthenticationWithoutSchemeRule());
        registry.Register(new DistributedCacheWithoutEncryptionRule());

        // Configuration (SMOL0033-0040)
        registry.Register(new HardcodedSecretRule());
        registry.Register(new InsecureHttpClientRule());
        registry.Register(new DiLifetimeMismatchRule());
        registry.Register(new ReflectionDynamicInvocationRule());

        // Brazil — LGPD (SMOL1001-1006)
        registry.Register(new PiiInLogStatementsRule());
        registry.Register(new PiiInUrlQueryStringRule());
        registry.Register(new PiiWithoutPersonalDataAnnotationRule());

        // Brazil — Bacen (SMOL1007-1010)
        registry.Register(new JwtValidationIncompleteRule());
        registry.Register(new HsmNotUsedForSigningRule());

        // Brazil — CVM (SMOL1011-1012)
        registry.Register(new PrivilegedActionWithoutDualControlRule());

        return registry;
    }
}
