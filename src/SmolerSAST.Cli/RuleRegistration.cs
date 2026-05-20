using SmolerSAST.Core.Rules;
using SmolerSAST.Rules.Base.AspNet;
using SmolerSAST.Rules.Base.Configuration;
using SmolerSAST.Rules.Base.Cryptography;
using SmolerSAST.Rules.Base.Deserialization;
using SmolerSAST.Rules.Base.Injection;
using SmolerSAST.Rules.BR.Bacen;
using SmolerSAST.Rules.BR.Cvm;
using SmolerSAST.Rules.BR.Lgpd;
using SmolerSAST.Rules.BR.Pci;

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
        registry.Register(new PiiInExceptionMessageRule());
        registry.Register(new PiiInCacheWithoutEncryptionRule());
        registry.Register(new PiiInCookieWithoutEncryptionRule());
        registry.Register(new PiiWithoutPersonalDataAnnotationRule());

        // Brazil — Bacen (SMOL1007-1016)
        registry.Register(new JwtValidationIncompleteRule());
        registry.Register(new HsmNotUsedForSigningRule());
        registry.Register(new MutualTlsNotEnforcedRule());
        registry.Register(new AuditLogWithoutTamperProtectionRule());
        registry.Register(new OAuthWithoutPkceRule());
        registry.Register(new PixKeyExposureRule());
        registry.Register(new SessionTimeoutExcessiveRule());
        registry.Register(new FinancialOperationWithoutIdempotencyRule());

        // Brazil — PCI-DSS (SMOL1017-1021)
        registry.Register(new PanInLogRule());
        registry.Register(new CvvStorageRule());
        registry.Register(new WeakCryptoForCardDataRule());
        registry.Register(new CardDataWithoutTlsRule());
        registry.Register(new AdminWithoutMfaRule());

        // Brazil — CVM (SMOL1012-1024)
        registry.Register(new PrivilegedActionWithoutDualControlRule());
        registry.Register(new MarketOperationWithoutAuditTrailRule());
        registry.Register(new DataIntegrityWithoutValidationRule());
        registry.Register(new RegulatoryReportWithoutDigitalSignatureRule());

        return registry;
    }
}
