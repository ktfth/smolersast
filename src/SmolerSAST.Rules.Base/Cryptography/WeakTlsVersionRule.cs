using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SmolerSAST.Core.Rules;

namespace SmolerSAST.Rules.Base.Cryptography;

/// <summary>
/// SMOL0024: Detects explicit selection of TLS 1.0 or TLS 1.1.
/// Both versions have known vulnerabilities and are deprecated — CWE-327.
/// </summary>
public sealed class WeakTlsVersionRule : SmolerRule
{
    private static readonly ImmutableHashSet<string> WeakProtocolContainerTypes = ImmutableHashSet.Create(
        StringComparer.Ordinal,
        "System.Security.Authentication.SslProtocols",
        "System.Net.SecurityProtocolType");

    private static readonly ImmutableHashSet<string> WeakProtocolNames = ImmutableHashSet.Create(
        StringComparer.Ordinal,
        "Tls", "Tls11", "Ssl2", "Ssl3");

    /// <inheritdoc />
    public override RuleId Id { get; } = new("SMOL0024");

    /// <inheritdoc />
    public override ImmutableArray<int> CweIds { get; } = [327];

    /// <inheritdoc />
    public override string OwaspCategory => "A02:2021";

    /// <inheritdoc />
    public override RuleSeverity Severity => RuleSeverity.High;

    /// <inheritdoc />
    public override RulePrecision Precision => RulePrecision.High;

    /// <inheritdoc />
    public override ImmutableArray<string> Tags { get; } = ["cryptography", "weak-tls"];

    /// <inheritdoc />
    public override string DescriptionPtBr =>
        "Uso de versão TLS fraca (TLS 1.0/1.1) detectado. " +
        "TLS 1.0 e 1.1 possuem vulnerabilidades conhecidas e estão obsoletos.";

    /// <inheritdoc />
    public override string DescriptionEnUs =>
        "Weak TLS version (TLS 1.0/1.1) usage detected. " +
        "TLS 1.0 and 1.1 have known vulnerabilities and are deprecated.";

    /// <inheritdoc />
    public override string RemediationGuidancePtBr =>
        """
        Use TLS 1.2 como mínimo, preferencialmente TLS 1.3.

        ```csharp
        // ANTES (inseguro):
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

        // DEPOIS (seguro):
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
        // Ou deixe o sistema escolher a melhor versão (padrão no .NET 6+).
        ```

        Referência: https://learn.microsoft.com/dotnet/framework/network-programming/tls
        """;

    /// <inheritdoc />
    public override void RegisterActions(AnalysisContext context)
    {
        context.RegisterSyntaxNodeAction(
            AnalyzeMemberAccess,
            SyntaxKind.SimpleMemberAccessExpression);
    }

    private void AnalyzeMemberAccess(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        var memberName = memberAccess.Name.Identifier.Text;
        if (!WeakProtocolNames.Contains(memberName))
        {
            return;
        }

        var symbolInfo = context.SemanticModel.GetSymbolInfo(memberAccess);
        if (symbolInfo.Symbol is not IFieldSymbol fieldSymbol)
        {
            return;
        }

        var containingTypeName = fieldSymbol.ContainingType?.ToDisplayString();
        if (containingTypeName is null || !WeakProtocolContainerTypes.Contains(containingTypeName))
        {
            return;
        }

        var location = context.Node.GetLocation();
        var lineSpan = location.GetLineSpan();

        var finding = new Finding(
            RuleId: Id,
            Severity: Severity,
            Precision: Precision,
            MessagePtBr: $"Uso de protocolo TLS fraco ({memberName}) detectado.",
            MessageEnUs: $"Weak TLS protocol ({memberName}) usage detected.",
            Location: new FindingLocation(
                FilePath: lineSpan.Path ?? "Unknown",
                StartLine: lineSpan.StartLinePosition.Line + 1,
                StartColumn: lineSpan.StartLinePosition.Character,
                EndLine: lineSpan.EndLinePosition.Line + 1,
                EndColumn: lineSpan.EndLinePosition.Character,
                CodeExcerpt: context.Node.ToString()),
            AdditionalLocations: [],
            CweIds: CweIds,
            OwaspCategory: OwaspCategory,
            Tags: Tags,
            Confidence: 1.0);

        context.ReportFinding(finding);
    }
}
