using System;

namespace BankingApp.Compliance;

/// <summary>
/// Demonstra violações regulatórias brasileiras que nenhuma ferramenta comercial detecta.
/// Cada método viola uma regulação específica (LGPD, Bacen, PCI-DSS, CVM).
/// </summary>
public class ComplianceViolations
{
    // ─── LGPD ─────────────────────────────────────────────

    // VULN SMOL1001: PII em log — LGPD Art. 46
    public void LogClientAccess(ILogger logger, string cpf, string action)
    {
        logger.LogInformation("Cliente {Cpf} executou ação: {Action}", cpf, action);
    }

    // VULN SMOL1003: PII em exception — LGPD Art. 46
    public void ValidateClient(string email)
    {
        throw new ArgumentException($"Email inválido: {email}");
    }

    // ─── BACEN ────────────────────────────────────────────

    // VULN SMOL1007: JWT sem validação completa — Bacen Res. 4.658 / FAPI 1.0
    public void ConfigureAuth(TokenValidationParameters parameters)
    {
        parameters.ValidateAudience = false;
        parameters.ValidateIssuer = false;
        parameters.ValidateLifetime = false;
    }

    // VULN SMOL1014: Chave PIX em log — Bacen Res. 1/2020
    public void ProcessPix(ILogger logger, string pixKey, decimal amount)
    {
        logger.LogInformation("PIX enviado: {PixKey} valor {Amount}", pixKey, amount);
    }

    // VULN SMOL1015: Session timeout > 15min — Bacen Res. 4.658
    public void ConfigureSession(SessionOptions options)
    {
        options.IdleTimeout = TimeSpan.FromMinutes(60);
    }

    // VULN SMOL1013: OAuth sem PKCE — Open Finance Brasil FAPI 1.0
    public void ConfigureOidc(OpenIdConnectOptions options)
    {
        options.UsePkce = false;
    }

    // ─── PCI-DSS ──────────────────────────────────────────

    // VULN SMOL1017: PAN em log sem mascaramento — PCI-DSS Req. 3.4
    public void LogPayment(ILogger logger, string cardNumber, decimal amount)
    {
        logger.LogInformation("Pagamento com cartão {CardNumber}: R${Amount}", cardNumber, amount);
    }

    // VULN SMOL1018: CVV em entity persistida — PCI-DSS Req. 3.2
    // (detectado via PropertyDeclaration analysis)

    // ─── CVM ──────────────────────────────────────────────

    // VULN SMOL1022: Operação de mercado sem trilha de auditoria — CVM Res. 35
    public void PlaceOrder(string symbol, int quantity, decimal price)
    {
        // executa ordem sem registrar audit trail
        var filled = quantity > 0;
    }
}

// Stubs para compilação
public interface ILogger
{
    void LogInformation(string message, params object[] args);
}

public class TokenValidationParameters
{
    public bool ValidateAudience { get; set; }
    public bool ValidateIssuer { get; set; }
    public bool ValidateLifetime { get; set; }
}

public class SessionOptions
{
    public TimeSpan IdleTimeout { get; set; }
}

public class OpenIdConnectOptions
{
    public bool UsePkce { get; set; }
}

// VULN SMOL1018: CVV armazenado — PCI-DSS Req. 3.2
public class PaymentEntity
{
    public string CardNumber { get; set; } = "";
    public string Cvv { get; set; } = "";
    public decimal Amount { get; set; }
}
