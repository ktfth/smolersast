namespace SmolerSAST.Core.Taint;

/// <summary>
/// Identifies the type of taint a value carries.
/// </summary>
public enum TaintLabel
{
    /// <summary>User-controlled input (HttpRequest, form data, query params).</summary>
    UserInput,

    /// <summary>Data from external systems (database, file, API).</summary>
    ExternalData,

    /// <summary>Configuration values (IConfiguration, environment variables).</summary>
    Configuration,

    /// <summary>Personal identifiable information (CPF, email, nome).</summary>
    Pii,

    /// <summary>Financial data (card number, account number, PIX key).</summary>
    FinancialData,
}
