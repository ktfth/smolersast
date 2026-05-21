using System;
using System.Data.SqlClient;

namespace BankingApp.Api;

/// <summary>
/// Controller de transferências — demonstra SQL injection via taint analysis.
/// O input do usuário flui do parâmetro [FromQuery] até SqlCommand.ExecuteNonQuery.
/// </summary>
public class TransferController
{
    // VULN: SQL Injection via taint — input do usuário concatenado em SQL
    // Taint path: destinatario (FromQuery) → sql (concatenation) → cmd.CommandText → ExecuteNonQuery
    public void SearchRecipient([FromQuery] string destinatario)
    {
        var sql = "SELECT * FROM Accounts WHERE HolderName = '" + destinatario + "'";
        var cmd = new SqlCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    // VULN: SQL Injection via interpolação
    // Taint path: accountId (FromRoute) → interpolated string → cmd.CommandText → ExecuteReader
    public void GetStatement([FromRoute] string accountId)
    {
        var cmd = new SqlCommand();
        cmd.CommandText = $"SELECT * FROM Transactions WHERE AccountId = '{accountId}' ORDER BY Date DESC";
        cmd.ExecuteReader();
    }

    // SAFE: Query parametrizada — taint é neutralizado pelo sanitizer AddWithValue
    public void GetBalance([FromQuery] string cpf)
    {
        var cmd = new SqlCommand("SELECT Balance FROM Accounts WHERE Cpf = @cpf");
        cmd.Parameters.AddWithValue("@cpf", cpf);
        cmd.ExecuteScalar();
    }
}

public class FromQueryAttribute : Attribute { }
public class FromRouteAttribute : Attribute { }
