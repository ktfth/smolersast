namespace SmolerSAST.Core.Rules;

/// <summary>
/// Identifies a SmolerSAST rule. Format: SMOL followed by exactly 4 digits (e.g., SMOL0009).
/// </summary>
public readonly record struct RuleId : IComparable<RuleId>
{
    /// <summary>
    /// Gets the string representation of the rule ID.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Creates a new <see cref="RuleId"/> after validating the format.
    /// </summary>
    /// <param name="value">The rule ID string in format SMOLnnnn.</param>
    /// <exception cref="ArgumentException">Thrown when value does not match SMOLnnnn format.</exception>
    public RuleId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (!IsValidFormat(value))
        {
            throw new ArgumentException(
                $"Rule ID must match format SMOLnnnn (e.g., SMOL0009). Got: '{value}'",
                nameof(value));
        }

        Value = value;
    }

    /// <summary>
    /// Compares this rule ID with another for ordering.
    /// </summary>
    public int CompareTo(RuleId other) => string.Compare(Value, other.Value, StringComparison.Ordinal);

    /// <summary>Less than operator.</summary>
    public static bool operator <(RuleId left, RuleId right) => left.CompareTo(right) < 0;

    /// <summary>Less than or equal operator.</summary>
    public static bool operator <=(RuleId left, RuleId right) => left.CompareTo(right) <= 0;

    /// <summary>Greater than operator.</summary>
    public static bool operator >(RuleId left, RuleId right) => left.CompareTo(right) > 0;

    /// <summary>Greater than or equal operator.</summary>
    public static bool operator >=(RuleId left, RuleId right) => left.CompareTo(right) >= 0;

    /// <inheritdoc />
    public override string ToString() => Value;

    private static bool IsValidFormat(ReadOnlySpan<char> value)
    {
        if (value.Length != 8)
        {
            return false;
        }

        if (value[0] != 'S' || value[1] != 'M' || value[2] != 'O' || value[3] != 'L')
        {
            return false;
        }

        for (var i = 4; i < 8; i++)
        {
            if (!char.IsAsciiDigit(value[i]))
            {
                return false;
            }
        }

        return true;
    }
}
