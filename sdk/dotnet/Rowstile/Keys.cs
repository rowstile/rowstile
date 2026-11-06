using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Rowstile;

/// <summary>A row's key as Postgres writes it, which <c>authz.explain_rule</c> reads back and messages show.</summary>
internal static class Keys
{
    /// <summary>
    /// <c>7</c>; or <c>(1,2)</c> for a key of several columns, given as a tuple (<c>(1, 2)</c>), an array of its
    /// values (<c>long[]</c> too) or a list, in the key's order. A field is quoted only where Postgres would: when it is
    /// empty or holds a comma, a quote, a parenthesis, a backslash or one of ASCII's six spaces, and for no other
    /// character. A key of one value is that value.
    /// </summary>
    public static string? Text(object? key)
    {
        object?[]? fields = key switch
        {
            ITuple tuple => [.. Enumerable.Range(0, tuple.Length).Select(i => tuple[i])],
            IList values => [.. values.Cast<object?>()],
            _ => null,
        };
        if (fields is null)
        {
            return Value(key);
        }
        if (fields.Length == 1)
        {
            return Value(fields[0]);
        }
        return "(" + string.Join(',', fields.Select(Field)) + ")";
    }

    private static string? Value(object? value) => value is null ? null : Convert.ToString(value, CultureInfo.InvariantCulture);

    private static string Field(object? value)
    {
        string text = Value(value) ?? "";
        if (value is not null && (text.Length == 0 || text.Any(c => "\",\\() \t\n\r\v\f".Contains(c, StringComparison.Ordinal))))
        {
            return "\"" + text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        }
        return text;
    }
}
