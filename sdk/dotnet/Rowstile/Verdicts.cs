using System;
using System.Collections.Generic;

namespace Rowstile;

/// <summary>A row an update or a delete changed nothing of: its table, the command, its key.</summary>
/// <param name="Table">The table, as the app names it (<c>app.notes</c>, or <c>notes</c> on the search_path).</param>
/// <param name="Command"><c>update</c> or <c>delete</c>.</param>
/// <param name="Key">The row's key: a value, or a tuple or an array of a key's columns (<see cref="Keys.Text"/>).</param>
public sealed record RowAsked(string Table, string Command, object? Key);

/// <summary>What <c>authz.explain_rule</c> answered for a row.</summary>
/// <param name="Lines">Its lines; null when the row isn't there for this user.</param>
/// <param name="Who">Who is signed in, in the words the database's own refusals use (<c>user 2</c>, <c>service 3</c>).</param>
/// <param name="Named">The table as the policy names it (<c>app.notes</c> for a model that says <c>notes</c>).</param>
public sealed record RowAnswer(IReadOnlyList<string>? Lines, string Who, string Named)
{
    /// <summary>Whether the rule allows the write: its first line says yes.</summary>
    public bool Allowed => Lines is [var first, ..] && first.TrimStart().StartsWith("yes", StringComparison.Ordinal);
}

/// <summary>What an update or a delete that changed nothing was, from the database's answer.</summary>
public static class Verdicts
{
    /// <summary>
    /// <see cref="NotFoundException"/> when the row isn't there for this user (<c>authz.explain_rule</c> answered
    /// null), or when the rule allows the write (the statement matched nothing for another reason, such as a WHERE with
    /// more than the key); <see cref="RefusedException"/>, with why, otherwise. Worded as the database words a refused
    /// insert: <c>permission denied: user 2 may not update row 7 of app.notes</c>.
    /// </summary>
    public static Exception Of(RowAsked row, RowAnswer answer)
    {
        ArgumentNullException.ThrowIfNull(row);
        ArgumentNullException.ThrowIfNull(answer);
        if (answer.Lines is null || answer.Allowed)
        {
            return new NotFoundException(answer.Named, row.Key);
        }
        string message = $"permission denied: {answer.Who} may not {row.Command} row {Keys.Text(row.Key)} of {answer.Named}";
        return new RefusedException(message, answer.Named, row.Command, answer.Lines);
    }
}
