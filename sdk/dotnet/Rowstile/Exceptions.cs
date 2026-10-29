using System;
using System.Collections.Generic;
using System.Linq;

namespace Rowstile;

/// <summary>The database refused a write, and said why: the rule (table and command), and the explanation.</summary>
public sealed class RefusedException : Exception
{
    /// <summary>A refusal: the database's words, the table and command whose rule refused it, why (a line each), its code.</summary>
    public RefusedException(
        string message,
        string? table = null,
        string? command = null,
        IReadOnlyList<string>? why = null,
        string? code = null
    )
        : base(message)
    {
        Table = table;
        Command = command;
        Why = why ?? [];
        Code = code ?? "AZ709";
    }

    /// <summary>The table, as the policy names it (<c>app.notes</c>); null for a refusal by the database's own code.</summary>
    public string? Table { get; }

    /// <summary>The rule's command (<c>insert</c>, <c>update</c>, <c>delete</c>, <c>select</c>); null for a refusal by the database's own code.</summary>
    public string? Command { get; }

    /// <summary>Why, a line each, as the database explained it.</summary>
    public IReadOnlyList<string> Why { get; }

    /// <summary>rowstile's code: AZ709, a rule's refusal (<c>rowstile help AZ709</c>); the database's own for another (AZ705: a share).</summary>
    public string Code { get; }

    /// <summary>The problem body for a 403 (RFC 9457).</summary>
    public Problem Problem => Problem.Refused(Message, Table, Command, Why, Code);
}

/// <summary>The row isn't there, or whoever the transaction acts for can't see it.</summary>
public sealed class NotFoundException : Exception
{
    /// <summary>The row of <paramref name="table"/> with key <paramref name="id"/>: <c>app.notes 7 not found</c>.</summary>
    public NotFoundException(string? table = null, object? id = null)
        : base(Said(table, Keys.Text(id)))
    {
        Table = table;
        Id = Keys.Text(id);
    }

    /// <summary>The table, as the policy names it.</summary>
    public string? Table { get; }

    /// <summary>The row's key as Postgres writes it: <c>7</c>, or <c>(1,2)</c> for a key of several columns.</summary>
    public string? Id { get; }

    /// <summary>The problem body for a 404 (RFC 9457).</summary>
    public Problem Problem => new("https://rowstile.dev/problems/not-found", "Not Found", 404, Message);

    // 'app.notes 7 not found', 'app.notes not found', 'row 7 not found', or 'not found'
    private static string Said(string? table, string? id)
    {
        var named = id is not null ? new[] { table ?? "row", id } : table is not null ? [table] : [];
        return string.Join(' ', named.Append("not found"));
    }
}

/// <summary>A query that needs to know who is asking ran in a transaction nobody signed in to (<c>rowstile help AZ701</c>).</summary>
public sealed class NotSignedInException(string message, Exception inner) : Exception(message, inner);

/// <summary><c>authz.connection_check()</c> found that the app's connection skips row-level security (or worse).</summary>
public sealed class ConnectionProblemException(IReadOnlyList<string> problems)
    : Exception("the app's database connection can't be used with rowstile: " + string.Join("; ", problems))
{
    /// <summary>What the check said, a problem each.</summary>
    public IReadOnlyList<string> Problems { get; } = problems;
}
