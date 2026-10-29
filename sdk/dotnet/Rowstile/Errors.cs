using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Npgsql;

namespace Rowstile;

/// <summary>
/// What a database error is, read from the error itself (Npgsql's <see cref="PostgresException"/>, bare or inside
/// another: EF Core's <c>DbUpdateException</c>). The runtime names its code in the HINT, <c>rowstile help AZ709</c>.
/// </summary>
public static class Errors
{
    private const string Unseen =
        "this user may not see the row as written (the select rule). An insert that reads it back (RETURNING), "
        + "an upsert, and an update with a WHERE need to see it.";

    // rowstile's codes for a call the database turned down that is no refusal, and what their pages say to answer
    // (rowstile help AZ703: a login refused; AZ708: what the call names isn't there; AZ710: a missing or wrong
    // argument; AZ713: moved inside itself; AZ714: sign in first)
    private static readonly Dictionary<string, (string Type, string Title, int Status)> CallProblems = new()
    {
        ["AZ703"] = ("https://rowstile.dev/problems/not-signed-in", "Unauthorized", 401),
        ["AZ708"] = ("https://rowstile.dev/problems/not-found", "Not Found", 404),
        ["AZ710"] = ("https://rowstile.dev/problems/bad-argument", "Bad Request", 400),
        ["AZ713"] = ("https://rowstile.dev/problems/conflict", "Conflict", 409),
        ["AZ714"] = ("https://rowstile.dev/problems/not-signed-in", "Unauthorized", 401),
    };

    /// <summary>The database's error inside <paramref name="error"/> (itself, or an inner exception), or null.</summary>
    public static PostgresException? Database(Exception? error)
    {
        for (var e = error; e is not null; e = e.InnerException)
        {
            if (e is PostgresException pg)
            {
                return pg;
            }
        }
        return null;
    }

    /// <summary>The error's SQLSTATE (<c>42501</c>), or null for an error that isn't the database's.</summary>
    public static string? SqlState(Exception error) => Database(error)?.SqlState;

    /// <summary>
    /// rowstile's code for a database error (AZ709; <c>rowstile help AZ709</c> says what it means): from its HINT,
    /// where the runtime puts it, or its message. Null for an error rowstile didn't raise.
    /// </summary>
    public static string? Code(Exception error)
    {
        var pg = Database(error);
        foreach (var text in new[] { pg?.Hint, pg?.MessageText })
        {
            var m = HelpCodeRegex.Match(text ?? "");
            if (m.Success)
            {
                return m.Groups[1].Value;
            }
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="error"/> is strict sign-in's error (<c>rowstile help AZ701</c>): a query that needs to
    /// know who is asking ran in a transaction nobody signed in to. A login refused (AZ703) and settings changed by hand
    /// (AZ702) share its SQLSTATE, 28000, but are no such thing.
    /// </summary>
    public static bool IsNotSignedIn(Exception error) =>
        SqlState(error) == "28000" && Code(error) is null or "AZ701";

    /// <summary>
    /// A <see cref="RefusedException"/> for an error that is the database refusing a write (SQLSTATE 42501, raised by
    /// rowstile's policies with the rule and why), else null. Another 42501 (a table the app role was never
    /// granted) is the app's mistake, not a refusal: null.
    /// </summary>
    public static RefusedException? Refusal(Exception error)
    {
        var pg = Database(error);
        if (pg is not { SqlState: "42501" })
        {
            return null;
        }
        string message = pg.MessageText;
        string? code = Code(error);
        // Postgres's own words, not rowstile's: a check of a row no rule's own refusal covers. Postgres names the table
        // without its schema
        var generic = PostgresWordsRegex.Match(message);
        if (code is null && !generic.Success)
        {
            return null;
        }
        if (code is not null && CallProblems.ContainsKey(code))
        {
            return null; // sign in first (AZ714) is a 42501 too, but no refusal: a 401
        }
        if (generic.Success)
        {
            string table = generic.Groups[3].Value;
            if (generic.Groups[1].Value == "target")
            {
                // MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
                return new RefusedException(
                    $"{message}: MERGE matched a row the update or delete rule doesn't let this user change",
                    table
                );
            }
            if (generic.Groups[2].Success)
            {
                // an upsert (INSERT ... ON CONFLICT DO UPDATE) whose existing row this user may not update, or not see
                return new RefusedException(
                    $"{message}: the row is there already, and the update rule (or the select rule) doesn't let this "
                        + "user change it (ON CONFLICT DO UPDATE)",
                    table,
                    "update"
                );
            }
            // the select rule, on the row as written: an insert that reads it back (RETURNING), an upsert, or an
            // update after which the row would be out of this user's sight
            return new RefusedException($"{message}: {Unseen}", table, "select");
        }
        string constraint = pg.ConstraintName ?? "";
        return new RefusedException(
            message,
            pg.SchemaName is not null && pg.TableName is not null ? $"{pg.SchemaName}.{pg.TableName}" : pg.TableName,
            constraint.StartsWith("authz_", StringComparison.Ordinal) ? constraint[6..] : null,
            string.IsNullOrEmpty(pg.Detail) ? [] : pg.Detail.Split('\n'),
            code
        );
    }

    /// <summary>
    /// The problem body for an error rowstile's answer is known for, else null: a refusal (403, with the rule and the
    /// reason), a row the user can't see (404), an update or a delete of an ORM's that matched no row
    /// (<see cref="Stale"/>: 403, 404, or 409 when the rules allow it), and a call the database turned down that is
    /// no refusal, as its code's page says, with the database's words: a login refused or a call that needs someone
    /// signed in 401 (AZ703, AZ714), something the call names that isn't there 404 (AZ708), an argument missing or
    /// wrong 400 (AZ710), a move inside itself 409 (AZ713). The app's mistakes (AZ706, AZ707, AZ702) have none: they
    /// stay errors.
    /// </summary>
    public static Problem? ProblemOf(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        switch (error)
        {
            case RefusedException refused:
                return refused.Problem;
            case NotFoundException notFound:
                return notFound.Problem;
        }
        switch (Stale.Why(error))
        {
            case RefusedException refused:
                return refused.Problem;
            case NotFoundException notFound:
                return notFound.Problem;
        }
        if (Stale.RulesAllow(error))
        {
            return Problem.Conflict;
        }
        if (Refusal(error) is { } refusal)
        {
            return refusal.Problem;
        }
        string? code = Code(error);
        if (code is null || !CallProblems.TryGetValue(code, out var said))
        {
            return null;
        }
        return new Problem(said.Type, said.Title, said.Status, Database(error)!.MessageText)
        {
            Extensions = [new("code", code)],
        };
    }

    private static readonly Regex HelpCodeRegex = new(@"rowstile help (AZ\d{3})");

    private static readonly Regex PostgresWordsRegex = new(
        @"^(new|target) row violates row-level security policy (\(USING expression\) )?for table ""([^""]+)"""
    );
}
