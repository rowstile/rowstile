using System;

namespace Rowstile;

/// <summary>
/// An ORM's update or delete that matched no row (EF Core's <c>DbUpdateConcurrencyException</c>): what the
/// database said of its rows, asked in its own transaction before that was rolled back
/// (<c>Rowstile.EntityFrameworkCore</c> asks, and records the answer on the error).
/// </summary>
public static class Stale
{
    private const string Key = "rowstile.verdict";
    private const string Allowed = "the rules allow every row";

    /// <summary>
    /// What the database said of the row: <see cref="NotFoundException"/> (the user can't see it) or
    /// <see cref="RefusedException"/> (they may not, and why). Null when the rules allow every row (the row changed
    /// since it was read: <see cref="RulesAllow"/>), or when nothing asked.
    /// </summary>
    public static Exception? Why(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return error.Data[Key] as Exception;
    }

    /// <summary>Whether the database said the rules allow every row of the write that matched none: not the rules' doing (a 409).</summary>
    public static bool RulesAllow(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return error.Data[Key] is Allowed;
    }

    /// <summary>
    /// Records on <paramref name="error"/> what the database said: <paramref name="verdict"/>, a
    /// <see cref="NotFoundException"/> or a <see cref="RefusedException"/>; null when the rules allow every row.
    /// </summary>
    public static void Record(Exception error, Exception? verdict)
    {
        ArgumentNullException.ThrowIfNull(error);
        error.Data[Key] = verdict ?? (object)Allowed;
    }
}
