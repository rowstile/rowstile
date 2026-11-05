using System;
using System.Runtime.CompilerServices;
using Npgsql;

namespace Rowstile;

/// <summary>
/// Whom the transaction <see cref="RowstileNpgsql.BeginSignedInAsync"/> began on a connection signed in as, while it is
/// open. Npgsql runs a command in the connection's open transaction whatever the command's own transaction is, so an
/// EF Core context on that connection that doesn't know of it (no <c>UseTransaction</c>) runs its commands in it: they
/// sign nothing in again, and work for anyone else is refused before it is sent.
/// </summary>
internal static class SignedConnections
{
    private static readonly ConditionalWeakTable<NpgsqlConnection, Signed> Open = [];

    private sealed record Signed(NpgsqlTransaction Transaction, Principal Who);

    public static void Record(NpgsqlConnection conn, NpgsqlTransaction transaction, Principal who) =>
        Open.AddOrUpdate(conn, new Signed(transaction, who));

    /// <summary>
    /// Whom the transaction open on <paramref name="conn"/> that <see cref="RowstileNpgsql.BeginSignedInAsync"/> began
    /// signed in as, or null when there is none. (Npgsql gives a connection's next transaction the same object: one the
    /// app begins there itself after it is taken for it, and its commands are refused or run unsigned, an error.)
    /// </summary>
    public static Principal? Of(NpgsqlConnection conn)
    {
        if (!Open.TryGetValue(conn, out var signed))
        {
            return null;
        }
        try
        {
            _ = signed.Transaction.IsolationLevel; // a transaction that ended throws
            return signed.Who;
        }
        catch (InvalidOperationException) // (ObjectDisposedException too: one disposed)
        {
            Open.Remove(conn);
            return null;
        }
    }
}
