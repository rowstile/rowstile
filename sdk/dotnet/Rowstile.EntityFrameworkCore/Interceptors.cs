using System.Data.Common;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace Rowstile.EntityFrameworkCore;

/// <summary>
/// Every transaction the context begins signs in first. Before SaveChanges rolls back to its savepoint because a
/// write matched no row, the database is asked why (<see cref="Asking"/>).
/// </summary>
internal sealed class TransactionSignIn(SignIn signIn, SaveChangesInTransaction saves) : DbTransactionInterceptor
{
    public override InterceptionResult RollingBackToSavepoint(
        DbTransaction transaction,
        TransactionEventData eventData,
        InterceptionResult result
    )
    {
        if (saves.TakeStale(eventData.Context!) is { } stale)
        {
            Asking.Stale((NpgsqlConnection)transaction.Connection!, stale, CancellationToken.None).GetAwaiter().GetResult();
        }
        return result;
    }

    public override async ValueTask<InterceptionResult> RollingBackToSavepointAsync(
        DbTransaction transaction,
        TransactionEventData eventData,
        InterceptionResult result,
        CancellationToken cancellationToken = default
    )
    {
        if (saves.TakeStale(eventData.Context!) is { } stale)
        {
            await Asking.Stale((NpgsqlConnection)transaction.Connection!, stale, cancellationToken).ConfigureAwait(false);
        }
        return result;
    }

    public override DbTransaction TransactionStarted(
        DbConnection connection,
        TransactionEndEventData eventData,
        DbTransaction result
    )
    {
        using var cmd = Command(connection, result);
        cmd.ExecuteNonQuery();
        return result;
    }

    public override async ValueTask<DbTransaction> TransactionStartedAsync(
        DbConnection connection,
        TransactionEndEventData eventData,
        DbTransaction result,
        CancellationToken cancellationToken = default
    )
    {
        await using var cmd = Command(connection, result);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private NpgsqlCommand Command(DbConnection connection, DbTransaction transaction)
    {
        var cmd = new NpgsqlCommand(RowstileNpgsql.ActAs, (NpgsqlConnection)connection, (NpgsqlTransaction)transaction);
        cmd.Parameters.AddRange(RowstileNpgsql.ActAsParameters(signIn.Who()));
        return cmd;
    }
}

/// <summary>
/// A command outside a transaction runs in one of its own, which Postgres makes for the statements of one command:
/// the sign-in goes first in it. Its result (one row) is skipped, so the app reads its own statement's; a SELECT's
/// rows are no rows affected, so a count stays the app's statement's.
/// </summary>
internal sealed class CommandSignIn(SignIn signIn) : DbCommandInterceptor
{
    private const string Prefix = RowstileNpgsql.ActAs + ";\n";

    public override InterceptionResult<DbDataReader> ReaderExecuting(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<DbDataReader> result
    )
    {
        SignInFirst(command);
        return result;
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<DbDataReader> result,
        CancellationToken cancellationToken = default
    )
    {
        SignInFirst(command);
        return ValueTask.FromResult(result);
    }

    public override DbDataReader ReaderExecuted(
        DbCommand command,
        CommandExecutedEventData eventData,
        DbDataReader result
    )
    {
        if (Signed(command))
        {
            result.NextResult(); // past the sign-in's row, to the app's statement's
        }
        return result;
    }

    public override async ValueTask<DbDataReader> ReaderExecutedAsync(
        DbCommand command,
        CommandExecutedEventData eventData,
        DbDataReader result,
        CancellationToken cancellationToken = default
    )
    {
        if (Signed(command))
        {
            await result.NextResultAsync(cancellationToken).ConfigureAwait(false);
        }
        return result;
    }

    public override InterceptionResult<int> NonQueryExecuting(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<int> result
    )
    {
        SignInFirst(command);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default
    )
    {
        SignInFirst(command);
        return ValueTask.FromResult(result);
    }

    // a scalar is the first result's first value, which would be the sign-in's: read the app's statement's instead
    public override InterceptionResult<object> ScalarExecuting(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<object> result
    )
    {
        if (!SignInFirst(command))
        {
            return result;
        }
        using var reader = command.ExecuteReader();
        reader.NextResult();
        return InterceptionResult<object>.SuppressWithResult(reader.Read() ? reader.GetValue(0) : null!);
    }

    public override async ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<object> result,
        CancellationToken cancellationToken = default
    )
    {
        if (!SignInFirst(command))
        {
            return result;
        }
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        await reader.NextResultAsync(cancellationToken).ConfigureAwait(false);
        bool row = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        return InterceptionResult<object>.SuppressWithResult(row ? reader.GetValue(0) : null!);
    }

    /// <summary>Puts the sign-in first in a command outside a transaction; whether it did.</summary>
    private bool SignInFirst(DbCommand command)
    {
        if (command.Transaction is not null)
        {
            return false; // the transaction signed in when it began
        }
        command.CommandText = Prefix + command.CommandText;
        command.Parameters.AddRange(RowstileNpgsql.ActAsParameters(signIn.Who()));
        return true;
    }

    private static bool Signed(DbCommand command) =>
        command.CommandText.StartsWith(Prefix, System.StringComparison.Ordinal);
}

/// <summary>
/// SaveChanges in a transaction of the SDK's when the app has none open, committed when it succeeds and rolled back
/// when it fails. So EF Core sends its writes after a savepoint, and rolls back to it when one fails: an update or a
/// delete that matched no row (a <see cref="DbUpdateConcurrencyException"/>) is asked about just before, in the
/// transaction and as the same user, while it still holds what SaveChanges wrote.
/// </summary>
internal sealed class SaveChangesInTransaction : SaveChangesInterceptor
{
    private readonly ConditionalWeakTable<DbContext, Saving> saving = [];

    /// <summary>What SaveChanges on a context is at: the SDK's transaction, and the write that matched no row.</summary>
    internal sealed class Saving
    {
        public IDbContextTransaction? Ours { get; set; }

        public DbUpdateConcurrencyException? Stale { get; set; }
    }

    /// <summary>The write of the context's that matched no row, if one is waiting to be asked about (and no longer waiting).</summary>
    public DbUpdateConcurrencyException? TakeStale(DbContext db)
    {
        if (!saving.TryGetValue(db, out var s))
        {
            return null;
        }
        var stale = s.Stale;
        s.Stale = null;
        return stale;
    }

    private Saving Of(DbContext db) =>
        saving.GetValue(
            db,
            context =>
            {
                var s = new Saving();
                // a failed SaveChanges (one that matched no row too, which no interceptor hears of) ends the SDK's
                // transaction: rolled back
                context.SaveChangesFailed += (_, _) => End(s)?.Dispose();
                return s;
            }
        );

    private static IDbContextTransaction? End(Saving s)
    {
        var tx = s.Ours;
        s.Ours = null;
        s.Stale = null;
        return tx;
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        var db = eventData.Context!;
        var s = Of(db);
        if (db.Database.CurrentTransaction is null)
        {
            s.Ours = db.Database.BeginTransaction();
        }
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default
    )
    {
        var db = eventData.Context!;
        var s = Of(db);
        if (db.Database.CurrentTransaction is null)
        {
            s.Ours = await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        }
        return result;
    }

    // the batch's reader is still open: the question waits for the rollback to the savepoint
    public override InterceptionResult ThrowingConcurrencyException(ConcurrencyExceptionEventData eventData, InterceptionResult result)
    {
        Of(eventData.Context!).Stale = (DbUpdateConcurrencyException)eventData.Exception;
        return result;
    }

    public override ValueTask<InterceptionResult> ThrowingConcurrencyExceptionAsync(
        ConcurrencyExceptionEventData eventData,
        InterceptionResult result,
        CancellationToken cancellationToken = default
    ) => ValueTask.FromResult(ThrowingConcurrencyException(eventData, result));

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        if (End(Of(eventData.Context!)) is { } tx)
        {
            using (tx)
            {
                tx.Commit();
            }
        }
        return result;
    }

    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData,
        int result,
        CancellationToken cancellationToken = default
    )
    {
        if (End(Of(eventData.Context!)) is { } tx)
        {
            await using (tx.ConfigureAwait(false))
            {
                await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        return result;
    }
}
