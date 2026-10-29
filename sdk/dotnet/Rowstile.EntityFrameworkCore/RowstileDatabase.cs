using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Npgsql;

namespace Rowstile.EntityFrameworkCore;

/// <summary>
/// The runtime's answers, on a context's connection, as whoever it signs in as (<c>UseRowstile()</c>): in the
/// transaction the context has open, else in one of their own.
/// </summary>
public static class RowstileDatabase
{
    /// <summary>
    /// The ids of <paramref name="permission"/>'s type the signed-in user holds it on, as a query to compose (a set
    /// check, never a function call per row): <c>db.Projects.Where(p => db.Database.Ids(Policy.Project.Edit).Contains(p.Id))</c>.
    /// For a key of type bigint; <see cref="TextIds"/> for any other key, as text.
    /// </summary>
    public static IQueryable<long> Ids(this DatabaseFacade database, Permission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        return database.SqlQuery<long>(
            $"SELECT CAST(x AS bigint) AS \"Value\" FROM authz.list({permission.Type.Name}, {permission.Name}) x"
        );
    }

    /// <summary>The ids <see cref="Ids"/> gives, as the text <c>authz.list</c> gives them: for a key that isn't a bigint.</summary>
    public static IQueryable<string> TextIds(this DatabaseFacade database, Permission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        return database.SqlQuery<string>(
            $"SELECT x AS \"Value\" FROM authz.list({permission.Type.Name}, {permission.Name}) x"
        );
    }

    /// <summary>Whether the signed-in user holds <paramref name="permission"/> on the object <paramref name="id"/>.</summary>
    public static Task<bool> CanAsync(
        this DatabaseFacade database,
        Permission permission,
        object id,
        CancellationToken cancellationToken = default
    ) => InTransaction(database, conn => conn.CanAsync(permission, id, cancellationToken), cancellationToken);

    /// <summary>{id: [permissions]} for many objects in one call (a list's buttons), the permissions as the generated client names them.</summary>
    public static Task<IReadOnlyDictionary<string, IReadOnlyList<Permission>>> PermsOfAsync(
        this DatabaseFacade database,
        ObjectType type,
        IEnumerable<object> ids,
        CancellationToken cancellationToken = default
    ) => InTransaction(database, conn => conn.PermsOfAsync(type, ids, cancellationToken), cancellationToken);

    /// <summary>
    /// A count of rows an <c>ExecuteUpdate</c> or <c>ExecuteDelete</c> changed: returned if it changed something, else
    /// <see cref="NotFoundException"/> (the row is hidden, or the statement matched nothing for another reason) or
    /// <see cref="RefusedException"/> (the user may not, and why).
    /// <code>
    /// int deleted = await db.Notes.Where(n => n.Id == id).ExecuteDeleteAsync();
    /// await db.Database.ExpectAsync(deleted, "app.notes", "delete", id);
    /// </code>
    /// </summary>
    public static Task<int> ExpectAsync(
        this DatabaseFacade database,
        int changed,
        string table,
        string command,
        object key,
        CancellationToken cancellationToken = default
    ) =>
        changed > 0
            ? Task.FromResult(changed)
            : InTransaction(
                database,
                conn => conn.ExpectAsync(changed, table, command, key, cancellationToken),
                cancellationToken
            );

    /// <summary>The errors <c>authz.connection_check()</c> finds on the context's connections (none: the app may use them).</summary>
    public static Task<IReadOnlyList<string>> ConnectionProblemsAsync(
        this DatabaseFacade database,
        CancellationToken cancellationToken = default
    ) => InTransaction(database, conn => conn.ConnectionProblemsAsync(cancellationToken), cancellationToken);

    private static async Task<T> InTransaction<T>(
        DatabaseFacade database,
        Func<NpgsqlConnection, Task<T>> run,
        CancellationToken cancellationToken
    )
    {
        ArgumentNullException.ThrowIfNull(database);
        var conn = (NpgsqlConnection)database.GetDbConnection();
        if (database.CurrentTransaction is not null)
        {
            return await run(conn).ConfigureAwait(false);
        }
        // signed in as it begins (UseRowstile's interceptor)
        var tx = await database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var result = await run(conn).ConfigureAwait(false);
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            await tx.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>Asking the database about the rows of a SaveChanges whose update or delete matched none.</summary>
internal static class Asking
{
    /// <summary>
    /// Asks about the rows of <paramref name="stale"/>, on the connection, in its transaction, and records the answer
    /// on it (<see cref="Rowstile.Stale"/>): the first row the database says no for, or that the rules allow every row.
    /// </summary>
    public static async Task Stale(NpgsqlConnection conn, DbUpdateConcurrencyException stale, CancellationToken cancellationToken)
    {
        var rows = stale.Entries.Select(Row).ToList();
        try
        {
            var answers = await conn.AskAsync(rows, cancellationToken).ConfigureAwait(false);
            var refused = rows.Zip(answers).FirstOrDefault(ra => !ra.Second.Allowed);
            Rowstile.Stale.Record(stale, refused == default ? null : Verdicts.Of(refused.First, refused.Second));
        }
        catch (PostgresException)
        {
            // the error the app sees is SaveChanges' own: this one would hide it (the rollback to the savepoint, next,
            // undoes it)
        }
    }

    /// <summary>The row of an entry SaveChanges updated or deleted: its table, as the model maps it, and its key.</summary>
    private static RowAsked Row(EntityEntry entry)
    {
        var type = entry.Metadata;
        object?[] key = [.. type.FindPrimaryKey()!.Properties.Select(p => entry.Property(p.Name).OriginalValue)];
        return new RowAsked(type.GetSchemaQualifiedTableName()!, entry.State == EntityState.Deleted ? "delete" : "update", key);
    }
}
