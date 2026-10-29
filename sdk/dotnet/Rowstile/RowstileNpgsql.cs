using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Npgsql;

namespace Rowstile;

/// <summary>
/// rowstile with Npgsql: transactions signed in as whoever the code acts for, and the runtime's answers.
/// <code>
/// await using var tx = await conn.BeginSignedInAsync(Principal.User("42"));   // BEGIN; SELECT authz.act_as('user', '42')
/// int changed = await new NpgsqlCommand("UPDATE app.notes SET body = 'x' WHERE id = 7", conn).ExecuteNonQueryAsync();
/// await conn.ExpectAsync(changed, "app.notes", "update", 7);                 // 0 rows: NotFoundException or RefusedException
/// await tx.CommitAsync();
/// </code>
/// A pooled connection never carries one request's user into another's: the sign-in ends with the transaction.
/// </summary>
public static class RowstileNpgsql
{
    /// <summary>The statement that signs a transaction in, with its two parameters: the principal's type and id (both null: nobody).</summary>
    public const string ActAs = "SELECT authz.act_as(@rowstile_type, @rowstile_id)";

    private const string Who =
        "coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), 'someone not signed in')";

    // authz.explain_rule for each row, in one statement and in the rows' order; with who is signed in, and the table as
    // the policy names it (a table named without its schema is looked up on the search_path)
    private const string Explain =
        "SELECT r.* FROM unnest(CAST(@t AS text[]), CAST(@c AS text[]), CAST(@k AS text[])) WITH ORDINALITY AS w(t, c, k, n) "
        + "CROSS JOIN LATERAL (SELECT authz.explain_rule(x.tbl, w.c, w.k, NULL), "
        + Who
        + ", x.tbl FROM (SELECT coalesce((SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c "
        + "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE position('.' in w.t) = 0 "
        + "AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident(w.t))), w.t) AS tbl) x) r ORDER BY w.n";

    /// <summary>
    /// authz.act_as's arguments for <paramref name="who"/>: (<c>user</c>, <c>42</c>), or (null, null) for nobody.
    /// Left out (null), whoever the code acts for now (<see cref="Acting.Current"/>), else nobody.
    /// </summary>
    public static (string? Type, string? Id) ActAsArgs(Principal? who = null)
    {
        var p = who ?? Acting.Current ?? Principal.Nobody;
        return p.Id is null ? (null, null) : (p.Type, p.Id);
    }

    /// <summary>The parameters <see cref="ActAs"/> takes, for <paramref name="who"/> (as <see cref="ActAsArgs"/>).</summary>
    public static NpgsqlParameter[] ActAsParameters(Principal? who = null)
    {
        var (type, id) = ActAsArgs(who);
        return
        [
            new("rowstile_type", NpgsqlTypes.NpgsqlDbType.Text) { Value = (object?)type ?? DBNull.Value },
            new("rowstile_id", NpgsqlTypes.NpgsqlDbType.Text) { Value = (object?)id ?? DBNull.Value },
        ];
    }

    /// <summary>Signs the transaction open on <paramref name="conn"/> in as <paramref name="who"/> (left out: whoever the code acts for, else nobody).</summary>
    public static async Task SignInAsync(this NpgsqlConnection conn, Principal? who = null, CancellationToken cancellationToken = default)
    {
        await using var cmd = new NpgsqlCommand(ActAs, conn);
        cmd.Parameters.AddRange(ActAsParameters(who));
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>A transaction signed in as <paramref name="who"/> (left out: whoever the code acts for, else nobody).</summary>
    public static async Task<NpgsqlTransaction> BeginSignedInAsync(
        this NpgsqlConnection conn,
        Principal? who = null,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(conn);
        var tx = await conn.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await conn.SignInAsync(who, cancellationToken).ConfigureAwait(false);
        return tx;
    }

    /// <summary>
    /// An UPDATE or DELETE's count of rows: returned if it changed something, else <see cref="NotFoundException"/> (the
    /// row is hidden, or didn't match) or <see cref="RefusedException"/> (the user may not, and why). Asked in the
    /// transaction open on the connection, as whoever it signed in as.
    /// </summary>
    public static async Task<int> ExpectAsync(
        this NpgsqlConnection conn,
        int changed,
        string table,
        string command,
        object key,
        CancellationToken cancellationToken = default
    )
    {
        if (changed > 0)
        {
            return changed;
        }
        var row = new RowAsked(table, command, key);
        var answers = await conn.AskAsync([row], cancellationToken).ConfigureAwait(false);
        throw Verdicts.Of(row, answers[0]);
    }

    /// <summary>What <c>authz.explain_rule</c> answers for each row, in one statement, in the transaction open on the connection.</summary>
    public static async Task<IReadOnlyList<RowAnswer>> AskAsync(
        this NpgsqlConnection conn,
        IReadOnlyList<RowAsked> rows,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(rows);
        await using var cmd = new NpgsqlCommand(Explain, conn);
        cmd.Parameters.AddWithValue("t", rows.Select(r => r.Table).ToArray());
        cmd.Parameters.AddWithValue("c", rows.Select(r => r.Command).ToArray());
        cmd.Parameters.AddWithValue("k", rows.Select(r => Keys.Text(r.Key)).ToArray());
        var answers = new List<RowAnswer>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var lines = reader.IsDBNull(0) ? null : reader.GetFieldValue<string[]>(0);
            answers.Add(new RowAnswer(lines, reader.GetString(1), reader.GetString(2)));
        }
        return answers;
    }

    /// <summary>Whether the signed-in user holds <paramref name="permission"/> on the object <paramref name="id"/>.</summary>
    public static async Task<bool> CanAsync(
        this NpgsqlConnection conn,
        Permission permission,
        object id,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(permission);
        await using var cmd = new NpgsqlCommand("SELECT authz.can(@t, @i, @p)", conn);
        cmd.Parameters.AddWithValue("t", permission.Type.Name);
        cmd.Parameters.AddWithValue("i", Keys.Text(id)!);
        cmd.Parameters.AddWithValue("p", permission.Name);
        return (bool)(await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;
    }

    /// <summary>
    /// Each object's permissions the signed-in user holds, for many objects in one call (a list's buttons):
    /// {id: [permissions]}, the permissions as the generated client names them (<c>Policy.Project.Edit</c>).
    /// </summary>
    public static async Task<IReadOnlyDictionary<string, IReadOnlyList<Permission>>> PermsOfAsync(
        this NpgsqlConnection conn,
        ObjectType type,
        IEnumerable<object> ids,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(type);
        await using var cmd = new NpgsqlCommand("SELECT id, perms FROM authz.perms_of(@t, CAST(@ids AS text[]))", conn);
        cmd.Parameters.AddWithValue("t", type.Name);
        cmd.Parameters.AddWithValue("ids", ids.Select(Keys.Text).ToArray());
        var perms = new Dictionary<string, IReadOnlyList<Permission>>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            perms[reader.GetString(0)] = [.. reader.GetFieldValue<string[]>(1).Select(p => new Permission(type, p))];
        }
        return perms;
    }

    /// <summary>The errors <c>authz.connection_check()</c> finds on this connection (none: the app may use it).</summary>
    public static async Task<IReadOnlyList<string>> ConnectionProblemsAsync(
        this NpgsqlConnection conn,
        CancellationToken cancellationToken = default
    )
    {
        await using var cmd = new NpgsqlCommand("SELECT problem FROM authz.connection_check() WHERE severity = 'error'", conn);
        var problems = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            problems.Add(reader.GetString(0));
        }
        return problems;
    }

    /// <summary>
    /// Throws <see cref="ConnectionProblemException"/> if the data source's connections skip row-level security (a
    /// superuser, BYPASSRLS, the tables' owner): at start-up, before the app takes a request.
    /// </summary>
    public static async Task CheckAsync(this NpgsqlDataSource dataSource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        await using var conn = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var problems = await conn.ConnectionProblemsAsync(cancellationToken).ConfigureAwait(false);
        if (problems.Count > 0)
        {
            throw new ConnectionProblemException(problems);
        }
    }
}
