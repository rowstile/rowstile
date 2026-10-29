using System;
using System.Threading;
using System.Threading.Tasks;
using Npgsql;

namespace Rowstile.Testing;

/// <summary>A worker's own test database: its connection string (the owner's), and the app role's if one was given.</summary>
/// <param name="ConnectionString">The copy, as the owner.</param>
/// <param name="AppConnectionString">The copy, as the app role; null if none was given.</param>
public sealed record WorkerDatabase(string ConnectionString, string? AppConnectionString);

/// <summary>
/// A copy of the migrated test database (with the policy) for each test worker, so tests that write don't meet each
/// other: in xUnit, one for each test collection (a collection fixture), named after the worker.
/// <code>
/// public sealed class Database : IAsyncLifetime
/// {
///     public WorkerDatabase Copy { get; private set; } = null!;
///     public async ValueTask InitializeAsync() =>
///         Copy = await TestDatabase.PerWorkerAsync(Environment.GetEnvironmentVariable("ROWSTILE_TESTS_CONN")!, "1");
/// }
/// </code>
/// </summary>
public static class TestDatabase
{
    /// <summary>
    /// A database for <paramref name="worker"/>, copied from the one <paramref name="connectionString"/> names (migrated,
    /// with the policy), named after it (<c>conf_tests_w1</c>), with the same user. The copy is made by a role that may
    /// create databases (the owner), while nothing else is connected to the original. A copy an earlier run left is made
    /// again, unless <paramref name="fresh"/> is false. <paramref name="appConnectionString"/>: the app role's, returned
    /// for the copy.
    /// </summary>
    public static async Task<WorkerDatabase> PerWorkerAsync(
        string connectionString,
        string worker,
        string? appConnectionString = null,
        bool fresh = true,
        CancellationToken cancellationToken = default
    )
    {
        var original = new NpgsqlConnectionStringBuilder(connectionString);
        string template = original.Database ?? "";
        if (template.Length == 0)
        {
            throw new ArgumentException("TestDatabase.PerWorkerAsync needs a database to copy, and this connection string names none", nameof(connectionString));
        }
        string name = $"{template}_w{worker}";
        // CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included; and no pool
        // keeps one open after
        var elsewhere = new NpgsqlConnectionStringBuilder(connectionString) { Database = "postgres", Pooling = false };
        await using var conn = new NpgsqlConnection(elsewhere.ConnectionString);
        await conn.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using (var exists = new NpgsqlCommand("SELECT 1 FROM pg_database WHERE datname = @n", conn))
        {
            exists.Parameters.AddWithValue("n", name);
            bool there = await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not null;
            if (there && !fresh)
            {
                return Copy(connectionString, appConnectionString, name);
            }
            if (there)
            {
                await Run(conn, $"DROP DATABASE {Quote(name)} WITH (FORCE)", cancellationToken).ConfigureAwait(false);
            }
        }
        try
        {
            await Run(conn, $"CREATE DATABASE {Quote(name)} TEMPLATE {Quote(template)}", cancellationToken).ConfigureAwait(false);
        }
        catch (PostgresException e) when (e.SqlState == "55006")
        {
            // something is connected to the original (Postgres has waited five seconds for it to leave)
            throw new InvalidOperationException(
                $"Rowstile.Testing: {template} can't be copied while anything is connected to it: close what holds it "
                    + "(the app, a migration tool, a console, a pooled connection: Pooling=false on the original's). "
                    + "Where the service keeps a connection of its own for minutes after yours (Neon does), a copy per "
                    + "worker can't be made: use one test database, where each test rolls back, or a branch for each run",
                e
            );
        }
        return Copy(connectionString, appConnectionString, name);
    }

    private static WorkerDatabase Copy(string connectionString, string? appConnectionString, string name) =>
        new(
            new NpgsqlConnectionStringBuilder(connectionString) { Database = name }.ConnectionString,
            appConnectionString is null ? null : new NpgsqlConnectionStringBuilder(appConnectionString) { Database = name }.ConnectionString
        );

    private static string Quote(string identifier) => "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static async Task Run(NpgsqlConnection conn, string sql, CancellationToken cancellationToken)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
