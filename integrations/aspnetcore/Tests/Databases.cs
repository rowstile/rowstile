// What the checks share: the environment test.sh sets, a copy of the migrated test database for each test
// collection (check 12: collections run side by side, each on its own), the same few rows in each, and the app.
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;
using Rowstile.Testing;

namespace Conformance.Tests;

public static class Env
{
    /// <summary>The migrated test database, as the owner (test.sh's conf_tests): each collection copies it.</summary>
    public static string Tests => Get("ROWSTILE_TESTS_CONN");

    /// <summary>The app role's connection (test.sh's conf, through PgBouncer with POOLER=pgbouncer): each copy's is this, on the copy.</summary>
    public static string App => Get("ROWSTILE_APP_CONN");

    /// <summary>integrations/aspnetcore.</summary>
    public static string Here => Get("CONFORMANCE_HERE");

    private static string Get(string name) =>
        Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"{name} is not set (test.sh sets it)");
}

/// <summary>A collection's own copy of the migrated test database, with the same few rows in each.</summary>
public abstract class Database : IAsyncLifetime
{
    // copies are made one at a time: a copy needs nobody connected to the original
    public static readonly SemaphoreSlim Copying = new(1, 1);

    public WorkerDatabase Copy { get; private set; } = null!;

    /// <summary>The copy as the owner: test data, and what someone else does meanwhile.</summary>
    public string Owner => Copy.ConnectionString;

    /// <summary>The copy as the app role.</summary>
    public string App => Copy.AppConnectionString!;

    protected abstract string Worker { get; }

    public async ValueTask InitializeAsync()
    {
        await Copying.WaitAsync();
        try
        {
            Copy = await TestDatabase.PerWorkerAsync(Env.Tests, Worker, Env.App);
        }
        finally
        {
            Copying.Release();
        }
        await Data.Reset(Owner);
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        NpgsqlConnection.ClearAllPools();
        return ValueTask.CompletedTask;
    }
}

public sealed class ConformanceDatabase : Database
{
    protected override string Worker => "1";
}

public sealed class SdkDatabase : Database
{
    protected override string Worker => "2";
}

public sealed class MigrationDatabase : Database
{
    protected override string Worker => "3";
}

[CollectionDefinition("conformance")]
public sealed class ConformanceCollection : ICollectionFixture<ConformanceDatabase>;

[CollectionDefinition("sdk")]
public sealed class SdkCollection : ICollectionFixture<SdkDatabase>;

[CollectionDefinition("migrations")]
public sealed class MigrationCollection : ICollectionFixture<MigrationDatabase>;

public static class Data
{
    /// <summary>
    /// The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
    /// project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it.
    /// </summary>
    public static async Task Reset(string owner)
    {
        await using var conn = new NpgsqlConnection(owner);
        await conn.OpenAsync();
        await Sql(
            conn,
            """
            TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services, app.users CASCADE;
            INSERT INTO app.users (id, name) VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
            INSERT INTO app.services (id, name) VALUES (1, 'digest');
            INSERT INTO app.projects (id, owner_id, name, public) VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
            INSERT INTO app.members (project_id, user_id) VALUES (1, 3);
            INSERT INTO app.project_services (project_id, service_id) VALUES (1, 1);
            INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
            SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
            INSERT INTO app.folders (id, parent_id, owner_id, name) VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside')
            """
        );
    }

    public static async Task Sql(string connectionString, string sql)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync();
        await Sql(conn, sql);
    }

    public static async Task<object?> Scalar(string connectionString, string sql)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        return await cmd.ExecuteScalarAsync();
    }

    private static async Task Sql(NpgsqlConnection conn, string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }
}

/// <summary>The conformance app (Program.cs), on a copy's app role, as test.sh would start it.</summary>
public sealed class AppFactory(string app, bool checkConnection = false) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production"); // an error the app doesn't answer reaches the test, as it is
        builder.UseSetting("Logging:LogLevel:Default", "Critical"); // the errors the checks make on purpose
        builder.UseSetting("ROWSTILE_APP_CONN", app);
        builder.UseSetting("ROWSTILE_CHECK_CONNECTION", checkConnection ? "true" : "false");
    }
}

public static class Http
{
    /// <summary>A request as a user (x-user: the conformance app's stand-in for a session), with a JSON body.</summary>
    public static Task<HttpResponseMessage> Send(
        this HttpClient client,
        HttpMethod method,
        string path,
        string? user = null,
        JsonObject? body = null,
        params (string Name, string Value)[] headers
    )
    {
        var request = new HttpRequestMessage(method, path);
        if (user is not null)
        {
            request.Headers.Add("x-user", user);
        }
        foreach (var (name, value) in headers)
        {
            request.Headers.Add(name, value);
        }
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        return client.SendAsync(request);
    }

    public static async Task<JsonNode> Json(this HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync()) ?? throw new InvalidOperationException("no body");

    /// <summary>A problem body as the other SDKs write it.</summary>
    public static JsonObject Problem(string kind, string title, int status, string detail, string? code = null)
    {
        var p = new JsonObject
        {
            ["type"] = $"https://rowstile.dev/problems/{kind}",
            ["title"] = title,
            ["status"] = status,
            ["detail"] = detail,
        };
        if (code is not null)
        {
            p["code"] = code;
        }
        return p;
    }

    /// <summary>The response is this problem body, with the problem's content type and status.</summary>
    public static async Task IsProblem(this HttpResponseMessage response, JsonNode expected)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.True(JsonNode.DeepEquals(expected, JsonNode.Parse(body)), $"{body}, not {expected.ToJsonString()}");
        Assert.Equal((int)expected["status"]!, (int)response.StatusCode);
    }
}
