// The conformance suite (integrations/README.md): the same checks for every stack. This is ASP.NET Core, EF Core on
// Npgsql, EF Core's migrations. test.sh does check 11 (a fresh database: migrate, the policy's tests, then EF Core's
// own diff shows no change) and starts the app on the owner's connection (13) before these run.
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Rowstile;

namespace Conformance.Tests;

[Collection("conformance")]
public sealed class ConformanceTests(ConformanceDatabase db) : IAsyncLifetime
{
    private static readonly Dictionary<string, long[]> Notes = new()
    {
        ["1"] = [1, 3, 4],
        ["2"] = [2, 3],
        ["3"] = [1, 3, 4],
        [""] = [3],
    };

    private AppFactory app = null!;
    private HttpClient client = null!;

    public async ValueTask InitializeAsync()
    {
        await Data.Reset(db.Owner); // the same rows for each check
        app = new AppFactory(db.App);
        client = app.CreateClient();
    }

    public async ValueTask DisposeAsync()
    {
        client.Dispose();
        await app.DisposeAsync();
    }

    private static string? Who(string user) => user.Length == 0 ? null : user;

    private async Task<long[]> NotesOf(string user, HttpClient? on = null)
    {
        var r = await (on ?? client).Send(HttpMethod.Get, "/notes", Who(user));
        return [.. (await r.Json()).AsArray().Select(x => (long)x!)];
    }

    // 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
    [Fact]
    public async Task Check_1_2_lists_show_what_each_may_see()
    {
        foreach (var (user, notes) in Notes)
        {
            Assert.Equal(notes, await NotesOf(user));
        }
        var projects = await client.Send(HttpMethod.Get, "/projects");
        Assert.Equal("[3]", (await projects.Json()).ToJsonString());
    }

    // 3: not signed in at all: the strict sign-in error, naming act_as
    [Fact]
    public async Task Check_3_not_signed_in_is_an_error_that_says_how()
    {
        await using var conn = new NpgsqlConnection(db.App);
        await conn.OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();
        var e = await Assert.ThrowsAsync<PostgresException>(() => new NpgsqlCommand("SELECT count(*) FROM app.notes", conn).ExecuteScalarAsync());
        Assert.Equal("28000", Errors.SqlState(e));
        Assert.Contains("act_as", e.Hint, StringComparison.Ordinal);
        Assert.Equal("AZ701", Errors.Code(e)); // rowstile help AZ701
        Assert.True(Errors.IsNotSignedIn(e));
    }

    // 4: one pooled connection, Ann then Bob: Bob never sees Ann's rows
    [Fact]
    public async Task Check_4_a_pooled_connection_carries_no_one_over()
    {
        await using var one = new AppFactory(db.App + ";Maximum Pool Size=1");
        using var c = one.CreateClient();
        Assert.Equal(Notes["1"], await NotesOf("1", c));
        Assert.Equal(Notes["2"], await NotesOf("2", c));
        Assert.Equal(Notes[""], await NotesOf("", c));
        // a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
        var moved = await c.Send(HttpMethod.Patch, "/folders/2", "1", new JsonObject { ["parent_id"] = 1 });
        Assert.Equal(HttpStatusCode.OK, moved.StatusCode);
        // each request signed in again, so the answers alone can't tell: the pool's one connection, as the last request
        // left it, in a transaction nobody signs in to, holds no one (a sign-in that outlived its transaction would
        // still be ann's here)
        var pool = one.Services.GetRequiredService<NpgsqlDataSource>();
        await using var conn = await pool.OpenConnectionAsync();
        var who = await new NpgsqlCommand("SELECT current_setting('authz.user_id', true)", conn).ExecuteScalarAsync();
        Assert.True(who is DBNull || (string)who! == "", $"{who}");
        var e = await Assert.ThrowsAsync<PostgresException>(() => new NpgsqlCommand("SELECT count(*) FROM app.notes", conn).ExecuteScalarAsync());
        Assert.Equal("AZ701", Errors.Code(e));
    }

    // 5: concurrent requests never mix users
    [Fact]
    public async Task Check_5_concurrent_requests_never_mix_users()
    {
        string[] users = [.. Enumerable.Repeat(new[] { "1", "2", "3", "" }, 10).SelectMany(x => x)];
        var got = await Task.WhenAll(users.Select(u => NotesOf(u)));
        Assert.Equal(users.Select(u => Notes[u]), got);
    }

    // 6: a refused insert: 403, with the problem body naming the rule
    [Fact]
    public async Task Check_6_a_refused_insert_says_which_rule()
    {
        var r = await client.Send(HttpMethod.Post, "/notes", "2", new JsonObject { ["project_id"] = 3, ["body"] = "hi" });
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal("application/problem+json", r.Content.Headers.ContentType?.MediaType);
        var body = await r.Json();
        Assert.Equal("app.notes", (string?)body["table"]);
        Assert.Equal("insert", (string?)body["command"]);
        Assert.Equal("AZ709", (string?)body["code"]); // rowstile help AZ709
        Assert.Contains("user 2 may not insert this row into app.notes", (string)body["detail"]!, StringComparison.Ordinal);
        Assert.Contains(body["why"]!.AsArray(), line => ((string)line!).Contains("project.edit", StringComparison.Ordinal));
    }

    // 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
    [Fact]
    public async Task Check_7_hidden_is_404_and_not_allowed_is_403()
    {
        var hidden = await client.Send(HttpMethod.Patch, "/notes/1", "2", new JsonObject { ["body"] = "x" });
        var refused = await client.Send(HttpMethod.Patch, "/notes/1", "3", new JsonObject { ["body"] = "x" });
        var mine = await client.Send(HttpMethod.Patch, "/notes/4", "3", new JsonObject { ["body"] = "better idea" });
        var gone = await client.Send(HttpMethod.Delete, "/notes/2", "1");
        var no = await client.Send(HttpMethod.Delete, "/notes/1", "3");
        await hidden.IsProblem(Http.Problem("not-found", "Not Found", 404, "app.notes 1 not found"));
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        var said = await refused.Json();
        Assert.Equal("update", (string?)said["command"]);
        Assert.Contains(said["why"]!.AsArray(), line => ((string)line!).Contains("edit", StringComparison.Ordinal));
        // worded as the database words a refused insert: who, the command, the row, the table
        Assert.Equal("permission denied: user 3 may not update row 1 of app.notes", (string?)said["detail"]);
        Assert.Equal(HttpStatusCode.OK, mine.StatusCode);
        await gone.IsProblem(Http.Problem("not-found", "Not Found", 404, "app.notes 2 not found"));
        Assert.Equal(HttpStatusCode.Forbidden, no.StatusCode);
        var not = await no.Json();
        Assert.Equal("delete", (string?)not["command"]);
        Assert.NotEmpty(not["why"]!.AsArray());
        Assert.Equal("permission denied: user 3 may not delete row 1 of app.notes", (string?)not["detail"]);
    }

    // 7: ... and the SDK's own 404: cy's note in ann's project, which ann reads and which is in bo's project by the
    // time her update reaches the database. The app found the row: the 404 is the database's answer, asked in
    // SaveChanges' own transaction
    [Fact]
    public async Task Check_7_a_row_hidden_before_the_update_is_404()
    {
        using var scope = app.Services.CreateScope();
        var appDb = scope.ServiceProvider.GetRequiredService<AppDb>();
        try
        {
            using (Acting.As(Principal.User(1)))
            {
                var note = await appDb.Notes.SingleAsync(n => n.Id == 4);
                await Data.Sql(db.Owner, "UPDATE app.notes SET project_id = 2 WHERE id = 4"); // someone moves it meanwhile
                note.Body = "x";
                var e = await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => appDb.SaveChangesAsync());
                Assert.Equal(new Problem("https://rowstile.dev/problems/not-found", "Not Found", 404, "app.notes 4 not found"), Errors.ProblemOf(e));
            }
        }
        finally
        {
            await Data.Sql(db.Owner, "UPDATE app.notes SET project_id = 1 WHERE id = 4");
        }
    }

    // 8: an insert read back works when the select rule allows it, and is explained when not
    [Fact]
    public async Task Check_8_insert_then_read_back()
    {
        var ok = await client.Send(HttpMethod.Post, "/notes", "1", new JsonObject { ["project_id"] = 1, ["body"] = "new" });
        var unreadable = await client.Send(HttpMethod.Post, "/inbox", "1", new JsonObject { ["recipient_id"] = 2, ["body"] = "hi bo" });
        var quiet = await client.Send(HttpMethod.Post, "/inbox/quietly", "1", new JsonObject { ["recipient_id"] = 2, ["body"] = "hi bo" });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        Assert.True((long)(await ok.Json())["id"]! > 100);
        Assert.Equal(HttpStatusCode.Forbidden, unreadable.StatusCode);
        var said = await unreadable.Json();
        Assert.Equal("select", (string?)said["command"]);
        Assert.Contains("may not see the row as written", (string)said["detail"]!, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Accepted, quiet.StatusCode);
    }

    // 10: a background job signs in as a service principal
    [Fact]
    public async Task Check_10_a_job_acts_as_its_service()
    {
        using var scope = app.Services.CreateScope();
        var appDb = scope.ServiceProvider.GetRequiredService<AppDb>();
        using (Acting.As(Principal.User(3))) // whatever started it
        {
            var (projects, who) = await Jobs.Digest(appDb);
            Assert.Equal(new Principal("service", "1"), who);
            Assert.Equal(2, projects); // project 1 (it is added to) and the public one
            Assert.Equal(Principal.User(3), Acting.Current); // the job's principal ends with the job
        }
    }

    // ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)
    [Fact]
    public void Check_10_an_id_with_a_colon_is_a_users_not_a_service()
    {
        Assert.Equal(new Principal("user", "service:1"), Principal.User("service:1"));
        // what ToString() wrote, read back, for text the app wrote itself (a job's argument): every principal as itself,
        // a user whose id holds a colon or is "nobody" too
        string[] users = ["service:1", "nobody", "google-oauth2:117", "user:5", "a:b", ":", "(1,a:b)", "(1,2)", "", "42"];
        Principal[] every =
        [
            .. users.Select(Principal.User),
            Principal.Nobody,
            new("service", "1"),
            new("service", "3:4"),
            new("service", "(1,2)"),
        ];
        Assert.Equal(every, every.Select(p => Principal.Parse(p.ToString())));
        Assert.Equal(["user:service:1", "user:nobody", "42"], new[] { "service:1", "nobody", "42" }.Select(u => Principal.User(u).ToString()));
        Assert.Equal("service:1", new Principal("service", "1").ToString());
        Assert.Equal("nobody", Principal.Nobody.ToString());
        Assert.Equal(Principal.User("42"), Principal.Parse("42"));
    }

    // 13: the app refuses to start on a connection that skips row-level security
    [Fact]
    public async Task Check_13_refuses_a_connection_that_skips_rls()
    {
        await using var owner = new AppFactory(db.Owner, checkConnection: true);
        var e = Assert.Throws<ConnectionProblemException>(() => owner.CreateClient());
        Assert.Contains("an owner skips row-level security", e.Message, StringComparison.Ordinal);
        await using var fine = new AppFactory(db.App, checkConnection: true);
        using var started = fine.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await started.Send(HttpMethod.Get, "/projects")).StatusCode);
    }

    // queries by permission: set checks, and one call for a list's buttons
    [Fact]
    public async Task Queries_by_permission()
    {
        Assert.Equal("[1]", (await (await client.Send(HttpMethod.Get, "/projects/editable", "3")).Json()).ToJsonString());
        var buttons = await (await client.Send(HttpMethod.Get, "/projects/buttons", "3")).Json();
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"1": ["edit", "view"], "3": ["view"]}"""), buttons), buttons.ToJsonString());
    }

    // 16: a call the database turns down that is no refusal answers as its code's page says: what it names isn't there
    // (AZ708) 404, a missing or wrong argument (AZ710) 400, with the database's words
    [Fact]
    public async Task Check_16_not_there_is_404_and_a_wrong_argument_400()
    {
        var (key, _) = await AKeyOfAnns("ci", "");
        var page = await client.Send(HttpMethod.Get, "/projects/page?limit=1", "1");
        var negative = await client.Send(HttpMethod.Get, "/projects/page?limit=-1", "1");
        var cursor = await client.Send(HttpMethod.Get, "/projects/page?limit=1&after=x", "1");
        var others = await client.Send(HttpMethod.Delete, $"/keys/{key}", "2"); // bo's key it isn't
        var revoked = await client.Send(HttpMethod.Delete, $"/keys/{key}", "1");
        var again = await client.Send(HttpMethod.Delete, $"/keys/{key}", "1"); // revoked: there is none now
        Assert.Equal("[\"1\"]", (await page.Json()).ToJsonString());
        await negative.IsProblem(Http.Problem("bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)", "AZ710"));
        await cursor.IsProblem(Http.Problem("bad-argument", "Bad Request", 400, "the page cursor 'x' is not a project id", "AZ710"));
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
        // no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
        foreach (var r in new[] { others, again })
        {
            await r.IsProblem(Http.Problem("not-found", "Not Found", 404, $"no API key {key} of yours", "AZ708"));
        }
    }

    // 16: and the other codes the runtime raises, each as its page says (rowstile help AZ703 and the like): a login
    // refused or a call that needs someone signed in 401, a move inside itself 409, a refusal by the database's own
    // code 403; a share the policy doesn't declare, a name not in the policy and who is signed in changed by hand are
    // the app's mistakes, which stay errors (a 500)
    [Fact]
    public async Task Check_16_each_code_answers_as_its_page_says()
    {
        var (_, readOnly) = await AKeyOfAnns("ro", "read"); // a key of ann's that may only read
        var nobody = await client.Send(HttpMethod.Post, "/keys", body: new JsonObject { ["name"] = "k" });
        var asks = await client.Send(HttpMethod.Post, "/projects/1/requests", body: new JsonObject { ["relation"] = "member", ["reason"] = "the review" });
        var badKey = await client.Send(HttpMethod.Post, "/keys", "1", new JsonObject { ["name"] = "k" }, ("x-api-key", "ak_nope"));
        var scoped = await client.Send(HttpMethod.Post, "/keys", "1", new JsonObject { ["name"] = "k" }, ("x-api-key", readOnly));
        var made = await client.Send(HttpMethod.Post, "/keys", "1", new JsonObject { ["name"] = "k" });
        var notShared = await client.Send(HttpMethod.Get, "/projects/1/shares", "2");
        var inside = await client.Send(HttpMethod.Patch, "/folders/1", "1", new JsonObject { ["parent_id"] = 2 });
        var stays = await client.Send(HttpMethod.Patch, "/folders/2", "1", new JsonObject { ["parent_id"] = 1 });
        var service = await client.Send(HttpMethod.Post, "/keys", body: new JsonObject { ["name"] = "mine" }, headers: [("x-service", "1")]);
        var errors = new List<Exception>();
        foreach (var call in new Func<Task<HttpResponseMessage>>[]
        {
            () => client.Send(HttpMethod.Post, "/projects/1/requests", "2", new JsonObject { ["relation"] = "member", ["reason"] = "the review" }),
            () => client.Send(HttpMethod.Post, "/keys", "1", new JsonObject { ["name"] = "k", ["principal_type"] = "service", ["principal_id"] = "1" }),
            () => client.Send(HttpMethod.Get, "/notes/as/2", "1"),
        })
        {
            errors.Add(await Assert.ThrowsAsync<PostgresException>(call)); // the database's own error, not a problem
        }
        Assert.Equal(HttpStatusCode.Created, made.StatusCode);
        Assert.StartsWith("ak_", (string)(await made.Json())["key"]!, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, stays.StatusCode);
        await nobody.IsProblem(Http.Problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714"));
        await asks.IsProblem(Http.Problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714"));
        await badKey.IsProblem(Http.Problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703"));
        await inside.IsProblem(Http.Problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713"));
        // refusals, by the database's own code: 403, naming no rule
        foreach (var (r, detail, code) in new[] { (scoped, "this session is read-only", "AZ704"), (notShared, "you cannot see the shares of project 1", "AZ705") })
        {
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
            var got = await r.Json();
            Assert.Equal("https://rowstile.dev/problems/refused", (string?)got["type"]);
            Assert.Equal(code, (string?)got["code"]);
            Assert.StartsWith(detail, (string)got["detail"]!, StringComparison.Ordinal);
            Assert.Null(got["table"]);
            Assert.Null(got["command"]);
        }
        // a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
        var refused = Http.Problem("refused", "Forbidden", 403, "authz.create_api_key for oneself is for users, not services (service 1 is signed in)");
        refused["table"] = null;
        refused["command"] = null;
        refused["why"] = new JsonArray();
        refused["code"] = "AZ715";
        await service.IsProblem(refused);
        Assert.Equal(
            new (string?, string?)[] { ("AZ706", "P0001"), ("AZ707", "P0001"), ("AZ702", "28000") },
            errors.Select(e => (Errors.Code(e), Errors.SqlState(e)))
        );
        string[] words =
        [
            "the policy does not allow sharing project.member with a user",
            "the policy gives service no manage_keys permission, so nobody manages its keys",
            "who is signed in was changed after signing in",
        ];
        foreach (var (e, w) in errors.Zip(words))
        {
            Assert.Contains(w, e.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>An API key of ann's, made in one transaction: its id, and the key.</summary>
    private async Task<(long Id, string Key)> AKeyOfAnns(string name, string scopes)
    {
        await using var conn = new NpgsqlConnection(db.Owner);
        await conn.OpenAsync();
        await using var tx = await conn.BeginSignedInAsync(Principal.User(1));
        string key;
        await using (var made = new NpgsqlCommand("SELECT authz.create_api_key(@n, @s)", conn))
        {
            made.Parameters.AddWithValue("n", name);
            made.Parameters.AddWithValue("s", scopes);
            key = (string)(await made.ExecuteScalarAsync())!;
        }
        await using var last = new NpgsqlCommand("SELECT max(id) FROM authz.api_keys WHERE user_id = '1'", conn);
        var id = Convert.ToInt64(await last.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
        await tx.CommitAsync();
        return (id, key);
    }
}
