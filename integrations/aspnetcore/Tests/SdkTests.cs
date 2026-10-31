// The SDK's own calls, each way they can go, beyond the conformance checks (ConformanceTests.cs): what each promises,
// asked of the database where there is one to ask. test.sh measures what these and the conformance checks run of the
// SDK (sdk/dotnet), and fails unless they run every line and branch of it.
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Rowstile;
using Rowstile.AspNetCore;
using Rowstile.EntityFrameworkCore;
using Rowstile.Generated;
using Rowstile.Testing;

namespace Conformance.Tests;

[Collection("sdk")]
public sealed class SdkTests(SdkDatabase db) : IAsyncLifetime
{
    private const string Refused3 = "permission denied: user 3 may not update row 1 of app.notes"; // cy may edit note 4, not note 1

    public async ValueTask InitializeAsync() => await Data.Reset(db.Owner);

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private AppDb Context(Func<Principal?>? user = null, string? connection = null) =>
        new(new DbContextOptionsBuilder<AppDb>().UseNpgsql(connection ?? db.App).UseRowstile(user).Options);

    private static List<long> Notes(AppDb ctx) => [.. ctx.Notes.Select(n => n.Id).OrderBy(id => id)];

    // --- the core package: names, principals, keys, errors --------------------------------------------------------
    [Fact]
    public void Names_print_as_the_policy_writes_them()
    {
        Assert.Equal("note", Policy.Note.Type.ToString());
        Assert.Equal("note.edit", Policy.Note.Edit.ToString());
        Assert.Equal(new Permission(new ObjectType("note"), "edit"), Policy.Note.Edit);
        Assert.Equal(Principal.User("7"), Principal.User(7));
    }

    [Fact]
    public void A_key_is_spelled_as_the_database_writes_it()
    {
        // in a message: 7, (1,2), a field quoted only where Postgres would. One spelling, for 403 and 404
        object?[] keys = [7, new object?[] { 7 }, (1, 2), new object?[] { "a b", "x,y" }, ("", "q\"t"), ("b\\s", "(1)"), new object?[] { 1, null }, null];
        Assert.Equal(["7", "7", "(1,2)", "(\"a b\",\"x,y\")", "(\"\",\"q\"\"t\")", "(\"b\\\\s\",\"(1)\")", "(1,)", null], keys.Select(Keys.Text));
        Assert.Equal("app.members (1,2) not found", new NotFoundException("app.members", (1, 2)).Message);
        Assert.Equal(("app.members", "(1,2)"), (new NotFoundException("app.members", (1, 2)).Table, new NotFoundException("app.members", (1, 2)).Id));
        Assert.Equal(
            ["app.notes 7 not found", "app.notes not found", "row 7 not found", "not found"],
            new[] { new NotFoundException("app.notes", 7), new NotFoundException("app.notes"), new NotFoundException(id: 7), new NotFoundException() }.Select(e => e.Message)
        );
        var refused = Verdicts.Of(new RowAsked("app.members", "delete", (1, 2)), new RowAnswer(["no   delete : manage"], "service 3", "app.members"));
        Assert.Equal("permission denied: service 3 may not delete row (1,2) of app.members", refused.Message);
    }

    [Fact]
    public void A_verdict_is_what_the_answer_says()
    {
        var row = new RowAsked("notes", "update", 7);
        Assert.IsType<NotFoundException>(Verdicts.Of(row, new RowAnswer(null, "user 2", "app.notes"))); // not there for them
        Assert.IsType<NotFoundException>(Verdicts.Of(row, new RowAnswer(["yes  update : edit"], "user 2", "app.notes"))); // matched nothing else
        var refused = Assert.IsType<RefusedException>(Verdicts.Of(row, new RowAnswer(["no   update : edit"], "user 2", "app.notes")));
        Assert.Equal(("app.notes", "update", "AZ709"), (refused.Table, refused.Command, refused.Code));
        Assert.False(new RowAnswer([], "user 2", "app.notes").Allowed);
        var bare = new RefusedException("no");
        Assert.Equal(((string?)null, (string?)null, 0, "AZ709"), (bare.Table, bare.Command, bare.Why.Count, bare.Code));
        Assert.Equal("the app's database connection can't be used with rowstile: a; b", new ConnectionProblemException(["a", "b"]).Message);
    }

    private static PostgresException Raised(
        string sqlState,
        string message,
        string? hint = null,
        string? schema = null,
        string? table = null,
        string? constraint = null,
        string? detail = null
    ) => new(message, "ERROR", "ERROR", sqlState, detail: detail, hint: hint, schemaName: schema, tableName: table, constraintName: constraint);

    [Fact]
    public void The_code_is_what_rowstile_help_names()
    {
        // in the HINT, where the runtime puts it, or else in the message; an applying error's [AZ612] is no answer
        Assert.Equal("AZ612", Errors.Code(Raised("P0001", "no", hint: "rowstile help AZ612")));
        Assert.Equal("AZ612", Errors.Code(Raised("P0001", "no: rowstile help AZ612")));
        Assert.Null(Errors.Code(Raised("P0001", "a check said no [AZ612]")));
        Assert.Null(Errors.Code(new InvalidOperationException("not the database's")));
        Assert.Null(Errors.SqlState(new InvalidOperationException("not the database's")));
        Assert.Equal("42501", Errors.SqlState(new InvalidOperationException("around it", Raised("42501", "inside"))));
        // not signed in: SQLSTATE 28000 and AZ701 (or no code); a login refused and settings changed by hand share it
        Assert.True(Errors.IsNotSignedIn(Raised("28000", "who?", hint: "rowstile help AZ701")));
        Assert.True(Errors.IsNotSignedIn(Raised("28000", "who?")));
        Assert.False(Errors.IsNotSignedIn(Raised("28000", "invalid API key", hint: "rowstile help AZ703")));
        Assert.False(Errors.IsNotSignedIn(Raised("42501", "no", hint: "rowstile help AZ701")));
    }

    [Fact]
    public void A_refusal_has_the_databases_code_and_its_name_for_the_table()
    {
        Assert.Null(Errors.Refusal(new InvalidOperationException("not the database's")));
        Assert.Null(Errors.Refusal(Raised("23505", "duplicate key")));
        Assert.Null(Errors.Refusal(Raised("42501", "permission denied for table x"))); // the app role was never granted it
        Assert.Null(Errors.Refusal(Raised("42501", "sign in first", hint: "rowstile help AZ714"))); // a 401, no refusal
        var share = Errors.Refusal(Raised("42501", "you cannot share project 1", hint: "rowstile help AZ705"))!;
        Assert.Equal(("AZ705", (string?)null, (string?)null, 0), (share.Code, share.Table, share.Command, share.Why.Count));
        // a table without its schema, or a schema without a table: the table as it is said
        Assert.Equal("notes", Errors.Refusal(Raised("42501", "no", hint: "rowstile help AZ709", table: "notes", constraint: "other"))!.Table);
        var noTable = Errors.Refusal(Raised("42501", "no", hint: "rowstile help AZ709", schema: "app", constraint: "authz_update", detail: "a\nb"))!;
        Assert.Equal(((string?)null, "update", 2), (noTable.Table, noTable.Command, noTable.Why.Count));
    }

    [Fact]
    public void Problems_for_each_error()
    {
        Assert.Null(Errors.ProblemOf(new InvalidOperationException("not the database's")));
        Assert.Null(Errors.ProblemOf(Raised("23505", "duplicate key")));
        Assert.Null(Errors.ProblemOf(Raised("P0001", "the policy does not allow sharing", hint: "rowstile help AZ706"))); // the app's mistake
        Assert.Equal(403, Errors.ProblemOf(new RefusedException("no"))!.Status);
        var stale = new DbUpdateConcurrencyException("stale");
        Assert.Null(Stale.Why(stale));
        Assert.False(Stale.RulesAllow(stale));
        Stale.Record(stale, new RefusedException("no"));
        Assert.Equal(403, Errors.ProblemOf(stale)!.Status);
        Stale.Record(stale, new NotFoundException("app.notes", 1));
        Assert.Equal(404, Errors.ProblemOf(stale)!.Status);
        Stale.Record(stale, null);
        Assert.True(Stale.RulesAllow(stale));
        Assert.Equal(Problem.Conflict, Errors.ProblemOf(stale));
    }

    // --- Npgsql alone --------------------------------------------------------------------------------------------
    [Fact]
    public void Who_a_transaction_signs_in_as()
    {
        Assert.Equal(((string?)null, (string?)null), RowstileNpgsql.ActAsArgs());
        Assert.Equal(("service", "3"), RowstileNpgsql.ActAsArgs(new Principal("service", "3")));
        using (Acting.As(Principal.User(1)))
        {
            Assert.Equal(("user", "1"), RowstileNpgsql.ActAsArgs());
            Assert.Equal(((string?)null, (string?)null), RowstileNpgsql.ActAsArgs(Principal.Nobody)); // nobody, inside too
        }
        Assert.Equal(DBNull.Value, RowstileNpgsql.ActAsParameters()[0].Value);
    }

    [Fact]
    public async Task Npgsql_transactions_and_their_answers()
    {
        await using var conn = new NpgsqlConnection(db.App);
        await conn.OpenAsync();
        await using (var tx = await conn.BeginSignedInAsync(Principal.User(2)))
        {
            Assert.Equal([2L, 3L], await Ids(conn, "SELECT id FROM app.notes ORDER BY id"));
            Assert.True(await conn.CanAsync(Policy.Note.Edit, 2));
            Assert.False(await conn.CanAsync(Policy.Note.Edit, 3));
            var perms = await conn.PermsOfAsync(Policy.Project.Type, [1, 2]);
            Assert.Equal([Policy.Project.Edit, Policy.Project.View], perms["2"]);
            Assert.Empty(perms["1"]);
            Assert.Equal(1, await conn.ExpectAsync(await Run(conn, "UPDATE app.notes SET body = 'x' WHERE id = 2"), "app.notes", "update", 2));
            // hidden from bo
            await Assert.ThrowsAsync<NotFoundException>(async () => await conn.ExpectAsync(await Run(conn, "UPDATE app.notes SET body = 'x' WHERE id = 1"), "app.notes", "update", 1));
        }
        await using (var tx = await conn.BeginSignedInAsync(Principal.User(3)))
        {
            var e = await Assert.ThrowsAsync<RefusedException>(async () => await conn.ExpectAsync(await Run(conn, "UPDATE app.notes SET body = 'x' WHERE id = 1"), "app.notes", "update", 1));
            Assert.Equal(Refused3, e.Message);
            Assert.StartsWith("no", e.Why[0], StringComparison.Ordinal);
            // an UPDATE that matched nothing for another reason than access isn't a refusal; a table named without its
            // schema is found on the search_path, and named as the policy does
            await Run(conn, "SET LOCAL search_path = app");
            var other = await Assert.ThrowsAsync<NotFoundException>(async () => await conn.ExpectAsync(await Run(conn, "UPDATE notes SET body = 'x' WHERE id = 4 AND body = 'else'"), "notes", "update", 4));
            Assert.Equal("app.notes 4 not found", other.Message);
        }
        // signed in as whoever the code acts for
        using (Acting.As(new Principal("service", "1")))
        {
            await using var tx = await conn.BeginSignedInAsync();
            Assert.Equal([1L, 3L], await Ids(conn, "SELECT id FROM app.projects ORDER BY id"));
        }
    }

    [Fact]
    public async Task Postgres_own_refusals_name_the_rule()
    {
        await using var conn = new NpgsqlConnection(db.App);
        await conn.OpenAsync();
        // an upsert whose existing row cy may not update: the update rule
        await using (var tx = await conn.BeginSignedInAsync(Principal.User(3)))
        {
            var e = await Assert.ThrowsAsync<PostgresException>(() => Run(conn, "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') ON CONFLICT (id) DO UPDATE SET body = 'y'"));
            var upsert = Errors.Refusal(e)!;
            Assert.Equal(("notes", "update"), (upsert.Table, upsert.Command));
            Assert.Contains("ON CONFLICT DO UPDATE", upsert.Message, StringComparison.Ordinal);
        }
        // a MERGE that matched a row the update rule hides from cy
        await using (var tx = await conn.BeginSignedInAsync(Principal.User(3)))
        {
            var e = await Assert.ThrowsAsync<PostgresException>(() => Run(conn, "MERGE INTO app.notes t USING (SELECT 1 AS id) s ON t.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'"));
            var merge = Errors.Refusal(e)!;
            Assert.Equal(("notes", (string?)null), (merge.Table, merge.Command));
            Assert.Contains("MERGE matched a row", merge.Message, StringComparison.Ordinal);
        }
        // a 42501 that isn't a policy's (a table the app role was never granted) isn't one
        await using (var tx = await conn.BeginSignedInAsync(Principal.User(1)))
        {
            var e = await Assert.ThrowsAsync<PostgresException>(() => Run(conn, "SELECT * FROM public.\"__EFMigrationsHistory\""));
            Assert.Null(Errors.Refusal(e));
        }
    }

    [Fact]
    public async Task The_connection_check_and_the_test_databases()
    {
        await using (var owner = NpgsqlDataSource.Create(db.Owner))
        {
            var e = await Assert.ThrowsAsync<ConnectionProblemException>(() => owner.CheckAsync());
            Assert.Contains(e.Problems, p => p.Contains("an owner skips row-level security", StringComparison.Ordinal));
        }
        await using var app = NpgsqlDataSource.Create(db.App);
        await app.CheckAsync();
        await using var ctx = Context();
        Assert.Empty(await ctx.Database.ConnectionProblemsAsync());
        // another error than someone connected to the original is the database's, as it is
        var none = await Assert.ThrowsAsync<PostgresException>(() => TestDatabase.PerWorkerAsync(db.Owner.Replace("conf_tests_w2", "conf_none", StringComparison.Ordinal), "x"));
        Assert.Equal("3D000", none.SqlState);
    }

    // --- EF Core -----------------------------------------------------------------------------------------------------
    [Fact]
    public void A_context_signs_in_as_the_code_or_user_or_nobody()
    {
        using (var withUser = Context(() => Principal.User(2)))
        {
            Assert.Equal([2L, 3L], Notes(withUser)); // a query outside a transaction, as user()
            using (Acting.As(Principal.User(1)))
            {
                Assert.Equal([1L, 3L, 4L], Notes(withUser)); // whoever the code acts for comes first
            }
        }
        using (var nobody = Context(() => null))
        {
            Assert.Equal([3L], Notes(nobody));
        }
        using var plain = Context();
        Assert.Equal([3L], Notes(plain));
        // a transaction begun without awaiting signs in the same
        using (Acting.As(Principal.User(2)))
        using (var tx = plain.Database.BeginTransaction())
        {
            Assert.Equal([2L, 3L], Notes(plain));
            Assert.Equal(0, plain.Notes.Where(n => n.Id == 1).ExecuteDelete()); // hidden: nothing deleted
            tx.Commit();
        }
        using (Acting.As(Principal.User(1)))
        {
            Assert.Equal(0, plain.Notes.Where(n => n.Id == 2).ExecuteDelete()); // outside one, too
        }
    }

    [Fact]
    public async Task A_scalar_is_the_apps_statements_value()
    {
        await using var ctx = Context(() => Principal.User(1));
        var raw = ctx.GetService<IRawSqlCommandBuilder>();
        RelationalCommandParameterObject Of() => new(ctx.GetService<IRelationalConnection>(), null, null, ctx, ctx.GetService<IRelationalCommandDiagnosticsLogger>());
        var count = raw.Build("SELECT count(*) FROM app.notes");
        var none = raw.Build("SELECT 1 WHERE false");
        Assert.Equal(3L, count.ExecuteScalar(Of()));
        Assert.Equal(3L, await count.ExecuteScalarAsync(Of()));
        Assert.Null(none.ExecuteScalar(Of()));
        Assert.Null(await none.ExecuteScalarAsync(Of()));
        await using var tx = await ctx.Database.BeginTransactionAsync();
        Assert.Equal(3L, count.ExecuteScalar(Of()));
        Assert.Equal(3L, await count.ExecuteScalarAsync(Of()));
    }

    [Fact]
    public void SaveChanges_without_awaiting_is_asked_about_too()
    {
        using (Acting.As(Principal.User(3)))
        {
            using var ctx = Context();
            var mine = ctx.Notes.Single(n => n.Id == 4);
            mine.Body = "better";
            Assert.Equal(1, ctx.SaveChanges()); // in the SDK's transaction, committed
            var other = ctx.Notes.Single(n => n.Id == 1);
            other.Body = "x";
            var e = Assert.Throws<DbUpdateConcurrencyException>(() => ctx.SaveChanges());
            Assert.Equal(Refused3, Stale.Why(e)!.Message);
            ctx.ChangeTracker.Clear();
            ctx.Notes.Add(new Note { ProjectId = 2, AuthorId = 3, Body = "hi" }); // bo's project: refused
            var insert = Assert.Throws<DbUpdateException>(() => ctx.SaveChanges());
            Assert.Equal("insert", Errors.Refusal(insert)!.Command);
            ctx.ChangeTracker.Clear();
            // in the app's own transaction: it commits it, and a failure leaves it to the app
            using (var tx = ctx.Database.BeginTransaction())
            {
                ctx.Notes.Single(n => n.Id == 4).Body = "again";
                Assert.Equal(1, ctx.SaveChanges());
                ctx.Notes.Single(n => n.Id == 1).Body = "y";
                Assert.IsType<RefusedException>(Stale.Why(Assert.Throws<DbUpdateConcurrencyException>(() => ctx.SaveChanges())));
                tx.Rollback();
            }
            // a rollback to a savepoint SaveChanges didn't make asks nothing
            using var fresh = Context();
            using var own = fresh.Database.BeginTransaction();
            own.CreateSavepoint("mine");
            own.RollbackToSavepoint("mine");
        }
    }

    [Fact]
    public async Task SaveChanges_answers_each_way_a_write_can_match_nothing()
    {
        using (Acting.As(Principal.User(3)))
        {
            // the rules allow it, and the note changed since it was read (its xmin): 409
            await using (var ctx = Context())
            {
                var mine = await ctx.Notes.SingleAsync(n => n.Id == 4);
                await Data.Sql(db.Owner, "UPDATE app.notes SET body = 'changed' WHERE id = 4");
                mine.Body = "mine";
                var e = await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => ctx.SaveChangesAsync());
                Assert.True(Stale.RulesAllow(e));
                Assert.Equal(409, Errors.ProblemOf(e)!.Status);
            }
            // an ORM delete the rules refuse: the delete rule
            await using (var ctx = Context())
            {
                ctx.Notes.Remove(await ctx.Notes.SingleAsync(n => n.Id == 1));
                var e = await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => ctx.SaveChangesAsync());
                Assert.Equal("permission denied: user 3 may not delete row 1 of app.notes", Stale.Why(e)!.Message);
            }
            // in the app's own transaction, which it commits
            await using (var ctx = Context())
            {
                await using var tx = await ctx.Database.BeginTransactionAsync();
                (await ctx.Notes.SingleAsync(n => n.Id == 4)).Body = "again";
                Assert.Equal(1, await ctx.SaveChangesAsync());
                (await ctx.Notes.SingleAsync(n => n.Id == 1)).Body = "y";
                Assert.IsType<RefusedException>(Stale.Why(await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => ctx.SaveChangesAsync())));
                await tx.CommitAsync();
                await using var fresh = Context();
                await using var own = await fresh.Database.BeginTransactionAsync();
                await own.CreateSavepointAsync("mine");
                await own.RollbackToSavepointAsync("mine");
            }
        }
    }

    [Fact]
    public async Task A_write_the_database_cannot_be_asked_about_stays_ef_cores()
    {
        await Data.Sql(db.Owner, "CREATE TABLE app.scratch (id bigint PRIMARY KEY, name text NOT NULL); INSERT INTO app.scratch VALUES (1, 'a'); GRANT SELECT, UPDATE ON app.scratch TO conf_app");
        try
        {
            using (Acting.As(Principal.User(1)))
            {
                await using var ctx = new ScratchDb(new DbContextOptionsBuilder<ScratchDb>().UseNpgsql(db.App).UseRowstile().Options);
                var row = await ctx.Rows.SingleAsync();
                await Data.Sql(db.Owner, "UPDATE app.scratch SET name = 'b'");
                row.Name = "c";
                // the policy has no rules for the table (AZ707, when asked): the error is EF Core's, without an answer
                var e = await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => ctx.SaveChangesAsync());
                Assert.Null(Errors.ProblemOf(e));
                Assert.Equal("c", row.Name);
            }
        }
        finally
        {
            await Data.Sql(db.Owner, "DROP TABLE app.scratch");
        }
    }

    [Fact]
    public async Task The_runtimes_answers_on_a_contexts_connection()
    {
        using (Acting.As(Principal.User(3)))
        {
            await using var ctx = Context();
            Assert.Equal(["1", "3"], await ctx.Database.TextIds(Policy.Project.View).OrderBy(x => x).ToListAsync());
            Assert.True(await ctx.Database.CanAsync(Policy.Note.Edit, 4));
            Assert.Equal(1, await ctx.Database.ExpectAsync(1, "app.notes", "update", 4));
            await using var tx = await ctx.Database.BeginTransactionAsync();
            Assert.False(await ctx.Database.CanAsync(Policy.Note.Edit, 1)); // in the transaction open
            int changed = await ctx.Notes.Where(n => n.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(n => n.Body, "x"));
            var e = await Assert.ThrowsAsync<RefusedException>(() => ctx.Database.ExpectAsync(changed, "app.notes", "update", 1));
            Assert.Equal(Refused3, e.Message);
        }
    }

    [Fact]
    public async Task A_transaction_is_one_principals()
    {
        static string Said(string who) =>
            "this transaction is signed in as user 1 already, and a sign-in lasts the database transaction: " + who
            + "'s work can't run inside it. Run it after, or in a transaction of its own (another connection)";
        var service1 = Said("service 1");
        await using var ctx = Context();
        using (Acting.As(Principal.User(1)))
        {
            await using var tx = await ctx.Database.BeginTransactionAsync();
            var note = await ctx.Notes.SingleAsync(n => n.Id == 1);
            note.Body = "ann's";
            // the same user's work goes on in it, as it is
            using (Acting.As(Principal.User(1)))
            {
                Assert.Equal([1L, 3L, 4L], Notes(ctx));
            }
            // anyone else's is refused before anything is sent for it: a query, a write, SaveChanges, the runtime's calls
            using (Acting.As(new Principal("service", "1")))
            {
                Assert.Equal(service1, Assert.Throws<InvalidOperationException>(() => Notes(ctx)).Message);
                Assert.Equal(service1, (await Assert.ThrowsAsync<InvalidOperationException>(() => ctx.Notes.CountAsync())).Message);
                await Assert.ThrowsAsync<InvalidOperationException>(() => ctx.Notes.Where(n => n.Id == 3).ExecuteUpdateAsync(s => s.SetProperty(n => n.Body, "the job's")));
                Assert.Equal(service1, Assert.Throws<InvalidOperationException>(() => ctx.SaveChanges()).Message);
                Assert.Equal(service1, (await Assert.ThrowsAsync<InvalidOperationException>(() => ctx.SaveChangesAsync())).Message);
                await Assert.ThrowsAsync<InvalidOperationException>(() => ctx.Database.CanAsync(Policy.Note.Edit, 1));
            }
            using (Acting.As(Principal.User(2)))
            {
                Assert.Equal(Said("user 2"), Assert.Throws<InvalidOperationException>(() => Notes(ctx)).Message);
            }
            using (Acting.As(Principal.Nobody))
            {
                Assert.Equal(Said("nobody"), Assert.Throws<InvalidOperationException>(() => ctx.Notes.Count()).Message);
            }
            // the transaction goes on as ann's: it reads and writes as hers, and commits
            Assert.Equal("1", await ctx.Database.SqlQuery<string>($"SELECT current_setting('authz.user_id', true) AS \"Value\"").SingleAsync());
            Assert.Equal(1, await ctx.SaveChangesAsync());
            await tx.CommitAsync();
        }
        Assert.Equal(["ann's", "hello"], await Data.Bodies(db.Owner, [1, 3])); // nothing of the job's was sent
        // a transaction of its own, after it, is the other's
        using (Acting.As(new Principal("service", "1")))
        {
            Assert.Equal(2, await ctx.Projects.CountAsync());
        }
        // a transaction the app brought (UseTransaction) is the app's to sign in: the SDK doesn't check it
        await using var conn = new NpgsqlConnection(db.App);
        await conn.OpenAsync();
        await using var bos = await conn.BeginSignedInAsync(Principal.User(2));
        await using var brought = new AppDb(new DbContextOptionsBuilder<AppDb>().UseNpgsql(conn).UseRowstile().Options);
        await brought.Database.UseTransactionAsync(bos);
        await using var again = new AppDb(new DbContextOptionsBuilder<AppDb>().UseNpgsql(conn).UseRowstile().Options);
        again.Database.UseTransaction(bos);
        using (Acting.As(Principal.User(1)))
        {
            Assert.Equal([2L, 3L], Notes(brought));
            Assert.Equal([2L, 3L], Notes(again));
        }
    }

    [Fact]
    public async Task A_refused_write_says_why_on_the_connections_the_sdk_builds()
    {
        const string Insert = "INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')"; // bo, ann's project
        // test.sh's connection strings don't ask Npgsql for the database's DETAIL, where the reasons are
        Assert.False(new NpgsqlConnectionStringBuilder(db.App).IncludeErrorDetail);
        async Task<string?> Detail(NpgsqlDataSource dataSource)
        {
            await using var conn = await dataSource.OpenConnectionAsync();
            await using var tx = await conn.BeginSignedInAsync(Principal.User(2));
            return Assert.IsType<PostgresException>(await Record.ExceptionAsync(() => Run(conn, Insert))).Detail;
        }
        // the data source AddRowstile builds from a connection string turns it on
        await using (var services = new ServiceCollection().AddRowstile(o => o.ConnectionString = db.App).BuildServiceProvider())
        {
            Assert.Contains("project.edit", await Detail(services.GetRequiredService<NpgsqlDataSource>()), StringComparison.Ordinal);
        }
        // and so does UseRowstile, on a context's connection string
        using (Acting.As(Principal.User(2)))
        {
            await using var ctx = Context();
            ctx.Notes.Add(new Note { ProjectId = 3, AuthorId = 2, Body = "hi" });
            var e = await Assert.ThrowsAsync<DbUpdateException>(() => ctx.SaveChangesAsync());
            Assert.Contains(Errors.Refusal(e)!.Why, line => line.Contains("project.edit", StringComparison.Ordinal));
        }
        // a data source the app built itself is its own: the SDK leaves it as it was built
        await using var own = NpgsqlDataSource.Create(db.App);
        Assert.DoesNotContain("project.edit", await Detail(own), StringComparison.Ordinal);
    }

    // --- ASP.NET Core ------------------------------------------------------------------------------------------------
    private static async Task<WebApplication> Host(Action<WebApplicationBuilder> services, Action<WebApplication> routes)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        services(builder);
        var app = builder.Build();
        app.UseRowstile();
        routes(app);
        await app.StartAsync();
        return app;
    }

    [Fact]
    public async Task Requests_without_a_user_act_for_whoever_the_code_says()
    {
        await using var app = await Host(
            b =>
            {
                b.Services.AddSingleton(_ => NpgsqlDataSource.Create(db.App)); // checked at start: the app role's
                b.Services.AddRowstile();
            },
            a => a.MapGet("/who", () => Acting.Current?.ToString() ?? "unset")
        );
        using var client = app.GetTestClient();
        Assert.Equal("unset", await client.GetStringAsync(new Uri("/who", UriKind.Relative)));
        await app.StopAsync();
    }

    [Fact]
    public async Task A_problem_after_the_response_began_is_the_servers_error()
    {
        await using var app = await Host(
            b => b.Services.AddRowstile(o => o.CheckConnection = false),
            a => a.MapGet(
                "/late",
                async (HttpContext c) =>
                {
                    await c.Response.WriteAsync("begun");
                    await c.Response.Body.FlushAsync();
                    throw new RefusedException("too late");
                }
            )
        );
        using var client = app.GetTestClient();
        var e = await Assert.ThrowsAnyAsync<Exception>(async () => await (await client.GetAsync(new Uri("/late", UriKind.Relative))).Content.ReadAsStringAsync());
        Assert.Contains("too late", e.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_context_without_the_sign_in_is_the_apps_bug_and_says_so()
    {
        await using var app = await Host(
            b =>
            {
                b.Services.AddDbContext<AppDb>(o => o.UseNpgsql(db.App)); // no UseRowstile()
                b.Services.AddRowstile(o => o.CheckConnection = false);
            },
            a => a.MapGet("/notes", async (AppDb ctx) => (await ctx.Notes.ToListAsync()).Count)
        );
        using var client = app.GetTestClient();
        var e = await Assert.ThrowsAsync<NotSignedInException>(() => client.GetAsync(new Uri("/notes", UriKind.Relative)));
        Assert.Contains("UseRowstile()", e.Message, StringComparison.Ordinal);
        Assert.Equal("AZ701", Errors.Code(e));
    }

    [Fact]
    public async Task The_check_takes_the_connections_it_is_given()
    {
        var e = await Assert.ThrowsAsync<ConnectionProblemException>(
            () => Host(b => b.Services.AddRowstile(o => o.DataSource = _ => NpgsqlDataSource.Create(db.Owner)), _ => { })
        );
        Assert.Contains("an owner skips row-level security", e.Message, StringComparison.Ordinal);
    }

    private static async Task<int> Run(NpgsqlConnection conn, string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        return await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<List<long>> Ids(NpgsqlConnection conn, string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        var ids = new List<long>();
        while (await reader.ReadAsync())
        {
            ids.Add(reader.GetInt64(0));
        }
        return ids;
    }
}

/// <summary>A table the policy has no rules for, with a concurrency token.</summary>
public sealed class ScratchDb(DbContextOptions<ScratchDb> options) : DbContext(options)
{
    public DbSet<ScratchRow> Rows => Set<ScratchRow>();
}

[Table("scratch", Schema = "app")]
public sealed class ScratchRow
{
    [Column("id")]
    public long Id { get; set; }

    [Column("name")]
    public required string Name { get; set; }

    [Timestamp]
    public uint Version { get; set; }
}
