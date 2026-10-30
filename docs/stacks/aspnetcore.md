# ASP.NET Core and EF Core (preview)

<!-- tested: every line of code below is in integrations/aspnetcore (tests/unit_test.py checks it) -->

**Preview**: the .NET SDK may change in any release, and is not part of what 1.0 will freeze. It passes the same
conformance checks as the Python and TypeScript SDKs, in CI, on PostgreSQL 16, 17 and 18 and through PgBouncer.

An ASP.NET Core app on EF Core and Npgsql, whose migrations are EF Core's. The endpoints check nothing: each
request's transactions sign in as its user, the database filters what they read and refuses what they may not
write, and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from `integrations/aspnetcore`, the conformance suite: a minimal API app, and the checks
every supported stack passes (`integrations/aspnetcore/test.sh`). .NET 10.

## Install

```sh
dotnet add package Rowstile.EntityFrameworkCore --prerelease
dotnet add package Rowstile.AspNetCore --prerelease
pip install --pre rowstile      # the command; or npm install --save-dev rowstile@next, or its Docker image
rowstile init                   # a first policy from your tables, a test file, rowstile.toml
```

`Rowstile.EntityFrameworkCore` brings `Rowstile`, the base, which works on Npgsql alone too
([Without EF Core](#without-ef-core)). The command installs as [Installing](../installing.md) says: it is
Python, and needs no .NET. The conformance app's `rowstile.toml`:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
csharp = "App/Authz.g.cs"
[migrations]
tool = "efcore"
dir  = "App/Migrations"
```

Two roles connect. The owner of the tables runs the migrations (`ROWSTILE_OWNER_DSN` for the command, a URL,
and the same as an Npgsql connection string, `ROWSTILE_OWNER_CONN`, for `dotnet ef`), and the app connects as the
role the policy names (`app role conf_app`), which row-level security applies to (`ROWSTILE_APP_CONN`). The owner
must be able to switch to the app role, since the command looks at the data as the app does when it runs the
policy's tests: `GRANT conf_app TO conf_owner`, once, by whoever made the app role.

A refused insert's reasons are in the database's DETAIL, which Npgsql hides unless the connection string says
`Include Error Detail=true`. The SDK turns it on where it builds the app's connections: the data source
`AddRowstile` builds from `o.ConnectionString`, and a context's connection string (`UseNpgsql(connectionString)`
before `UseRowstile()`). A data source or a connection you build yourself is yours, and the SDK leaves it as it
is: put `Include Error Detail=true` in its connection string. (It shows the DETAIL of every error, the values in a
unique key's error too: the SDK doesn't turn it on behind an app that built its own without it.)

## The policy

```authz
app role conf_app

type user = app.users

type service = app.services principal

type project = app.projects
  owner   : user    = owner_id
  member  : user    = app.members(project_id -> user_id)
  service : service = app.project_services(project_id -> service_id)

  can edit = owner or member
  can view = edit or service or {public}

type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.owner
  can view = project.view

rules app.notes
  select : view
  insert : project.edit and author
  update : edit
  delete : edit
```

## The app

`UseRowstile()` on the context's options signs in every transaction the context begins (SaveChanges' own, and
the app's, `BeginTransactionAsync`), and every command outside a transaction (a query, an `ExecuteDeleteAsync`),
as whoever the code acts for. `AddRowstile` builds the `NpgsqlDataSource` the services hold, from
`o.ConnectionString`, and says who a request acts for, and `UseRowstile()` on the app runs it for each request:
`User(context)` returns a `Principal`, or null for nobody, who sees only what `anyone` may. It also refuses to
start on a connection that skips row-level security (that data source, unless `o.DataSource` gives another).

Here `User` is `Auth.SessionUser`, the app's own: yours reads `context.User`, once your authentication ran. The
conformance app has no sign-in, so its `Auth.cs` stands in for one: it takes the user from a header its checks
set, which a real app must never believe. That is why this page doesn't show it.

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRowstile(o =>
{
    o.ConnectionString = builder.Configuration["ROWSTILE_APP_CONN"];
    o.User = Auth.SessionUser;
});
builder.Services.AddDbContext<AppDb>((services, o) => o.UseNpgsql(services.GetRequiredService<NpgsqlDataSource>()).UseRowstile());
var app = builder.Build();
app.UseRowstile();
```

Then endpoints are plain EF Core. A list shows only the user's rows:

```csharp
app.MapGet("/notes", async (AppDb db) => await db.Notes.Select(n => n.Id).OrderBy(id => id).ToListAsync());
```

An update the rules refuse changes no row, and EF Core throws `DbUpdateConcurrencyException`. SaveChanges runs in
a transaction (the SDK's, when the app has none open), and EF Core sends its writes after a savepoint: just before
it rolls back to it, the SDK asks the database why, in that transaction and as the same user, so it sees what
SaveChanges wrote. The middleware answers 403 with the rule and the reason, or 404 when the user can't see the
row. When the rules allow the change, the row changed since it was read (a concurrency token: the conformance
app's notes have Postgres's `xmin`, `[Timestamp] public uint Version`), and the answer is 409:

```csharp
        var note = await db.Notes.FindAsync(noteId) ?? throw new NotFoundException("app.notes", noteId);
        note.Body = b.Body;
        await db.SaveChangesAsync(); // an update the rules may refuse: 403 with the reason
```

An ORM delete (`db.Notes.Remove(note)`) is answered the same way. An `ExecuteUpdateAsync` or `ExecuteDeleteAsync`
reports 0 rows without an error; `ExpectAsync` turns that into the same answers (404 too when the user may change
the row and the statement matched nothing for another reason, such as a `Where` with more than the key):

```csharp
        int deleted = await db.Notes.Where(n => n.Id == noteId).ExecuteDeleteAsync();
        await db.Database.ExpectAsync(deleted, "app.notes", "delete", noteId);
```

An insert that reads the new row back (SaveChanges uses `RETURNING` for a generated key) also needs the select
rule: if the user may insert but not read the row, the 403 names the select rule.

A call the database says names something that isn't there answers 404 (an API key of the user's that isn't there,
a share with someone who doesn't exist), and one it says lacks an argument or has a wrong one 400, each with the
database's words (a negative page size: "the page size must not be negative (got -1)"):

```csharp
        await db.Database.SqlQuery<string>(
            $"SELECT x AS \"Value\" FROM authz.list('project', 'view', CAST({after} AS text), {limit}) x"
        ).ToListAsync()
```

A call that needs someone signed in, from a visitor who isn't (an access request, an API key), answers 401, and so
does a login with a key or a token the database refuses; a folder moved into one of its own subfolders answers 409.
Each code's page says what its answer is (`rowstile help AZ714`). The app's own mistakes stay errors, a 500: a share
the policy doesn't declare (AZ706), a name not in the policy (AZ707), who is signed in changed by hand (AZ702).
`Errors.ProblemOf(e)` gives the same answers anywhere else: the problem body, or null.

## Lists by permission

`db.Database.Ids(permission)` filters a query to the objects the user holds a permission on (a set check, which
Postgres runs once for the query); `PermsOfAsync` answers a list's buttons in one call. Both take only the policy's
names, from the generated client (`rowstile client csharp`, here `App/Authz.g.cs`), so a misspelled type or
permission doesn't compile:

```csharp
using Rowstile.Generated;

        await db.Projects.Where(p => db.Database.Ids(Policy.Project.Edit).Contains(p.Id)).Select(p => p.Id).OrderBy(id => id).ToListAsync()

        var ids = await db.Projects.Select(p => p.Id).ToListAsync();
        var perms = await db.Database.PermsOfAsync(Policy.Project.Type, ids.Cast<object>());
```

`Ids` is for a key that is a bigint; `TextIds` gives any other as text. `db.Database.CanAsync(Policy.Note.Edit, 4)`
asks about one object.

## Background jobs

A job acts for a principal of its own, whatever request started it (`type service = app.services principal` in
the policy):

```csharp
    public static Task<(int Projects, Principal? Who)> Digest(AppDb db) =>
        Acting.Job(new Principal("service", "1"), async () => (await db.Projects.CountAsync(), Acting.Current));
```

Anywhere else, `using (Acting.As(Principal.User(2)))` signs in the transactions inside it. An id is always a
user's, whatever it holds: `Principal.User("service:1")` is the user with that id.

A sign-in lasts the database transaction, so a transaction is one principal's. Inside one a context began, a
query, a write, `SaveChanges` or a call such as `CanAsync` runs as it is while the code acts for the principal it
signed in as. For anyone else, or for nobody, it throws an `InvalidOperationException` before anything is sent for
it, and the transaction goes on as it was. Run a job after the request's transaction, or in a transaction of its
own (a context of its own, on another connection). A transaction the app brings to a context (`UseTransaction`) is
the app's to sign in, and the SDK doesn't check it.

## Migrations

The policy ships as EF Core migrations. `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`), a migration class and its `.Designer.cs` after the folder's others, and `dotnet ef database
update` applies it with the others. The class runs the policy's SQL in one statement (a `DO` block: Npgsql splits
a command at each semicolon it sees, and a function written `BEGIN ATOMIC ... END` has some inside it), in the
migration's transaction. Its `.Designer.cs` builds the model the folder's snapshot holds, since the policy changes
nothing EF Core models: `dotnet ef migrations has-pending-model-changes` shows no change, and a migration you add
later starts from the same model. Its `Down` throws: a policy migration isn't undone, the next one changes the
policy back. The first EF Core migration, the one that makes the tables, comes first: `rowstile migrate` reads the
snapshot it makes, `*ModelSnapshot.cs`, for the context's name.

`dotnet ef` connects as the owner, through a design-time factory, and without `UseRowstile()`, since the first
migration runs before rowstile's functions exist:

```csharp
public sealed class AppDbFactory : IDesignTimeDbContextFactory<AppDb>
{
    public AppDb CreateDbContext(string[] args)
    {
        var owner = Environment.GetEnvironmentVariable("ROWSTILE_OWNER_CONN") ?? "Host=localhost;Database=conf";
        return new AppDb(new DbContextOptionsBuilder<AppDb>().UseNpgsql(owner).Options);
```

```sh
rowstile migrate                    # after changing the policy
dotnet ef database update
rowstile migrate --check            # in CI: exit 1 if a policy change has no migration
```

Don't migrate when the app starts (`Database.Migrate()`): the app connects as the app role, which may not change
the schema. While you edit, `rowstile dev` checks, pushes to the development database, runs the tests and rewrites
`App/Authz.g.cs` on every save (and writes the migration once you stop editing). The development database then
holds what `dev` pushed: a migration that brings what it holds already stops with AZ607. EF Core has no command to
mark a migration applied: insert its id into `__EFMigrationsHistory`, or make the database again from the
migrations.

## Tests

The policy's own tests run with `rowstile test`. In xUnit, `TestDatabase.PerWorkerAsync` copies the migrated test
database once for each test collection (xUnit runs collections side by side), so tests that write don't meet each
other. A collection fixture, as the conformance suite has one:

```csharp
public abstract class Database : IAsyncLifetime
{
    public WorkerDatabase Copy { get; private set; } = null!;
            Copy = await TestDatabase.PerWorkerAsync(Env.Tests, Worker, Env.App);
```

It returns the copy's connection string, and the app role's for it. The copy needs nobody connected to the
original: give the original's connection string `Pooling=false` where a test reads it. Then sign in the way the app
does:

```csharp
            using (Acting.As(Principal.User(1)))
```

## Without EF Core

On Npgsql alone, `BeginSignedInAsync` begins a transaction signed in as someone (left out: whoever the code acts
for), and `ExpectAsync` answers an UPDATE or DELETE that changed nothing; the middleware answers their errors the
same way:

```csharp
        await using (var tx = await conn.BeginSignedInAsync(Principal.User(2)))
            Assert.Equal(1, await conn.ExpectAsync(await Run(conn, "UPDATE app.notes SET body = 'x' WHERE id = 2"), "app.notes", "update", 2));
```

At start-up, `await dataSource.CheckAsync()` throws `ConnectionProblemException` on a connection that skips
row-level security (a superuser, BYPASSRLS, the tables' owner); `AddRowstile` does it for you.
