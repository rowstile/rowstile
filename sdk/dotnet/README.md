# rowstile for .NET (preview)

**Preview**: these packages may change in any release, and are not part of what 1.0 will freeze. They run the
same conformance checks as the Python and TypeScript SDKs, in CI (`integrations/aspnetcore`).

The SDK for .NET apps on a rowstile policy: every transaction signs in as whoever the request or the job acts
for, refused writes become a 403 with the database's reason, rows the user can't see a 404, and the app refuses
to start on a connection that skips row-level security. It holds no rowstile logic: it calls the `authz.*`
functions the policy made, and translates their answers. .NET 10, PostgreSQL through Npgsql.

| package | what |
|---|---|
| `Rowstile` | `Acting.As(who)`, `Acting.Job(who, ...)`, `Principal`, `RefusedException`, `NotFoundException`, `NotSignedInException`, `ConnectionProblemException`, `Errors` (`Refusal(e)`, `Code(e)`: rowstile's code for any database error, `Database(e)` and `SqlState(e)`: the `PostgresException` inside, and its SQLSTATE, `IsNotSignedIn(e)`, `ProblemOf(e)`: the problem body and status each error answers with), `Problem`, `Stale` (what the database said of an ORM write that matched no row); on Npgsql alone, `BeginSignedInAsync`, `SignInAsync`, `ExpectAsync`, `CanAsync`, `PermsOfAsync`, `CheckAsync` (the start-up check), `ConnectionProblemsAsync` (what the check finds); `ObjectType` and `Permission`, which the generated names are (`rowstile client csharp`); `Rowstile.Testing.TestDatabase`: a copy of the migrated test database for each test collection |
| `Rowstile.EntityFrameworkCore` | `UseRowstile()` on a context's options: every transaction and every command outside one signs in (a transaction is one principal's: inside one, work for someone else throws `InvalidOperationException` before anything is sent), and an update or delete SaveChanges sends that matches no row is asked about (403, 404, or 409 when the row changed since it was read); `Database.Ids(permission)` to filter a query (`TextIds` for a key that isn't a bigint), `PermsOfAsync`, `CanAsync`, `ExpectAsync` for `ExecuteUpdate` and `ExecuteDelete`, `ConnectionProblemsAsync` |
| `Rowstile.AspNetCore` | `AddRowstile(o => o.User = ...)` and `UseRowstile()`: the data source, from `o.ConnectionString`, with `Include Error Detail` on; each request acts for its user, and the database's answers become problem bodies with the statuses the other SDKs send; the start-up check |

Not on NuGet yet: pack it from the repository, then add it from that folder.

```sh
git clone https://github.com/rowstile/rowstile && dotnet pack rowstile/sdk/dotnet/Rowstile.slnx -o rowstile-feed
dotnet nuget add source "$PWD/rowstile-feed" --name rowstile
dotnet add package Rowstile.EntityFrameworkCore --prerelease
dotnet add package Rowstile.AspNetCore --prerelease
```

The page for the stack: [ASP.NET Core and EF Core](../../docs/stacks/aspnetcore.md). Npgsql hides the database's
DETAIL, where a refused insert's reasons are, unless the connection string says `Include Error Detail=true`: the
SDK turns it on where it builds the connections (`AddRowstile(o => o.ConnectionString = ...)`, and a context's
connection string before `UseRowstile()`). A data source or a connection the app builds itself keeps what it was
built with, and so does a named connection string (`Name=...`), which EF Core reads from the configuration.

`Version.props` holds the version every package carries (`packaging/version.py` sets it). Build and pack:
`dotnet pack sdk/dotnet/Rowstile.slnx -o out`.
