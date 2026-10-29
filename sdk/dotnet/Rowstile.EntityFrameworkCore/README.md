# Rowstile.EntityFrameworkCore (preview)

**Preview**: it may change in any release, and is not part of what 1.0 will freeze.

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is rowstile for EF Core on Npgsql: `UseRowstile()` on a context's options signs every transaction, and every command outside one, in as whoever the code acts for; an update or delete SaveChanges sends that matches no row is asked about, in its transaction, and answered: hidden (404), refused with the reason (403), or changed since it was read (409). `Database.Ids(Policy.Project.Edit)` filters a query to what the user holds a permission on. It holds no rowstile logic: it calls the `authz.*` functions the policy made, and translates their
answers.

```sh
dotnet add package Rowstile.EntityFrameworkCore --prerelease
```

How to use it with ASP.NET Core and EF Core: https://rowstile.dev/stacks/aspnetcore
