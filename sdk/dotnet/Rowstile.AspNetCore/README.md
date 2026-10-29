# Rowstile.AspNetCore (preview)

**Preview**: it may change in any release, and is not part of what 1.0 will freeze.

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is rowstile for ASP.NET Core: `AddRowstile(o => o.User = ...)` and `UseRowstile()` make each request act for its user, answer the database's refusals as problem bodies (403, 404, 401, 400, 409, as each code's page says), and refuse to start on a connection that skips row-level security. It holds no rowstile logic: it calls the `authz.*` functions the policy made, and translates their
answers.

```sh
dotnet add package Rowstile.AspNetCore --prerelease
```

How to use it with ASP.NET Core and EF Core: https://rowstile.dev/stacks/aspnetcore
