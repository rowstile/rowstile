# Rowstile (preview)

**Preview**: it may change in any release, and is not part of what 1.0 will freeze.

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is the base of the .NET SDK, on Npgsql: who a transaction acts for (`Acting`, `Principal`), the errors a refusal becomes (`RefusedException`, `NotFoundException`, `Errors.ProblemOf`), transactions signed in on an Npgsql connection (`BeginSignedInAsync`), the runtime's answers (`CanAsync`, `PermsOfAsync`, `ExpectAsync`), the start-up check (`CheckAsync`), and a test database per test collection (`Rowstile.Testing`). It holds no rowstile logic: it calls the `authz.*` functions the policy made, and translates their
answers.

```sh
dotnet add package Rowstile --prerelease
```

How to use it with ASP.NET Core and EF Core: https://rowstile.dev/stacks/aspnetcore
