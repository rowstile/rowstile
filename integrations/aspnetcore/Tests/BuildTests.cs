// Checks 9, 12 and 14: the generated names compile and a wrong one doesn't; the framework's test database has the
// policy, a copy for each test collection; a policy change ships as the next migration, and the app works with the
// names the policy then makes.
using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Npgsql;
using Rowstile;
using Rowstile.Testing;

namespace Conformance.Tests;

public static class Build
{
    /// <summary>The framework's assemblies and the app's, as the test runs on them: what a snippet compiles against.</summary>
    private static IEnumerable<MetadataReference> References(bool withApp) =>
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Where(path => withApp || Path.GetFileNameWithoutExtension(path) != "App")
            .Select(path => MetadataReference.CreateFromFile(path));

    public static CSharpCompilation Compile(bool withApp, params string[] sources) =>
        CSharpCompilation.Create(
            "snippet" + Guid.NewGuid().ToString("N"),
            sources.Select(s => CSharpSyntaxTree.ParseText(s, new CSharpParseOptions(LanguageVersion.Latest))),
            References(withApp),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable)
        );

    /// <summary>The errors a snippet compiled against the app gets (none: it compiles).</summary>
    public static IReadOnlyList<string> Errors(string source) =>
        [.. Compile(true, source).GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).Select(d => d.ToString())];

    public static async Task<string> Run(string file, string arguments, string cwd, Dictionary<string, string>? env = null)
    {
        var start = new ProcessStartInfo(file, arguments) { WorkingDirectory = cwd, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var (k, v) in env ?? [])
        {
            start.Environment[k] = v;
        }
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var errors = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        string said = await output + await errors;
        Assert.True(p.ExitCode == 0, $"{file} {arguments}: {said}");
        return await output;
    }

    public static string Python => Environment.GetEnvironmentVariable("PYTHON") ?? "python3";

    public static string Command => Path.GetFullPath(Path.Combine(Env.Here, "..", "..", "core", "cli", "rowstile_cli.py"));
}

[Collection("conformance")]
public sealed class Check9
{
    // 9: the generated names type-check, and a wrong permission name doesn't: in the generated client, and in the
    // SDK's own calls
    [Fact]
    public async Task Check_9_generated_names_type_check()
    {
        // the committed client is the one the policy makes (rowstile client csharp POLICY prints it, and writes nothing)
        string made = await Build.Run(Build.Python, $"{Build.Command} client csharp db/policy.authz", Env.Here);
        Assert.True(made == await File.ReadAllTextAsync(Path.Combine(Env.Here, "App", "Authz.g.cs")), "App/Authz.g.cs is out of date: run rowstile client");
        const string Use = """
            using Rowstile;
            using Rowstile.Generated;
            public static class Use
            {
                public static string Name => Policy.Note.{0}.Name;
            }
            """;
        Assert.Empty(Build.Errors(Use.Replace("{0}", "Edit", StringComparison.Ordinal)));
        Assert.Contains(Build.Errors(Use.Replace("{0}", "Edt", StringComparison.Ordinal)), e => e.Contains("'Edt'", StringComparison.Ordinal));
        // the SDK's own calls take the same names, and only them (a string is no permission)
        const string Sdk = """
            using Conformance;
            using Microsoft.EntityFrameworkCore;
            using Rowstile.EntityFrameworkCore;
            using Rowstile.Generated;
            public static class Use
            {
                public static object Ids(AppDb db) => db.Database.Ids({0});
            }
            """;
        foreach (var (name, wanted, wrong) in new[]
        {
            ("good", "Policy.Note.Edit", ""),
            ("permission", "Policy.Note.Edt", "'Edt'"),
            ("type", "Policy.Nte.Edit", "'Nte'"),
            ("text", "\"note.edit\"", "cannot convert from 'string'"),
        })
        {
            var errors = Build.Errors(Sdk.Replace("{0}", wanted, StringComparison.Ordinal));
            Assert.True(wrong.Length == 0 ? errors.Count == 0 : errors.Any(e => e.Contains(wrong, StringComparison.Ordinal)), $"{name}: {string.Join("\n", errors)}");
        }
    }
}

[Collection("migrations")]
public sealed class Check12And14(MigrationDatabase db)
{
    // 12: the framework's test database has the policy: a database for each test collection (a worker of xUnit's,
    // which runs collections side by side), copied from the migrated one
    [Fact]
    public async Task Check_12_a_test_database_per_collection_has_the_policy()
    {
        string template = new NpgsqlConnectionStringBuilder(Env.Tests).Database!;
        Assert.Equal($"{template}_w3", new NpgsqlConnectionStringBuilder(db.Owner).Database); // this collection's own
        WorkerDatabase copy;
        await Database.Copying.WaitAsync();
        try
        {
            copy = await TestDatabase.PerWorkerAsync(Env.Tests, "12", Env.App);
        }
        finally
        {
            Database.Copying.Release();
        }
        var owner = new NpgsqlConnectionStringBuilder(copy.ConnectionString);
        var app = new NpgsqlConnectionStringBuilder(copy.AppConnectionString);
        Assert.Equal(($"{template}_w12", "conf_owner"), (owner.Database, owner.Username));
        Assert.Equal(($"{template}_w12", "conf_app"), (app.Database, app.Username));
        await Data.Sql(copy.ConnectionString, "INSERT INTO app.users (id, name) VALUES (1, 'ann'), (2, 'bo'); INSERT INTO app.projects (id, owner_id, name, public) VALUES (1, 1, 'Plans', false)");
        // the app's role, under row-level security: the copy has the policy
        await using (var source = NpgsqlDataSource.Create(copy.AppConnectionString!))
        {
            await source.CheckAsync();
        }
        Assert.Equal([1L], await Projects(copy.AppConnectionString!, 1));
        Assert.Empty(await Projects(copy.AppConnectionString!, 2));
        Assert.Equal(0L, await Data.Scalar(Env.Tests, "SELECT count(*) FROM app.users")); // the original is as migrated
        NpgsqlConnection.ClearAllPools();
        await Database.Copying.WaitAsync();
        try
        {
            Assert.Equal(copy, await TestDatabase.PerWorkerAsync(Env.Tests, "12", Env.App, fresh: false)); // kept, with what the test wrote
            Assert.Equal(2L, await Data.Scalar(copy.ConnectionString, "SELECT count(*) FROM app.users"));
            NpgsqlConnection.ClearAllPools();
            Assert.Equal(copy.ConnectionString, (await TestDatabase.PerWorkerAsync(Env.Tests, "12")).ConnectionString); // copied again: as migrated
            Assert.Equal(0L, await Data.Scalar(copy.ConnectionString, "SELECT count(*) FROM app.users"));
            NpgsqlConnection.ClearAllPools();
            var none = await Assert.ThrowsAsync<ArgumentException>(() => TestDatabase.PerWorkerAsync("Host=localhost;Username=conf_owner", "12"));
            Assert.Contains("a database to copy", none.Message, StringComparison.Ordinal);
            // nothing may be connected to the original: it says so, and what to do
            await using var holding = new NpgsqlConnection(Env.Tests + ";Pooling=false");
            await holding.OpenAsync();
            var held = await Assert.ThrowsAsync<InvalidOperationException>(() => TestDatabase.PerWorkerAsync(Env.Tests, "12"));
            Assert.Contains("can't be copied while anything is connected to it", held.Message, StringComparison.Ordinal);
        }
        finally
        {
            Database.Copying.Release();
        }
    }

    private static async Task<List<long>> Projects(string app, long user)
    {
        await using var conn = new NpgsqlConnection(app);
        await conn.OpenAsync();
        await using var tx = await conn.BeginSignedInAsync(Principal.User(user));
        var ids = new List<long>();
        await using var reader = await new NpgsqlCommand("SELECT id FROM app.projects ORDER BY id", conn).ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            ids.Add(reader.GetInt64(0));
        }
        return ids;
    }

    // 14: after a policy change and a new migration, the app works with the new generated names. On this collection's
    // copy of the migrated test database
    [Fact]
    public async Task Check_14_a_policy_change_ships_as_the_next_migration()
    {
        string work = Path.Combine(Path.GetTempPath(), "rowstile-conformance-" + Guid.NewGuid().ToString("N"));
        string app = Path.Combine(work, "integrations", "aspnetcore");
        try
        {
            CopyFolder(Env.Here, app);
            Directory.CreateDirectory(Path.Combine(work, "sdk", "dotnet"));
            File.Copy(Path.Combine(Env.Here, "..", "..", "sdk", "dotnet", "Version.props"), Path.Combine(work, "sdk", "dotnet", "Version.props"));
            string policy = Path.Combine(app, "db", "policy.authz");
            string text = await File.ReadAllTextAsync(policy);
            await File.WriteAllTextAsync(policy, text.Replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n", StringComparison.Ordinal));
            // ann sends bo a message
            await Data.Sql(db.Owner, "INSERT INTO app.inbox (id, sender_id, recipient_id, body) VALUES (500, 1, 2, 'hi')");
            string migrations = Path.Combine(app, "App", "Migrations");
            int before = Directory.GetFiles(migrations, "*_Authz*.Designer.cs").Length;
            await Build.Run(Build.Python, $"{Build.Command} migrate", app);
            await Build.Run(Build.Python, $"{Build.Command} client", app);
            Assert.Equal(before + 1, Directory.GetFiles(migrations, "*_Authz*.Designer.cs").Length); // the next one
            var owner = new Dictionary<string, string> { ["ROWSTILE_OWNER_CONN"] = db.Owner };
            await Build.Run("dotnet", "tool restore", app);
            NpgsqlConnection.ClearAllPools();
            await Build.Run("dotnet", "build App", app);
            await Build.Run("dotnet", "ef database update --project App --no-build", app, owner);
            string pending = await Build.Run("dotnet", "ef migrations has-pending-model-changes --project App --no-build", app, owner);
            Assert.Contains("No changes have been made to the model", pending, StringComparison.Ordinal);
            // the app's code, with the client the policy now makes: it names reply, and the database answers it
            var compiled = Build.Compile(
                false,
                await File.ReadAllTextAsync(Path.Combine(app, "App", "Authz.g.cs")),
                """
                using System.Threading.Tasks;
                using Npgsql;
                using Rowstile;
                using Rowstile.Generated;
                public static class Use
                {
                    public static async Task<(bool, bool)> Ask(NpgsqlConnection conn, long message) =>
                        (await conn.CanAsync(Policy.Message.Reply, message), await conn.CanAsync(Policy.Message.Read, message));
                }
                """
            );
            using var dll = new MemoryStream();
            var emitted = compiled.Emit(dll);
            Assert.True(emitted.Success, string.Join("\n", emitted.Diagnostics));
            var ask = Assembly.Load(dll.ToArray()).GetType("Use")!.GetMethod("Ask")!;
            var said = new List<(bool, bool)>();
            foreach (long user in new long[] { 2, 1 }) // bo, to whom it is sent, may reply; ann, who sent it, may not even read it
            {
                await using var conn = new NpgsqlConnection(db.App);
                await conn.OpenAsync();
                await using var tx = await conn.BeginSignedInAsync(Principal.User(user));
                said.Add(await (Task<(bool, bool)>)ask.Invoke(null, [conn, 500L])!);
            }
            Assert.Equal([(true, true), (false, false)], said);
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    private static void CopyFolder(string from, string to)
    {
        foreach (string dir in Directory.GetDirectories(from, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(dir.Replace(from, to, StringComparison.Ordinal));
        }
        Directory.CreateDirectory(to);
        foreach (string file in Directory.GetFiles(from, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(from, file);
            if (!Regex.IsMatch(rel, @"(^|/)(bin|obj|Tests)/"))
            {
                File.Copy(file, Path.Combine(to, rel));
            }
        }
    }
}
