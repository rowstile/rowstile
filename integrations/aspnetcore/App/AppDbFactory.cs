// The context as `dotnet ef` makes it: as the tables' owner (ROWSTILE_OWNER_CONN), who runs the migrations, and
// without UseRowstile(), since the first migration runs before rowstile's functions exist.
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Conformance;

public sealed class AppDbFactory : IDesignTimeDbContextFactory<AppDb>
{
    public AppDb CreateDbContext(string[] args)
    {
        var owner = Environment.GetEnvironmentVariable("ROWSTILE_OWNER_CONN") ?? "Host=localhost;Database=conf";
        return new AppDb(new DbContextOptionsBuilder<AppDb>().UseNpgsql(owner).Options);
    }
}
