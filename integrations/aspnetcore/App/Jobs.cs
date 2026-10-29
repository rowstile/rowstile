using Microsoft.EntityFrameworkCore;
using Rowstile;

namespace Conformance;

public static class Jobs
{
    /// <summary>A background job: it signs in as service 1, whatever request started it.</summary>
    public static Task<(int Projects, Principal? Who)> Digest(AppDb db) =>
        Acting.Job(new Principal("service", "1"), async () => (await db.Projects.CountAsync(), Acting.Current));
}
