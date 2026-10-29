// Who a request is. A real app reads its session or token here: a cookie, a bearer token, an API key (context.User,
// once its authentication ran). The conformance app has no sign-in: its checks name the user in a header, which a
// real app must never believe. So docs/stacks/aspnetcore.md shows Program.cs naming SessionUser, and never this file.
using Rowstile;

namespace Conformance;

public static class Auth
{
    /// <summary>The request's signed-in user (null: nobody), or a service (x-service: a service's own API calls).</summary>
    public static Principal? SessionUser(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Request.Headers["x-service"] is [{ } service])
        {
            return new Principal("service", service);
        }
        return context.Request.Headers["x-user"] is [{ } user] ? Principal.User(user) : null;
    }
}
