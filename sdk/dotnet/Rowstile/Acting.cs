using System;
using System.Threading;
using System.Threading.Tasks;

namespace Rowstile;

/// <summary>
/// Who the code running now acts for: every transaction the integrations begin in it signs in as them.
/// <code>
/// using (Acting.As(Principal.User("42")))   // or new Principal("service", "3"), or Principal.Nobody
/// {
///     ...                                    // every transaction in here signs in as user 42
/// }
/// </code>
/// It flows with the code's async calls (an <see cref="AsyncLocal{T}"/>), so concurrent requests never meet.
/// </summary>
public static class Acting
{
    private static readonly AsyncLocal<Principal?> CurrentValue = new();

    /// <summary>Who the code running now acts for (set by <see cref="As"/>, the web integration or a job), or null if unset.</summary>
    public static Principal? Current => CurrentValue.Value;

    /// <summary>Everything until the returned value is disposed acts for <paramref name="who"/>.</summary>
    public static IDisposable As(Principal who)
    {
        ArgumentNullException.ThrowIfNull(who);
        var before = CurrentValue.Value;
        CurrentValue.Value = who;
        return new Restore(before);
    }

    /// <summary>
    /// A background job: <paramref name="job"/> acts for <paramref name="who"/>, whatever request started it
    /// (<c>await Acting.Job(new Principal("service", "1"), () => Digest(db))</c>).
    /// </summary>
    public static async Task<T> Job<T>(Principal who, Func<Task<T>> job)
    {
        ArgumentNullException.ThrowIfNull(job);
        using (As(who))
        {
            return await job().ConfigureAwait(false);
        }
    }

    private sealed class Restore(Principal? before) : IDisposable
    {
        public void Dispose() => CurrentValue.Value = before;
    }
}
