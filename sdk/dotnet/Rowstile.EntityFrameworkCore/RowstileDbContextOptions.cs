using System;
using Microsoft.EntityFrameworkCore;

namespace Rowstile.EntityFrameworkCore;

/// <summary>
/// rowstile with EF Core on Npgsql.
/// <code>
/// builder.Services.AddDbContext&lt;AppDb&gt;(o => o.UseNpgsql(dataSource).UseRowstile());
/// </code>
/// Every transaction the context begins (its own, for SaveChanges, and the app's, <c>BeginTransactionAsync</c>)
/// signs in with <c>authz.act_as()</c> as whoever the code acts for (<see cref="Acting"/>: the web integration, a
/// job), else as <c>user()</c> if given, else as nobody; so does every command outside a transaction (a query, an
/// <c>ExecuteUpdate</c>), in the transaction of its own Postgres runs it in. SaveChanges runs in a transaction: when
/// an update or a delete it sends matches no row (EF's <c>DbUpdateConcurrencyException</c>), the SDK asks the database
/// why, in that transaction and as the same user, before it is rolled back, and records the answer on the error
/// (<see cref="Stale.Why"/>): the row is hidden (404), the user may not change it (403, with the reason), or the
/// rules allow it and the row changed since it was read (a concurrency token: 409).
/// </summary>
public static class RowstileDbContextOptions
{
    /// <summary>Signs every transaction, and every command outside one, in (see <see cref="RowstileDbContextOptions"/>).</summary>
    /// <param name="builder">The context's options, on Npgsql.</param>
    /// <param name="user">Who the code acts for when nothing set it with <see cref="Acting"/> (null: nobody).</param>
    public static DbContextOptionsBuilder UseRowstile(this DbContextOptionsBuilder builder, Func<Principal?>? user = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var signIn = new SignIn(user);
        var saves = new SaveChangesInTransaction();
        return builder.AddInterceptors(new TransactionSignIn(signIn, saves), new CommandSignIn(signIn), saves);
    }

    /// <summary>The same, for a context's typed options (<c>new DbContextOptionsBuilder&lt;AppDb&gt;()</c>).</summary>
    public static DbContextOptionsBuilder<TContext> UseRowstile<TContext>(
        this DbContextOptionsBuilder<TContext> builder,
        Func<Principal?>? user = null
    )
        where TContext : DbContext => (DbContextOptionsBuilder<TContext>)UseRowstile((DbContextOptionsBuilder)builder, user);
}

/// <summary>Who a transaction signs in as: whoever the code acts for, else <c>user()</c>, else nobody.</summary>
internal sealed class SignIn(Func<Principal?>? user)
{
    public Principal Who() => Acting.Current ?? user?.Invoke() ?? Principal.Nobody;
}
