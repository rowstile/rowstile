using System;
using System.Globalization;

namespace Rowstile;

/// <summary>
/// Who a transaction acts for: a user (type <c>user</c>), another principal type the policy declares (a service, a
/// bot), or nobody (<see cref="Id"/> null: only what <c>anyone</c> may see).
/// </summary>
/// <param name="Type">The principal type: <c>user</c>, or another the policy declares (<c>service</c>).</param>
/// <param name="Id">Its id, as text; null for nobody.</param>
public sealed record Principal(string Type, string? Id)
{
    /// <summary>Nobody: only what <c>anyone</c> may see.</summary>
    public static Principal Nobody { get; } = new("user", null);

    /// <summary>
    /// The user with this id, whatever it holds: <c>"service:3"</c> is the user whose id that is (ids often come from
    /// outside: a username, an identity provider's subject), never service 3. Another principal type is named:
    /// <c>new Principal("service", "3")</c>.
    /// </summary>
    public static Principal User(string id) => new("user", id);

    /// <summary>The user with this id.</summary>
    public static Principal User(long id) => new("user", id.ToString(CultureInfo.InvariantCulture));

    /// <summary>
    /// What <see cref="ToString"/> wrote, read back: <c>service:3</c> is service 3, <c>42</c> and <c>user:42</c> user 42,
    /// <c>nobody</c> nobody. For text your own code wrote (a job's argument) and for who acted in the audit trail,
    /// which the database writes the same way; not for an id that came from outside.
    /// </summary>
    public static Principal Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text == "nobody")
        {
            return Nobody;
        }
        int colon = text.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0 && !text.StartsWith('('))
        {
            return new Principal(text[..colon], text[(colon + 1)..]);
        }
        return User(text);
    }

    /// <summary>
    /// <c>42</c>, <c>service:3</c> or <c>nobody</c>. A user whose id holds <c>:</c> or is <c>nobody</c> is
    /// <c>user:&lt;id&gt;</c>, so that <see cref="Parse"/> reads every principal back as itself.
    /// </summary>
    public override string ToString()
    {
        if (Id is null)
        {
            return "nobody";
        }
        if (Type != "user")
        {
            return $"{Type}:{Id}";
        }
        return Id.Contains(':', StringComparison.Ordinal) || Id == "nobody" ? $"user:{Id}" : Id;
    }
}
