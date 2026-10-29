using System.Collections.Generic;

namespace Rowstile;

/// <summary>
/// An RFC 9457 problem body, as every rowstile SDK writes it: <c>type</c>, <c>title</c>, <c>status</c>,
/// <c>detail</c> (the database's words), then the fields of its own (<see cref="Extensions"/>): a refusal's
/// <c>table</c>, <c>command</c>, <c>why</c> and <c>code</c>; the <c>code</c> of a call the database turned down.
/// The types' pages are at https://rowstile.dev/problems/.
/// </summary>
/// <param name="Type">The problem's type, a URL: <c>https://rowstile.dev/problems/refused</c>.</param>
/// <param name="Title">The status's words: <c>Forbidden</c>.</param>
/// <param name="Status">The HTTP status: 403.</param>
/// <param name="Detail">What happened, in the database's words.</param>
public sealed record Problem(string Type, string Title, int Status, string Detail)
{
    /// <summary>The fields after <c>detail</c>, in order (a value may be null: a refusal by the database's own code names no table).</summary>
    public IReadOnlyList<KeyValuePair<string, object?>> Extensions { get; init; } = [];

    /// <summary>The 403 of a refusal.</summary>
    public static Problem Refused(
        string detail,
        string? table,
        string? command,
        IReadOnlyList<string> why,
        string code
    ) =>
        new("https://rowstile.dev/problems/refused", "Forbidden", 403, detail)
        {
            Extensions =
            [
                new("table", table),
                new("command", command),
                new("why", why),
                new("code", code),
            ],
        };

    /// <summary>The 409 of an update the rules allow, of a row that changed since it was read (a version counter).</summary>
    public static Problem Conflict { get; } =
        new(
            "https://rowstile.dev/problems/conflict",
            "Conflict",
            409,
            "the row changed since it was read, and the rules allow the change: read it again"
        );
}
