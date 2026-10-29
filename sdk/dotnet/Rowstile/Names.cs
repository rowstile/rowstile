namespace Rowstile;

/// <summary>
/// A type of the policy (<c>project</c>, <c>note</c>). The generated client (<c>rowstile client csharp</c>) has one for
/// each, <c>Policy.Note.Type</c>, so a misspelled one doesn't compile.
/// </summary>
/// <param name="Name">The type's name, as the policy writes it.</param>
public sealed record ObjectType(string Name)
{
    /// <summary>The type's name.</summary>
    public override string ToString() => Name;
}

/// <summary>
/// A permission of a type of the policy (<c>note</c>'s <c>edit</c>). The generated client has one for each,
/// <c>Policy.Note.Edit</c>, so the SDK's calls that take one take only the policy's names.
/// </summary>
/// <param name="Type">The type it is a permission of.</param>
/// <param name="Name">The permission's name, as the policy writes it.</param>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1711", Justification = "a permission of the policy, not of .NET's security")]
public sealed record Permission(ObjectType Type, string Name)
{
    /// <summary><c>note.edit</c>.</summary>
    public override string ToString() => $"{Type.Name}.{Name}";
}
