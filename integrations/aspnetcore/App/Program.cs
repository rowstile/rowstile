// The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the database
// filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404.
using System.Text.Json;
using Conformance;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Rowstile;
using Rowstile.AspNetCore;
using Rowstile.EntityFrameworkCore;
using Rowstile.Generated;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRowstile(o =>
{
    o.ConnectionString = builder.Configuration["ROWSTILE_APP_CONN"];
    o.User = Auth.SessionUser;
    o.CheckConnection = builder.Configuration.GetValue("ROWSTILE_CHECK_CONNECTION", true);
});
builder.Services.AddDbContext<AppDb>((services, o) => o.UseNpgsql(services.GetRequiredService<NpgsqlDataSource>()).UseRowstile());
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower);
var app = builder.Build();
app.UseRowstile();

app.MapGet("/projects", async (AppDb db) => await db.Projects.Select(p => p.Id).OrderBy(id => id).ToListAsync());

app.MapGet(
    "/projects/editable",
    async (AppDb db) =>
        await db.Projects.Where(p => db.Database.Ids(Policy.Project.Edit).Contains(p.Id)).Select(p => p.Id).OrderBy(id => id).ToListAsync()
);

app.MapGet(
    "/projects/buttons",
    async (AppDb db) =>
    {
        var ids = await db.Projects.Select(p => p.Id).ToListAsync();
        var perms = await db.Database.PermsOfAsync(Policy.Project.Type, ids.Cast<object>());
        return perms.ToDictionary(kv => kv.Key, kv => kv.Value.Select(p => p.Name).ToList());
    }
);

// the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
app.MapGet(
    "/projects/page",
    async (AppDb db, int limit, string? after) =>
        await db.Database.SqlQuery<string>(
            $"SELECT x AS \"Value\" FROM authz.list('project', 'view', CAST({after} AS text), {limit}) x"
        ).ToListAsync()
);

// one of the user's API keys: someone else's, or one that isn't there, is 404
app.MapDelete(
    "/keys/{keyId}",
    async (AppDb db, long keyId) =>
    {
        await db.Database.ExecuteSqlAsync($"SELECT 1 FROM authz.revoke_api_key({keyId})");
        return Results.NoContent();
    }
);

// an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key) signs in
// with it first, in the same transaction: the database says who may make which
app.MapPost(
    "/keys",
    async (AppDb db, HttpRequest request, NewKey k) =>
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        if (request.Headers["x-api-key"] is [{ } key])
        {
            await db.Database.ExecuteSqlAsync($"SELECT authz.login_key({key})");
        }
        var made = await db.Database.SqlQuery<string>(
            $"SELECT authz.create_api_key({k.Name}, '', NULL, CAST({k.PrincipalType} AS text), CAST({k.PrincipalId} AS text)) AS \"Value\""
        ).ToListAsync();
        await tx.CommitAsync();
        return Results.Created((string?)null, new { key = made[0] });
    }
);

app.MapGet(
    "/projects/{projectId}/shares",
    async (AppDb db, long projectId) =>
        await db.Database.SqlQuery<string>(
            $"SELECT subject_id AS \"Value\" FROM authz.list_shares('project', CAST({projectId} AS text))"
        ).ToListAsync()
);

// access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once the
// database knows who asks
app.MapPost(
    "/projects/{projectId}/requests",
    async (AppDb db, long projectId, Ask a) =>
    {
        var asked = await db.Database.SqlQuery<long>(
            $"SELECT authz.request_access('project', CAST({projectId} AS text), {a.Relation}, {a.Reason}) AS \"Value\""
        ).ToListAsync();
        return Results.Created((string?)null, new { id = asked[0] });
    }
);

// who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
app.MapGet(
    "/notes/as/{userId}",
    async (AppDb db, long userId) =>
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlAsync($"SELECT set_config('authz.user_id', CAST({userId} AS text), true)");
        return await db.Notes.Select(n => n.Id).OrderBy(id => id).ToListAsync();
    }
);

app.MapPatch(
    "/folders/{folderId}",
    async (AppDb db, long folderId, Move m) =>
    {
        var folder = await db.Folders.FindAsync(folderId) ?? throw new NotFoundException("app.folders", folderId);
        folder.ParentId = m.ParentId; // inside one of its own subfolders: 409, the database's words
        await db.SaveChangesAsync();
        return new { id = folderId };
    }
);

app.MapGet("/notes", async (AppDb db) => await db.Notes.Select(n => n.Id).OrderBy(id => id).ToListAsync());

app.MapPost(
    "/notes",
    async (AppDb db, NewNote n) =>
    {
        var note = new Note { ProjectId = n.ProjectId, AuthorId = SignedIn(), Body = n.Body };
        db.Notes.Add(note);
        await db.SaveChangesAsync(); // reads the id back (RETURNING)
        return Results.Created((string?)null, new { id = note.Id });
    }
);

app.MapPatch(
    "/notes/{noteId}",
    async (AppDb db, long noteId, NoteBody b) =>
    {
        var note = await db.Notes.FindAsync(noteId) ?? throw new NotFoundException("app.notes", noteId);
        note.Body = b.Body;
        await db.SaveChangesAsync(); // an update the rules may refuse: 403 with the reason
        return new { id = noteId };
    }
);

app.MapDelete(
    "/notes/{noteId}",
    async (AppDb db, long noteId) =>
    {
        int deleted = await db.Notes.Where(n => n.Id == noteId).ExecuteDeleteAsync();
        await db.Database.ExpectAsync(deleted, "app.notes", "delete", noteId);
        return Results.NoContent();
    }
);

app.MapPost(
    "/inbox",
    async (AppDb db, NewMessage m) =>
    {
        var message = new Message { SenderId = SignedIn(), RecipientId = m.RecipientId, Body = m.Body };
        db.Inbox.Add(message);
        await db.SaveChangesAsync(); // reads the id back (RETURNING): only the recipient may read it
        return Results.Created((string?)null, new { id = message.Id });
    }
);

// without reading the row back (EF Core's SaveChanges would, with RETURNING, to learn the new id)
app.MapPost(
    "/inbox/quietly",
    async (AppDb db, NewMessage m) =>
    {
        await db.Database.ExecuteSqlAsync(
            $"INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES ({SignedIn()}, {m.RecipientId}, {m.Body})"
        );
        return Results.Accepted();
    }
);

await app.RunAsync();

// the user the request acts for (the middleware set it from SessionUser), as the tables' key
static long SignedIn() => Acting.Current is { Type: "user", Id: { } id } ? long.Parse(id, System.Globalization.CultureInfo.InvariantCulture) : 0;

internal sealed record NewKey(string Name, string? PrincipalType, string? PrincipalId);

internal sealed record Ask(string Relation, string Reason);

internal sealed record Move(long? ParentId);

internal sealed record NewNote(long ProjectId, string Body);

internal sealed record NoteBody(string Body);

internal sealed record NewMessage(long RecipientId, string Body);

public partial class Program;
