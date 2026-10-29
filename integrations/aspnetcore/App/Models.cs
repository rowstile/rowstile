// The conformance app's tables: projects with members, notes in them, a service that reads projects, an inbox people
// can write to but only the recipient reads, and folders inside folders.
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace Conformance;

public sealed class AppDb(DbContextOptions<AppDb> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Service> Services => Set<Service>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<Member> Members => Set<Member>();
    public DbSet<ProjectService> ProjectServices => Set<ProjectService>();
    public DbSet<Note> Notes => Set<Note>();
    public DbSet<Message> Inbox => Set<Message>();
    public DbSet<Folder> Folders => Set<Folder>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("app");
        modelBuilder.Entity<Member>().HasKey(m => new { m.ProjectId, m.UserId });
        modelBuilder.Entity<Member>().HasIndex(m => m.UserId);
        modelBuilder.Entity<ProjectService>().HasKey(s => new { s.ProjectId, s.ServiceId });
        modelBuilder.Entity<ProjectService>().HasIndex(s => s.ServiceId);
    }
}

[Table("users")]
public sealed class User
{
    [Column("id"), DatabaseGenerated(DatabaseGeneratedOption.None)]
    public long Id { get; set; }

    [Column("name")]
    public required string Name { get; set; }
}

[Table("services")]
public sealed class Service
{
    [Column("id"), DatabaseGenerated(DatabaseGeneratedOption.None)]
    public long Id { get; set; }

    [Column("name")]
    public required string Name { get; set; }
}

[Table("projects")]
public sealed class Project
{
    [Column("id"), DatabaseGenerated(DatabaseGeneratedOption.None)]
    public long Id { get; set; }

    [Column("owner_id"), ForeignKey(nameof(Owner))]
    public long OwnerId { get; set; }

    public User? Owner { get; set; }

    [Column("name")]
    public required string Name { get; set; }

    [Column("public")]
    public bool Public { get; set; }
}

[Table("members")]
public sealed class Member
{
    [Column("project_id"), ForeignKey(nameof(Project))]
    public long ProjectId { get; set; }

    public Project? Project { get; set; }

    [Column("user_id"), ForeignKey(nameof(User))]
    public long UserId { get; set; }

    public User? User { get; set; }
}

[Table("project_services")]
public sealed class ProjectService
{
    [Column("project_id"), ForeignKey(nameof(Project))]
    public long ProjectId { get; set; }

    public Project? Project { get; set; }

    [Column("service_id"), ForeignKey(nameof(Service))]
    public long ServiceId { get; set; }

    public Service? Service { get; set; }
}

[Table("notes")]
public sealed class Note
{
    [Column("id")]
    public long Id { get; set; }

    [Column("project_id"), ForeignKey(nameof(Project))]
    public long ProjectId { get; set; }

    public Project? Project { get; set; }

    [Column("author_id"), ForeignKey(nameof(Author))]
    public long AuthorId { get; set; }

    public User? Author { get; set; }

    [Column("body")]
    public required string Body { get; set; }

    // Postgres's xmin, as EF Core's concurrency token: an update of a note that changed since it was read matches no row
    [Timestamp]
    public uint Version { get; set; }
}

[Table("inbox")]
public sealed class Message
{
    [Column("id")]
    public long Id { get; set; }

    [Column("sender_id"), ForeignKey(nameof(Sender))]
    public long SenderId { get; set; }

    public User? Sender { get; set; }

    [Column("recipient_id"), ForeignKey(nameof(Recipient))]
    public long RecipientId { get; set; }

    public User? Recipient { get; set; }

    [Column("body")]
    public required string Body { get; set; }
}

[Table("folders")]
public sealed class Folder
{
    [Column("id"), DatabaseGenerated(DatabaseGeneratedOption.None)]
    public long Id { get; set; }

    [Column("parent_id"), ForeignKey(nameof(Parent))]
    public long? ParentId { get; set; }

    public Folder? Parent { get; set; }

    [Column("owner_id"), ForeignKey(nameof(Owner))]
    public long OwnerId { get; set; }

    public User? Owner { get; set; }

    [Column("name")]
    public required string Name { get; set; }
}
