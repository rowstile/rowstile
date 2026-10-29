using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Conformance.Migrations
{
    /// <inheritdoc />
    public partial class Schema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "app");

            migrationBuilder.CreateTable(
                name: "services",
                schema: "app",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_services", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                schema: "app",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "folders",
                schema: "app",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    parent_id = table.Column<long>(type: "bigint", nullable: true),
                    owner_id = table.Column<long>(type: "bigint", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_folders", x => x.id);
                    table.ForeignKey(
                        name: "FK_folders_folders_parent_id",
                        column: x => x.parent_id,
                        principalSchema: "app",
                        principalTable: "folders",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_folders_users_owner_id",
                        column: x => x.owner_id,
                        principalSchema: "app",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "inbox",
                schema: "app",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    sender_id = table.Column<long>(type: "bigint", nullable: false),
                    recipient_id = table.Column<long>(type: "bigint", nullable: false),
                    body = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_inbox", x => x.id);
                    table.ForeignKey(
                        name: "FK_inbox_users_recipient_id",
                        column: x => x.recipient_id,
                        principalSchema: "app",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_inbox_users_sender_id",
                        column: x => x.sender_id,
                        principalSchema: "app",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "projects",
                schema: "app",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    owner_id = table.Column<long>(type: "bigint", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    @public = table.Column<bool>(name: "public", type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_projects", x => x.id);
                    table.ForeignKey(
                        name: "FK_projects_users_owner_id",
                        column: x => x.owner_id,
                        principalSchema: "app",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "members",
                schema: "app",
                columns: table => new
                {
                    project_id = table.Column<long>(type: "bigint", nullable: false),
                    user_id = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_members", x => new { x.project_id, x.user_id });
                    table.ForeignKey(
                        name: "FK_members_projects_project_id",
                        column: x => x.project_id,
                        principalSchema: "app",
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_members_users_user_id",
                        column: x => x.user_id,
                        principalSchema: "app",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "notes",
                schema: "app",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    project_id = table.Column<long>(type: "bigint", nullable: false),
                    author_id = table.Column<long>(type: "bigint", nullable: false),
                    body = table.Column<string>(type: "text", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_notes", x => x.id);
                    table.ForeignKey(
                        name: "FK_notes_projects_project_id",
                        column: x => x.project_id,
                        principalSchema: "app",
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_notes_users_author_id",
                        column: x => x.author_id,
                        principalSchema: "app",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "project_services",
                schema: "app",
                columns: table => new
                {
                    project_id = table.Column<long>(type: "bigint", nullable: false),
                    service_id = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_project_services", x => new { x.project_id, x.service_id });
                    table.ForeignKey(
                        name: "FK_project_services_projects_project_id",
                        column: x => x.project_id,
                        principalSchema: "app",
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_project_services_services_service_id",
                        column: x => x.service_id,
                        principalSchema: "app",
                        principalTable: "services",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_folders_owner_id",
                schema: "app",
                table: "folders",
                column: "owner_id");

            migrationBuilder.CreateIndex(
                name: "IX_folders_parent_id",
                schema: "app",
                table: "folders",
                column: "parent_id");

            migrationBuilder.CreateIndex(
                name: "IX_inbox_recipient_id",
                schema: "app",
                table: "inbox",
                column: "recipient_id");

            migrationBuilder.CreateIndex(
                name: "IX_inbox_sender_id",
                schema: "app",
                table: "inbox",
                column: "sender_id");

            migrationBuilder.CreateIndex(
                name: "IX_members_user_id",
                schema: "app",
                table: "members",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "IX_notes_author_id",
                schema: "app",
                table: "notes",
                column: "author_id");

            migrationBuilder.CreateIndex(
                name: "IX_notes_project_id",
                schema: "app",
                table: "notes",
                column: "project_id");

            migrationBuilder.CreateIndex(
                name: "IX_project_services_service_id",
                schema: "app",
                table: "project_services",
                column: "service_id");

            migrationBuilder.CreateIndex(
                name: "IX_projects_owner_id",
                schema: "app",
                table: "projects",
                column: "owner_id");

            // the role the app connects as, and what it may do (row-level security decides which rows)
            var password = (Environment.GetEnvironmentVariable("CONF_APP_PASSWORD") ?? "app").Replace("'", "''", StringComparison.Ordinal);
            migrationBuilder.Sql($"""
                DO $$ BEGIN
                  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
                    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}';
                  END IF; END $$
                """);
            migrationBuilder.Sql("GRANT USAGE ON SCHEMA app TO conf_app");
            migrationBuilder.Sql("GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app");
            migrationBuilder.Sql("GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app");
            migrationBuilder.Sql("GRANT UPDATE ON app.folders TO conf_app");
            migrationBuilder.Sql("GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO conf_app");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "folders",
                schema: "app");

            migrationBuilder.DropTable(
                name: "inbox",
                schema: "app");

            migrationBuilder.DropTable(
                name: "members",
                schema: "app");

            migrationBuilder.DropTable(
                name: "notes",
                schema: "app");

            migrationBuilder.DropTable(
                name: "project_services",
                schema: "app");

            migrationBuilder.DropTable(
                name: "projects",
                schema: "app");

            migrationBuilder.DropTable(
                name: "services",
                schema: "app");

            migrationBuilder.DropTable(
                name: "users",
                schema: "app");
        }
    }
}
