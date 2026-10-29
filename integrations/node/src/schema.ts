// The app's tables, as Drizzle declares them: Drizzle Kit wrote the first migration from this file
// (drizzle/0000_schema.sql), and its own diff must find nothing else to change once rowstile's are applied.
import { boolean, index, integer, pgSchema, primaryKey, serial, text } from "drizzle-orm/pg-core";

export const app = pgSchema("app");

export const users = app.table("users", { id: integer().primaryKey(), name: text().notNull() });

export const services = app.table("services", { id: integer().primaryKey(), name: text().notNull() });

export const projects = app.table("projects", {
  id: integer().primaryKey(),
  ownerId: integer("owner_id").notNull(),
  name: text().notNull(),
  public: boolean().notNull().default(false),
}, (t) => [index("projects_owner_id_idx").on(t.ownerId)]);

export const members = app.table("members", {
  projectId: integer("project_id").notNull(),
  userId: integer("user_id").notNull(),
}, (t) => [primaryKey({ columns: [t.projectId, t.userId] }), index("members_user_id_idx").on(t.userId)]);

export const projectServices = app.table("project_services", {
  projectId: integer("project_id").notNull(),
  serviceId: integer("service_id").notNull(),
}, (t) => [primaryKey({ columns: [t.projectId, t.serviceId] }), index("project_services_service_id_idx").on(t.serviceId)]);

export const notes = app.table("notes", {
  id: serial().primaryKey(),
  projectId: integer("project_id").notNull(),
  authorId: integer("author_id").notNull(),
  body: text().notNull(),
}, (t) => [index("notes_project_id_idx").on(t.projectId), index("notes_author_id_idx").on(t.authorId)]);

export const inbox = app.table("inbox", {
  id: serial().primaryKey(),
  senderId: integer("sender_id").notNull(),
  recipientId: integer("recipient_id").notNull(),
  body: text().notNull(),
}, (t) => [index("inbox_sender_id_idx").on(t.senderId), index("inbox_recipient_id_idx").on(t.recipientId)]);

export const folders = app.table("folders", {
  id: integer().primaryKey(),
  parentId: integer("parent_id"),
  ownerId: integer("owner_id").notNull(),
  name: text().notNull(),
}, (t) => [index("folders_parent_id_idx").on(t.parentId), index("folders_owner_id_idx").on(t.ownerId)]);
