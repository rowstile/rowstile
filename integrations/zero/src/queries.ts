// The app's synced queries: each table's rows, filtered by the sync index for whoever the context says (rowstile
// client zero's readable). The query endpoint makes that context from the request, so a client that says it is
// someone else in its own context still gets its token's rows: the client's context only runs its local copy.
import { defineQueriesWithType, defineQueryWithType } from "@rocicorp/zero";
import type { Schema } from "./schema.js";
import { zql } from "./schema.js";
import { readable, type SyncedBy } from "./zero.gen.js";

/** Whom the queries are for: the signed-in principal (nobody never gets this far: the endpoint answers 401). */
export type Ctx = SyncedBy;

const defineQuery = defineQueryWithType<Schema, Ctx>();
const defineQueries = defineQueriesWithType<Schema>();

export const queries = defineQueries({
  files: defineQuery(({ ctx }) => readable["app.files"](zql.file, ctx).orderBy("id", "asc")),
  folders: defineQuery(({ ctx }) => readable["app.folders"](zql.folder, ctx).orderBy("id", "asc")),
  notes: defineQuery(({ ctx }) => readable["app.notes"](zql.note, ctx).orderBy("id", "asc")),
});
