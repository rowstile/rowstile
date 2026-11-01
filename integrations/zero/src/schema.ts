// The app's Zero schema: its synced tables (never a column the policy masks: the notes have no body here, nor in
// the publication), and the sync index's tables and relationships, which rowstile client zero writes
// (src/zero.gen.ts), each synced table with its `readers`.
import { boolean, createBuilder, createSchema, number, relationships, string, table } from "@rocicorp/zero";
import { readers, syncRelationships, syncTables } from "./zero.gen.js";

const file = table("file").from("app.files")
  .columns({ id: number(), folder_id: number(), owner_id: number(), name: string(), confidential: boolean() })
  .primaryKey("id");
const folder = table("folder").from("app.folders")
  .columns({ id: number(), parent_id: number().optional(), owner_id: number(), name: string() })
  .primaryKey("id");
const note = table("note").from("app.notes")
  .columns({ id: number(), file_id: number(), author_id: number() })
  .primaryKey("id");

export const schema = createSchema({
  tables: [file, folder, note, ...syncTables],
  relationships: [
    relationships(file, ({ many }) => ({ readers: many(readers["app.files"]) })),
    relationships(folder, ({ many }) => ({ readers: many(readers["app.folders"]) })),
    relationships(note, ({ many }) => ({ readers: many(readers["app.notes"]) })),
    ...syncRelationships,
  ],
});
export type Schema = typeof schema;
export const zql = createBuilder(schema);

/** What the mutate endpoint writes through: the app's own tables. Zero checks a server schema's tables against those
 *  its connection holds a privilege on, and the app role holds none on the sync index: it is the engine's alone. The
 *  mutators write only the app's tables, so they run on this one as on the whole schema. */
export const writeSchema = createSchema({ tables: [file, folder, note] });
