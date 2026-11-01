// The app's mutators. On the server they run in the transaction the mutate endpoint signed in as the request's
// user (src/app.ts), so the database's rules decide what they may write: a refused one says why, in the policy's
// words, and Zero gives its error to the client that asked.
import { defineMutatorWithType, defineMutatorsWithType } from "@rocicorp/zero";
import { calls } from "@rowstile/client";
import type { NodePgTransaction } from "@rocicorp/zero/server/adapters/pg";
import type { Ctx } from "./queries.js";
import type { Schema } from "./schema.js";

const defineMutator = defineMutatorWithType<Schema, Ctx, NodePgTransaction>();
const defineMutators = defineMutatorsWithType<Schema>();

export const mutators = defineMutators({
  file: {
    create: defineMutator<{ id: number; folder_id: number; name: string }>(async ({ tx, args, ctx }) => {
      await tx.mutate.file.insert({ ...args, owner_id: Number(ctx.id), confidential: false });
    }),
    // on the server, the update as SQL: a row the rules don't let the user update matches nothing (row-level
    // security filters it), which Zero's own update doesn't count, so the SDK's expect says what it was: hidden
    // (NotFound) or refused, and why (Refused)
    rename: defineMutator<{ id: number; name: string }>(async ({ tx, args }) => {
      if (tx.location !== "server") return tx.mutate.file.update({ id: args.id, name: args.name });
      const db = { query: async (text: string, values: unknown[]) => ({ rows: [...await tx.dbTransaction.query(text, values)] }) };
      await calls(db).expect(await db.query("UPDATE app.files SET name = $1 WHERE id = $2 RETURNING id", [args.name, args.id]),
        "app.files", "update", args.id);
    }),
  },
});
