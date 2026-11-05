// The app's database: Prisma, signed in as the request's user on every transaction (@rowstile/prisma). The app
// connects as hd_app, which row-level security applies to: it checks no permission itself.
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";
import { authz, signedIn } from "@rowstile/prisma";
import { authz as pgAuthz } from "@rowstile/pg";
import "@rowstile/next";                              // signed-in reads never land in a cache
import { session } from "./session.ts";
import { PrismaClient } from "./generated/prisma/client.ts";
import "./authz_client.ts";                           // the policy's names, for the SDK's types

/** Who the request is: the session's user (none: nobody, who sees nothing here). */
export async function requestUser(): Promise<string | null> {
  return (await session())?.user ?? null;
}

const url = process.env.HD_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
// node-postgres beside Prisma, on the same pool, for Electric's shape routes (app/api/shapes)
export const sql = pgAuthz(pool);
export const db = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: requestUser }) }).$extends(authz());
export type Tx = Parameters<Parameters<typeof db.$transaction>[0]>[0];

/** A transaction as the request's user, or, while an admin views the app as someone, as that person: authz.view_as
 *  switches it to them, read-only (a write is refused by the database, and says so), and the audit trail keeps
 *  who looked and why. Every route and page goes through it. */
export async function inTx<R>(fn: (tx: Tx) => Promise<R>): Promise<R> {
  const viewAs = (await session())?.viewAs;
  return db.$transaction(async (tx) => {
    if (viewAs) await tx.$executeRaw`SELECT authz.view_as(${viewAs}::text, 'the admin page: view as')`;
    return fn(tx);
  });
}
