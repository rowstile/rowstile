// The app's database: Prisma, signed in as the request's user on every transaction (@rowstile/prisma).
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";
import { authz, signedIn } from "@rowstile/prisma";
import { changes } from "@rowstile/pg";
import "@rowstile/next";                              // signed-in reads never land in a cache
import { auth } from "./auth.ts";                     // the session: Auth.js's auth(), or your own
import { PrismaClient } from "./generated/prisma/client.ts";
import "./authz.gen.ts";                              // the policy's names, for the SDK's types

/** Who the request is: the session's user (none: nobody, who sees only what `anyone` may). */
export async function requestUser(): Promise<string | null> {
  return (await auth())?.user?.id ?? null;
}

const url = process.env.ROWSTILE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const db = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: requestUser }) }).$extends(authz());

// live updates for @rowstile/react: one connection that LISTENs, beside the pool, straight to Postgres
// (through a pooler in transaction mode LISTEN hears nothing: ROWSTILE_FEED_URL is the direct URL then)
export const feed = changes(new pg.Pool({ connectionString: process.env.ROWSTILE_FEED_URL ?? url, max: 1 }));
