// The same app's queries without Prisma: node-postgres, each transaction signed in as the request's user
// (@rowstile/pg). docs/stacks/nextjs.md shows it ("Next.js with pg").
import { authz } from "@rowstile/pg";
import "@rowstile/next";                              // signed-in reads never land in a cache
import { pool, requestUser } from "./db.ts";

export const sql = authz(pool, { user: requestUser });
