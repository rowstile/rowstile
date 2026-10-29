// The app's database: node-postgres, and Drizzle on the same pool, each transaction signed in as whoever the code
// acts for (the request's user: src/app.ts's middleware); postgres.js beside them, for a route or two.
import pg from "pg";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/node-postgres";
import { authz } from "@rowstile/pg";
import { withAuthz } from "@rowstile/drizzle";
import { authz as postgresAuthz } from "@rowstile/postgres";
import "./authz.gen.js";                              // the policy's names, for the SDK's types

const url = process.env.ROWSTILE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const sql = authz(pool);                       // sql.transaction(fn), sql.query(), sql.can(), ...
export const db = withAuthz(drizzle(pool));           // db.transaction((tx) => tx.select()...)
// postgres.js: { prepare: false } for PgBouncer in transaction mode, as postgres.js says
export const pgjs = postgresAuthz(postgres(url ?? "", { max: 2, prepare: false }));
