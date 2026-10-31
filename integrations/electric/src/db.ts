// The app's database: node-postgres, each transaction signed in as whoever the code acts for (the request's user).
import pg from "pg";
import { authz } from "@rowstile/pg";
import "./authz.gen.js";                              // the policy's names, for the SDK's types

export const pool = new pg.Pool({ connectionString: process.env.ROWSTILE_APP_URL, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const sql = authz(pool);
