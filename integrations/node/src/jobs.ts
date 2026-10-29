// A background job (a queue worker, a timer): it acts for service 1, whatever started it
import { current, job } from "@rowstile/client";
import { sql } from "./db.js";

export const digest = job(["service", 1], async () => ({
  count: (await sql.query<{ n: number }>("SELECT count(*)::int AS n FROM app.projects")).rows[0]?.n,
  who: current(),
}));
