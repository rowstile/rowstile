// At start-up: the server stops if its connection skips row-level security (a superuser, BYPASSRLS, the
// tables' owner), where the database would filter nothing
import { checkAtStart } from "@rowstile/next";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/db.ts")).db.$authz);
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/pg.ts")).sql);
}
