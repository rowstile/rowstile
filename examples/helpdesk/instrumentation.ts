import { checkAtStart } from "@rowstile/next";

// the server stops if its connection skips row-level security (a superuser, BYPASSRLS, the tables' owner)
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/db.ts")).db.$authz);
}
