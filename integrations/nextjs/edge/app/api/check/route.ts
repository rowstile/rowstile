// What doesn't run on the edge says so: checkAtStart has no server to stop there (instrumentation.ts runs it on the
// Node.js runtime), and it throws instead of checking
import { checkAtStart } from "@rowstile/next";
import { edgeSql } from "@/neon";

export const runtime = "edge";

export const GET = async () =>
  Response.json({ said: await checkAtStart(edgeSql()).then(() => null, (e: Error) => e.message) });
