// The same app's queries through Neon's serverless driver (@neondatabase/serverless): its Pool talks to Postgres
// over WebSockets, which the edge runtime has where it has no TCP. On Neon it needs no settings; here, as in local
// development, a WebSocket proxy (Neon's wsproxy, in Docker: test.sh) stands in front of a plain Postgres.
// docs/stacks/nextjs.md shows it ("Neon's serverless driver"). Nothing here imports pg or Prisma: the edge routes
// import this file.
import { Pool, neonConfig } from "@neondatabase/serverless";
import { after } from "next/server";
import { authz } from "@rowstile/pg";
import "@rowstile/next";                              // signed-in reads never land in a cache
import { auth } from "./auth.ts";                     // the session: Auth.js's auth(), or your own

const proxy = process.env.ROWSTILE_WSPROXY;           // host:port of a local wsproxy; unset on Neon
if (proxy) {
  neonConfig.wsProxy = (host, port) => `${proxy}/v1?address=${host}:${port}`;
  neonConfig.useSecureWebSocket = false;              // ws://, to localhost
  neonConfig.pipelineConnect = false;                 // the startup pipelining only Neon's own proxy takes
}

async function requestUser(): Promise<string | null> {
  return (await auth())?.user?.id ?? null;
}

// the Node.js runtime: one pool for the server, as with pg
const neonUrl = process.env.ROWSTILE_NEON_URL;
export const neonPool = new Pool({ connectionString: neonUrl, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const neon = authz(neonPool, { user: requestUser });

// the edge runtime: a WebSocket can't outlive the request it was opened in, so each request has a pool of its own,
// ended once the response is sent
export function edgeSql() {
  const pool = new Pool({ connectionString: neonUrl });
  after(() => pool.end());
  return authz(pool, { user: requestUser });
}
