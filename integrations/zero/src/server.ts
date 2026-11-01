// Starts the app. At start-up it refuses a connection that skips row-level security (a superuser, BYPASSRLS, the
// tables' owner): sql.check() throws ConnectionProblem, and the process ends before it listens. It listens on every
// address: zero-cache, in a container, calls its endpoints through the host's.
import type { AddressInfo } from "node:net";
import { app } from "./app.js";
import { sql } from "./db.js";

await sql.check();
const server = app.listen(Number(process.env.PORT ?? 3000), "0.0.0.0", () =>
  console.log(`listening on ${(server.address() as AddressInfo).port}`));
