// The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
// project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it. The servers test.sh started, and what they answer.
import pg from "pg";

export const OWNER = process.env.ROWSTILE_OWNER_DSN ?? "";
export const APP = process.env.ROWSTILE_APP_URL ?? "";
// the change feed's own connection: straight to Postgres when the app's goes through a pooler (POOLER=pgbouncer)
export const FEED = process.env.ROWSTILE_FEED_URL ?? APP;
export const SERVER = process.env.CONFORMANCE_SERVER ?? "";          // a pool of 5 connections
export const SERVER_ONE = process.env.CONFORMANCE_SERVER_ONE ?? "";  // a pool of one
export const SERVER_LOG = process.env.CONFORMANCE_SERVER_LOG ?? "";  // what SERVER logs
export const SERVER_EDGE = process.env.CONFORMANCE_SERVER_EDGE ?? "";  // edge/: the edge runtime's routes
export const EXPECTED: Record<string, number[]> = { "1": [1, 3, 4], "2": [2, 3], "3": [1, 3, 4], "": [3] };

export async function seed(): Promise<void> {
  if (!OWNER) throw new Error("ROWSTILE_OWNER_DSN is not set (test.sh sets it)");
  const c = new pg.Client({ connectionString: OWNER });
  await c.connect();
  try {
    await c.query(`
      TRUNCATE app.folders, app.feedback, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services, app.users;
      DELETE FROM authz.shares WHERE object_type = 'project';
      DELETE FROM authz.requests;
      INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
      INSERT INTO app.services VALUES (1, 'digest');
      INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
      INSERT INTO app.members VALUES (1, 3);
      INSERT INTO app.project_services VALUES (1, 1);
      INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
      SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
      INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');`);
  } finally {
    await c.end();
  }
}

/** A request to a server, as a user (a header here; a real app has its session), or nobody. */
export function as(user: string | null, init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  if (user !== null) headers.set("x-user", user);
  if (init.body !== undefined) headers.set("content-type", "application/json");
  return { ...init, headers };
}
