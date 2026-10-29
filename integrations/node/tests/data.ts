// The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
// project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it. The servers test.sh started.
import pg from "pg";

export const OWNER = process.env.ROWSTILE_OWNER_DSN ?? "";
export const APP = process.env.ROWSTILE_APP_URL ?? "";
export const TESTS = process.env.ROWSTILE_TESTS_DSN ?? "";
export const SERVER = process.env.CONFORMANCE_SERVER ?? "";          // a pool of 5 connections
export const SERVER_ONE = process.env.CONFORMANCE_SERVER_ONE ?? "";  // a pool of one
export const EXPECTED: Record<string, number[]> = { "1": [1, 3, 4], "2": [2, 3], "3": [1, 3, 4], "": [3] };

/** The app role's URL for another database of the same server (a worker's copy). */
export function appAt(url: string): string {
  const u = new URL(APP);
  u.pathname = new URL(url).pathname;
  return u.toString();
}

/** Runs fn on a connection of its own to url (the owner's, by default), then closes it. */
export async function owner<R>(fn: (c: pg.Client) => Promise<R>, url = OWNER): Promise<R> {
  const c = new pg.Client({ connectionString: url });
  await c.connect();
  try {
    return await fn(c);
  } finally {
    await c.end();
  }
}

export async function seed(url = OWNER): Promise<void> {
  if (!url) throw new Error("ROWSTILE_OWNER_DSN is not set (test.sh sets it)");
  await owner((c) => c.query(`
    TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services, app.users;
    DELETE FROM authz.shares WHERE object_type = 'project';
    DELETE FROM authz.requests;
    INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
    INSERT INTO app.services VALUES (1, 'digest');
    INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
    INSERT INTO app.members VALUES (1, 3);
    INSERT INTO app.project_services VALUES (1, 1);
    INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
    SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
    INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');`), url);
}

/** A request to a server, as a user (a header here; a real app has its session), or nobody. */
export function as(user: string | null, init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  if (user !== null) headers.set("x-user", user);
  if (init.body !== undefined) headers.set("content-type", "application/json");
  return { ...init, headers };
}

/** A JSON body, as fetch sends it. */
export const json = (method: string, body: object): RequestInit => ({ method, body: JSON.stringify(body) });
