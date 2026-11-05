// The demo's people (db/seed.sql), each with a cookie of their own: as(email) signs in through the app's own route
// and calls it as them.
export const SERVER = process.env.HELPDESK_SERVER ?? "http://localhost:8002";

export const ACME = "a0000000-0000-4000-8000-000000000001";
export const GLOBEX = "b0000000-0000-4000-8000-000000000001";
export const ids = {
  ann: "a0000000-0000-4000-8000-000000000a01", lea: "a0000000-0000-4000-8000-000000000a02",
  al: "a0000000-0000-4000-8000-000000000a03", oz: "a0000000-0000-4000-8000-000000000a04",
  peter: "a0000000-0000-4000-8000-000000000c01", milton: "a0000000-0000-4000-8000-000000000c02",
  cy: "a0000000-0000-4000-8000-000000000c03", bob: "b0000000-0000-4000-8000-000000000a01",
  xu: "b0000000-0000-4000-8000-000000000c01", sam: "f0000000-0000-4000-8000-000000000001",
};
export const tickets = {
  invoice: "a0000000-0000-4000-8000-000000000101", printer: "a0000000-0000-4000-8000-000000000102",
  password: "a0000000-0000-4000-8000-000000000103", globex: "b0000000-0000-4000-8000-000000000101",
};
export const EMAIL_INTAKE = "a0000000-0000-4000-8000-0000000000f1";

export interface Answer { status: number; json: any }

export interface Person {
  get(path: string): Promise<Answer>;
  send(method: string, path: string, json?: unknown): Promise<Answer>;
}

export async function as(email: string): Promise<Person> {
  const res = await fetch(`${SERVER}/api/session`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email }),
  });
  if (!res.ok) throw new Error(`signing in as ${email}: ${res.status}`);
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0];
  let jar = cookie;
  const send = async (method: string, path: string, json?: unknown): Promise<Answer> => {
    const r = await fetch(`${SERVER}${path}`, {
      method, headers: { "content-type": "application/json", cookie: jar },
      body: json === undefined ? undefined : JSON.stringify(json),
    });
    const set = r.headers.get("set-cookie");
    if (set) jar = set.split(";")[0];
    const text = await r.text();
    return { status: r.status, json: text ? JSON.parse(text) : null };
  };
  return { get: (path) => send("GET", path), send };
}
