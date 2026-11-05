"use client";
// The pages' calls to the app's routes. A refusal comes back as a problem (https://rowstile.dev/problems/refused):
// its detail is the database's own explanation of which rule refused, and why.
export interface Problem { title: string; detail?: string; why?: string[]; status: number }

export async function call(method: string, path: string, json?: unknown): Promise<{ ok: true; value: unknown } | { ok: false; problem: Problem }> {
  const res = await fetch(path, { method, headers: { "content-type": "application/json" }, body: json === undefined ? undefined : JSON.stringify(json) });
  if (res.ok) return { ok: true, value: res.status === 204 ? null : await res.json() };
  const problem = (await res.json().catch(() => ({ title: res.statusText }))) as Problem;
  return { ok: false, problem: { ...problem, status: res.status } };
}
