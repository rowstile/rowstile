// What the work after a response saw (app/api/after), for the checks to read. Next.js bundles each route on its
// own, so the record is the process's, not a module's.
const KEY = Symbol.for("conformance.after");
const store = globalThis as { [KEY]?: Map<string, unknown> };
export const done: Map<string, unknown> = (store[KEY] ??= new Map());
