// A shape's rows as a client must keep them: its inserts, updates and deletes, and the rows a move-out takes away.
// The sync index's filter has a subquery, so when a row leaves a user's shape (a share revoked, a ticket handed
// on) Electric sends a move-out event naming the values that no longer match, and no delete. Electric's own Shape
// (@electric-sql/client 1.5.28) doesn't read those events and would keep the row; this follows them, as Electric's
// Elixir client does (the conformance suite's integrations/electric/tests/data.ts, for a filter of ORs).
import { isChangeMessage, isControlMessage, type Message, type Row } from "@electric-sql/client";

export class Rows {
  readonly rows = new Map<string, { value: Row; entries: Set<string> }>();

  /** Applies one message; true if the rows changed. */
  apply(m: Message<Row>): boolean {
    if (isControlMessage(m)) {
      if (m.headers.control !== "must-refetch") return false;
      this.rows.clear();
      return true;
    }
    if (isChangeMessage(m)) {
      const h = m.headers as { operation: string; tags?: string[]; removed_tags?: string[] };
      if (h.operation === "delete") return this.rows.delete(m.key);
      const old = this.rows.get(m.key);
      const entries = new Set(old?.entries ?? []);
      for (const t of h.removed_tags ?? []) t.split("/").forEach((x, i) => x && entries.delete(`${i}:${x}`));
      for (const t of h.tags ?? []) t.split("/").forEach((x, i) => x && entries.add(`${i}:${x}`));
      if (h.operation === "update" && old && old.entries.size > 0 && entries.size === 0) return this.rows.delete(m.key);
      this.rows.set(m.key, { value: { ...(old?.value ?? {}), ...m.value }, entries });
      return true;
    }
    const e = m as unknown as { headers: { event: string; patterns: { pos: number; value: string }[] } };
    if (e.headers.event !== "move-out") return false;
    let changed = false;
    for (const [key, row] of this.rows) {
      const hit = e.headers.patterns.filter((p) => row.entries.has(`${p.pos}:${p.value}`));
      if (!hit.length) continue;
      for (const p of hit) row.entries.delete(`${p.pos}:${p.value}`);
      if (!row.entries.size) changed = this.rows.delete(key) || changed;
    }
    return changed;
  }

  ids(): string[] {
    return [...this.rows.values()].map((r) => String(r.value.id)).sort();
  }
}
