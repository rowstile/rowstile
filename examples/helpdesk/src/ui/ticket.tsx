"use client";
// A ticket: its comments and the actions the user's permissions allow (authz.perms decides which buttons show;
// the database refuses the rest anyway, and "why?" says which rule)
import { useCallback, useEffect, useState } from "react";
import { call, type Problem } from "./api.ts";
import { ProblemNote } from "./problem.tsx";

interface Ticket {
  id: string; subject: string; status: string; perms: string[];
  requester: { name: string };
  comments: { id: string; body: string; internal: boolean; author: { name: string } | null }[];
}

export function TicketView({ id }: { id: string }) {
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [text, setText] = useState("");
  const [internal, setInternal] = useState(false);
  const load = useCallback(async () => {
    const r = await call("GET", `/api/tickets/${id}`);
    if (r.ok) setTicket(r.value as Ticket); else setProblem(r.problem);
  }, [id]);
  useEffect(() => { void load(); }, [load]);
  const act = async (method: string, path: string, json?: unknown) => {
    const r = await call(method, path, json);
    setProblem(r.ok ? null : r.problem);
    if (r.ok) await load();
    return r.ok;
  };
  if (!ticket) return <ProblemNote problem={problem} />;
  const may = (p: string) => ticket.perms.includes(p);
  return (
    <>
      <h1>{ticket.subject}</h1>
      <p>From {ticket.requester.name} · <span className="tag">{ticket.status}</span> · you may: {ticket.perms.join(", ") || "nothing"}</p>
      <ProblemNote problem={problem} />
      {ticket.comments.map((c) => (
        <section key={c.id} className={c.internal ? "internal" : ""}>
          <b>{c.author?.name ?? "by email"}</b>{c.internal && " (internal note)"}<br />{c.body}
        </section>
      ))}
      {may("reply") && (
        <form onSubmit={async (e) => { e.preventDefault(); if (await act("POST", `/api/tickets/${id}/comments`, { body: text, internal })) setText(""); }}>
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3} style={{ width: "100%" }} />
          {may("work") && <label><input type="checkbox" checked={internal} onChange={(e) => setInternal(e.target.checked)} /> internal note</label>}
          <button>Send</button>
        </form>
      )}
      <p>
        {["open", "pending", "solved", "closed"].map((s) => (
          <button key={s} disabled={s === ticket.status} onClick={() => act("PATCH", `/api/tickets/${id}`, { status: s })}>{s}</button>
        ))}
        {may("break_glass") && (
          <button onClick={() => act("POST", `/api/tickets/${id}/break-glass`, { reason: prompt("Why? (kept in the audit trail)") ?? "" })}>
            Break the glass
          </button>
        )}
      </p>
    </>
  );
}
