"use client";
import { useState } from "react";
import { call, type Problem } from "./api.ts";
import { ProblemNote } from "./problem.tsx";

// the demo's ids (db/seed.sql)
const ACME = "a0000000-0000-4000-8000-000000000001";
const SAM = "f0000000-0000-4000-8000-000000000001";
const EMAIL = "a0000000-0000-4000-8000-0000000000f1";

export function AdminForms() {
  const [problem, setProblem] = useState<Problem | null>(null);
  const [said, setSaid] = useState("");
  const run = async (what: string, method: string, path: string, json?: unknown) => {
    const r = await call(method, path, json);
    setProblem(r.ok ? null : r.problem);
    setSaid(r.ok ? `${what}: ${JSON.stringify(r.value ?? "done")}` : "");
  };
  const [viewAs, setViewAs] = useState("");
  return (
    <>
      <ProblemNote problem={problem} />
      {said && <p>{said}</p>}
      <section>
        <h2>Custom roles</h2>
        <button onClick={() => run("role", "POST", "/api/roles", { workspaceId: ACME, name: "Escalations", perms: ["work"] })}>
          Make the role Escalations (works any ticket it is given on)
        </button>
      </section>
      <section>
        <h2>The vendor's support</h2>
        <button onClick={() => run("support access", "POST", "/api/support-access", { workspaceId: ACME, staffId: SAM, days: 3 })}>
          Let Sam (the vendor's staff) in for 3 days
        </button>
      </section>
      <section>
        <h2>View as</h2>
        <input placeholder="a person's id" value={viewAs} onChange={(e) => setViewAs(e.target.value)} size={40} />
        <button onClick={() => run("view as", "POST", "/api/view-as", { user: viewAs })}>View the app as them</button>
        <button onClick={() => run("view as", "POST", "/api/view-as", { user: null })}>Stop</button>
      </section>
      <section>
        <h2>The email intake</h2>
        <button onClick={() => run("key", "POST", `/api/integrations/${EMAIL}/keys`, { name: "mail server" })}>
          Make a key for the email intake (scope intake, shown once)
        </button>
      </section>
    </>
  );
}
