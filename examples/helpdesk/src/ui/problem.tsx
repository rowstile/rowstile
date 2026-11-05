"use client";
import { useState } from "react";
import type { Problem } from "./api.ts";

// a refusal, and behind "why?" the database's explanation
export function ProblemNote({ problem }: { problem: Problem | null }) {
  const [open, setOpen] = useState(false);
  if (!problem) return null;
  return (
    <div className="problem" role="alert">
      {problem.detail ?? problem.title} {problem.why && <a href="#" onClick={(e) => { e.preventDefault(); setOpen(!open); }}>why?</a>}
      {open && <pre>{problem.why?.join("\n")}</pre>}
    </div>
  );
}
