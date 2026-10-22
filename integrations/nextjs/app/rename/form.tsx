"use client";
// A form that renames a note with the server action (app/actions.ts): the browser posts to the action, and shows
// what it answers, the note's id or the problem
import { useState } from "react";
import { renameNote } from "../actions";

export function RenameForm({ id }: { id: number }) {
  const [said, setSaid] = useState("");
  async function rename(data: FormData) {
    const r = await renameNote(id, String(data.get("body") ?? ""));
    setSaid(r.ok ? `renamed ${r.value}` : r.problem.detail);
  }
  return (
    <form action={rename}>
      <input name="body" />
      <button type="submit">rename</button>
      <p id="said">{said}</p>
    </form>
  );
}
