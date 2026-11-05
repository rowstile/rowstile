"use client";
// Live: the page follows the user's shape of a table through the app's shape route (Electric behind it), and
// renders again from the server when a row arrives, changes or leaves. What the user sees is still read as them.
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { ShapeStream, isControlMessage } from "@electric-sql/client";
import { Rows } from "@/live.ts";

export function LiveRefresh({ table, onChange }: { table: "tickets" | "comments"; onChange?: () => void }) {
  const router = useRouter();
  useEffect(() => {
    const stop = new AbortController();
    const rows = new Rows();
    let ready = false;
    const stream = new ShapeStream({ url: new URL(`/api/shapes/${table}`, location.origin).toString(), signal: stop.signal });
    const off = stream.subscribe((messages) => {
      let changed = false;
      for (const m of messages) {
        changed = rows.apply(m) || changed;
        if (isControlMessage(m) && m.headers.control === "up-to-date" && !ready) { ready = true; changed = false; }
      }
      if (ready && changed) (onChange ?? router.refresh)();
    }, () => {});
    return () => { off(); stop.abort(); };
  }, [table, onChange, router]);
  return null;
}
