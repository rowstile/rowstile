import { Suspense } from "react";
import { inTx } from "@/db.ts";

// A person, from the masked view: the agents' notes are null for anyone the policy doesn't let read them
async function Person({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [p] = await inTx((tx) => tx.$queryRaw<{ name: string; email: string; kind: string; notes: string | null }[]>`
    SELECT name, email, kind, notes FROM hd.users_visible WHERE id = ${id}::uuid`);
  if (!p) return <p>Not found.</p>;
  return (
    <section>
      <h1>{p.name}</h1>
      <p>{p.email} · {p.kind}</p>
      {p.notes !== null && <p className="internal">Notes: {p.notes}</p>}
    </section>
  );
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <Suspense fallback={<p>loading</p>}><Person params={params} /></Suspense>;
}
