import { Suspense } from "react";
import { inTx } from "@/db.ts";

// The tickets the database shows the user: an agent sees the workspace's, and works those of their teams; a
// customer sees their own (and their org's, where it shares them). The page asks which ones the user works.
async function Tickets() {
  const { tickets, mine } = await inTx(async (tx) => {
    const tickets = await tx.ticket.findMany({
      select: { id: true, subject: true, status: true, requester: { select: { name: true } }, team: { select: { name: true } } },
      orderBy: { createdAt: "desc" },
    });
    const work = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM authz.list('ticket', 'work') AS id`;
    return { tickets, mine: new Set(work.map((w) => w.id)) };
  });
  if (tickets.length === 0) return <p>No tickets.</p>;
  return (
    <table>
      <thead><tr><th>Subject</th><th>Requester</th><th>Team</th><th>Status</th><th></th></tr></thead>
      <tbody>
        {tickets.map((t) => (
          <tr key={t.id}>
            <td><a href={`/tickets/${t.id}`}>{t.subject}</a></td>
            <td>{t.requester.name}</td>
            <td>{t.team?.name ?? ""}</td>
            <td>{t.status}</td>
            <td>{mine.has(t.id) && <span className="tag">yours to work</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Page() {
  return (
    <>
      <h1>Inbox</h1>
      <Suspense fallback={<p>loading</p>}><Tickets /></Suspense>
    </>
  );
}
