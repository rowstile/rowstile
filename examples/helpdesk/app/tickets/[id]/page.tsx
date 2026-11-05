import { Suspense } from "react";
import { TicketView } from "@/ui/ticket.tsx";

async function Ticket({ params }: { params: Promise<{ id: string }> }) {
  return <TicketView id={(await params).id} />;
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <Suspense fallback={<p>loading</p>}><Ticket params={params} /></Suspense>;
}
