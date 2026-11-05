"use client";
import { useRouter } from "next/navigation";
import { call } from "./api.ts";

export function SignIn({ people }: { people: string[][] }) {
  const router = useRouter();
  const signIn = async (email: string) => {
    const r = await call("POST", "/api/session", { email });
    if (r.ok) router.push("/inbox");
  };
  return (
    <ul>
      {people.map(([email, who]) => (
        <li key={email}><button onClick={() => signIn(email)}>{email}</button> {who}</li>
      ))}
    </ul>
  );
}
