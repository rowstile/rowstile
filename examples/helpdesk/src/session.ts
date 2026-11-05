// Who the request is. The example has no identity provider: its sign-in page picks a person, and the session is a
// cookie signed with HD_SESSION_SECRET (an HMAC), so a browser can't name someone else. A real app reads its own
// session here (Auth.js's auth(), say); the database decides everything else.
import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";

const COOKIE = "hd_session";
const secret = (): string => {
  const s = process.env.HD_SESSION_SECRET;
  if (!s || s.length < 32) throw new Error("HD_SESSION_SECRET: 32 characters or more");
  return s;
};
const sign = (text: string): string => createHmac("sha256", secret()).update(text).digest("base64url");

/** The session: who signed in, and whom an admin views the app as (authz.view_as), if anyone. */
export interface Session {
  user: string;
  viewAs?: string;
}

export function sealed(session: Session): string {
  const text = Buffer.from(JSON.stringify(session)).toString("base64url");
  return `${text}.${sign(text)}`;
}

export function opened(value: string | undefined): Session | null {
  if (!value) return null;
  const [text, mac] = value.split(".");
  if (!text || !mac) return null;
  const want = Buffer.from(sign(text));
  const got = Buffer.from(mac);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
  const s = JSON.parse(Buffer.from(text, "base64url").toString()) as Session;
  return typeof s.user === "string" ? s : null;
}

export async function session(): Promise<Session | null> {
  return opened((await cookies()).get(COOKIE)?.value);
}

export async function setSession(s: Session | null): Promise<void> {
  const jar = await cookies();
  if (s) jar.set(COOKIE, sealed(s), { httpOnly: true, sameSite: "lax", path: "/" });
  else jar.delete(COOKIE);
}
