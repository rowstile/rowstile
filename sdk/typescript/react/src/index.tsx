/**
 * rowstile for React: which buttons to show, a headless share dialog, access requests, kept current.
 *
 *     <AuthzProvider endpoint="/api/authz">          // the routes of @rowstile/next's authzRoutes
 *       const perms = usePerms("folder", folderIds); // one call for the whole list
 *       {perms(id).can("edit") && <RenameButton id={id} />}
 *       <Can type="folder" id={id} perm="edit"><RenameButton id={id} /></Can>
 *       <ShareDialog type="folder" id={id}>{(d) => <YourDialog {...d} />}</ShareDialog>
 *
 * The answers only decide what to show: the database decides what happens. With live updates on (the
 * default, when the routes have a change feed), every hook asks again when access may have changed. The
 * answers are the signed-in user's: give the provider `user` (their id, or null) if the user can change
 * without a page load, and the hooks ask again for the new one.
 *
 * A client module ("use client"): a server component, such as the App Router's app/layout.tsx, renders the
 * provider and the components as it renders its own.
 */
"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Id, ObjectType, Permission, Problem, Share, SharedRelation, SharedType } from "@rowstile/client";

interface Settings {
  endpoint: string;
  fetch: typeof fetch;
  /** Goes up whenever the server says access may have changed. */
  version: number;
  /** Who is signed in, as the app says it: when it changes, every hook asks again. */
  user: string | number | null | undefined;
}

const Context = createContext<Settings | null>(null);

export interface ProviderProps {
  /** Where authzRoutes is mounted. */
  endpoint?: string;
  /** Live updates over server-sent events (GET <endpoint>/events). */
  live?: boolean;
  /** For tests and other hosts: the fetch to use. */
  fetch?: typeof fetch;
  /** Who is signed in (their id, or null): the answers are theirs, so when this changes (a sign-out, another
   *  account, without a page load) every hook forgets what it had and asks again. */
  user?: string | number | null;
  children?: ReactNode;
}

export function AuthzProvider({ endpoint = "/api/authz", live = true, fetch: f, user, children }: ProviderProps) {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    if (!live || typeof EventSource === "undefined") return;
    const source = new EventSource(`${endpoint}/events`);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const again = () => {
      clearTimeout(timer);                            // many changes at once: ask again once
      timer = setTimeout(() => setVersion((v) => v + 1), 50);
    };
    source.addEventListener("changed", again);
    // the stream opened again after a gap: what changed meanwhile was never said
    let opened = false;
    source.addEventListener("open", () => {
      if (opened) again();
      opened = true;
    });
    return () => {
      clearTimeout(timer);
      source.close();
    };
  }, [endpoint, live]);
  const value = useMemo<Settings>(() => ({ endpoint, fetch: f ?? ((...a) => fetch(...a)), version, user }),
    [endpoint, f, version, user]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

function useSettings(): Settings {
  const s = useContext(Context);
  if (!s) throw new Error("@rowstile/react: wrap the app in <AuthzProvider>");
  return s;
}

/** An error the routes answered with: its problem body. */
export class AuthzRequestError extends Error {
  constructor(public problem: Problem) {
    super(problem.detail || problem.title);
    this.name = "AuthzRequestError";
  }
}

async function call<R>(s: Settings, path: string, body?: object): Promise<R> {
  const r = await s.fetch(`${s.endpoint}/${path}`, body === undefined ? { headers: { accept: "application/json" } }
    : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const out = await r.json().catch(() => ({ title: r.statusText, status: r.status, detail: "" }));
  if (!r.ok) throw new AuthzRequestError(out as Problem);
  return out as R;
}

// an id as the database writes it: a composite key as a row, every field quoted; a key of one column given as
// an array is that value (idText in @rowstile/client)
const key = (id: Id): string => (Array.isArray(id)
  ? id.length === 1 ? String(id[0]) : "(" + id.map((v) => '"' + String(v).replace(/["\\]/g, (c) => "\\" + c) + '"').join(",") + ")"
  : String(id));

export interface ObjectPerms<T extends ObjectType> {
  /** Whether the user holds perm on it (false while loading). */
  can(perm: Permission<T>): boolean;
  perms: Permission<T>[];
}

/** The user's permissions on many objects, in one call: perms(id).can("edit"). */
export function usePerms<T extends ObjectType>(type: T, ids: readonly Id[]): ((id: Id) => ObjectPerms<T>) & {
  loading: boolean;
  error: Error | null;
} {
  const s = useSettings();
  const list = ids.map((id) => "ids=" + encodeURIComponent(key(id))).join("&");
  const [state, setState] = useState<{ list: string; user: Settings["user"]; perms: Record<string, Permission<T>[]>; error: Error | null } | null>(null);
  useEffect(() => {
    let live = true;
    const user = s.user;
    if (!list) {
      setState({ list, user, perms: {}, error: null });
      return;
    }
    // a long list goes in a body: a URL has a limit (the server's header size)
    const asked = list.length > 1500
      ? call<Record<string, Permission<T>[]>>(s, "perms", { type, ids: ids.map(key) })
      : call<Record<string, Permission<T>[]>>(s, `perms?type=${encodeURIComponent(type)}&${list}`);
    asked.then((perms) => live && setState({ list, user, perms, error: null }),
               (error: Error) => live && setState({ list, user, perms: {}, error }));
    return () => { live = false; };
    // (ids is read through list, the text of it)
  }, [s, type, list]);
  const current = state?.list === list && state.user === s.user ? state : null;
  const perms = current?.perms ?? {};
  const of = (id: Id): ObjectPerms<T> => {
    const p = perms[key(id)] ?? [];
    return { perms: p, can: (perm) => p.includes(perm) };
  };
  return Object.assign(of, { loading: current === null, error: current?.error ?? null });
}

export interface CanProps<T extends ObjectType> {
  type: T;
  id: Id;
  perm: Permission<T>;
  children?: ReactNode;
  /** Shown when the user doesn't hold perm (and while asking). */
  fallback?: ReactNode;
}

/** Its children if the user holds perm on the object. In a list, prefer usePerms: one call for all. */
export function Can<T extends ObjectType>({ type, id, perm, children, fallback = null }: CanProps<T>) {
  const perms = usePerms(type, [id]);
  return <>{perms(id).can(perm) ? children : fallback}</>;
}

export interface ShareDialogState<T extends SharedType> {
  shares: Share[];
  loading: boolean;
  error: Error | null;
  share(relation: SharedRelation<T>, subjectType: string, subjectId: Id, subjectRelation?: string): Promise<void>;
  unshare(relation: SharedRelation<T>, subjectType: string, subjectId: Id, subjectRelation?: string): Promise<void>;
  refresh(): void;
}

/** Who an object is shared with, and sharing it: the logic of a share dialog, for your own components. */
export function useShares<T extends SharedType>(type: T, id: Id): ShareDialogState<T> {
  const s = useSettings();
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<{ shares: Share[]; error: Error | null; loading: boolean; user?: Settings["user"] }>(
    { shares: [], error: null, loading: true, user: s.user });
  const idKey = key(id);
  const user = s.user;
  useEffect(() => {
    let live = true;
    // another user's shares are never shown while this one's are asked for
    setState((st) => (st.user === user ? { ...st, loading: true } : { shares: [], error: null, loading: true, user }));
    call<Share[]>(s, `shares?type=${encodeURIComponent(type)}&id=${encodeURIComponent(idKey)}`)
      .then((shares) => live && setState({ shares, error: null, loading: false, user }),
            (error: Error) => live && setState({ shares: [], error, loading: false, user }));
    return () => { live = false; };
  }, [s, type, idKey, nonce, user]);
  const change = useCallback(async (path: "share" | "unshare", relation: string, subjectType: string, subjectId: Id, subjectRelation = "") => {
    try {
      await call(s, path, { type, id: idKey, relation, subjectType, subjectId: key(subjectId), subjectRelation });
    } finally {
      setNonce((n) => n + 1);
    }
  }, [s, type, idKey]);
  return {
    shares: state.user === user ? state.shares : [],
    error: state.user === user ? state.error : null,
    loading: state.user === user ? state.loading : true,
    share: (relation, subjectType, subjectId, subjectRelation) => change("share", relation, subjectType, subjectId, subjectRelation),
    unshare: (relation, subjectType, subjectId, subjectRelation) => change("unshare", relation, subjectType, subjectId, subjectRelation),
    refresh: () => setNonce((n) => n + 1),
  };
}

/** A headless share dialog: <ShareDialog type="folder" id={3}>{(d) => ...your markup...}</ShareDialog>. */
export function ShareDialog<T extends SharedType>({ type, id, children }: { type: T; id: Id; children: (d: ShareDialogState<T>) => ReactNode }) {
  return <>{children(useShares(type, id))}</>;
}

/** Asking for access (authz.request_access): the owner decides, and approving makes a share. */
export function useAccessRequest<T extends SharedType>(type: T, id: Id) {
  const s = useSettings();
  const [state, setState] = useState<{ status: "idle" | "sending" | "sent" | "failed"; id?: string; error?: Error }>({ status: "idle" });
  const request = useCallback(async (relation: SharedRelation<T>, reason: string) => {
    setState({ status: "sending" });
    try {
      const r = await call<{ id: string }>(s, "request", { type, id: key(id), relation, reason });
      setState({ status: "sent", id: r.id });
      return r.id;
    } catch (error) {
      setState({ status: "failed", error: error as Error });
      throw error;
    }
  }, [s, type, id]);
  return { ...state, request };
}
