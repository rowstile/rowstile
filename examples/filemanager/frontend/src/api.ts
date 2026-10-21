// The backend's HTTP API. The session is a cookie; the database decides what each call may see and do.

export type Kind = "folder" | "file";
export type Relation = "viewer" | "editor";

export interface User { id: string; email: string; name: string; is_support?: boolean; used?: number; quota?: number }
export interface Version { id: number; file_id: number; size: number; content_type: string; created_at: string;
                           created_by: string; created_by_name: string; current: boolean }
export interface Group { id: string; name: string; parent_id: string | null; member: boolean; manage: boolean }
export interface Member { id: string; email: string; name: string; is_admin: boolean }
export interface Folder { id: number; parent_id: number | null; name: string; owner_id: string; inherit: boolean; created_at: string; mine?: boolean }
export interface FileRow { id: number; folder_id: number; name: string; owner_id: string; size: number; content_type: string; created_at: string; updated_at: string }
/** A page of search results: each list's next page starts at its cursor in `next` (null: no more). */
export interface SearchPage { folders: Folder[]; files: FileRow[]; next: { folder: string | null; file: string | null } }
export interface FolderPage { folder: Folder; path: { id: number; name: string }[]; folders: Folder[]; files: FileRow[]; perms: string[] }
export interface ShareRow { relation: Relation; subject_type: "user" | "group"; subject_id: string; subject_relation: string;
                            subject_name: string | null; expires_at: string | null; created_by: string | null }
export interface RequestRow { id: number; object_type: Kind; object_id: string; relation: Relation; requester: string;
                              reason: string; duration: string | null; created_at: string; mine: boolean; requester_name?: string | null }
export interface ReviewItem { item: number; relation: string; subject_type: string; subject_id: string; subject_relation: string;
                              subject_name?: string | null;
                              expires_at: string | null; keep: boolean | null; decided_by: string | null }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function call<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const init: RequestInit = { method, credentials: "same-origin", headers: { ...headers } };
  if (body instanceof FormData) init.body = body;
  else if (body !== undefined) {
    init.body = JSON.stringify(body);
    (init.headers as Record<string, string>)["Content-Type"] = "application/json";
  }
  const r = await fetch(path, init);
  if (!r.ok) {
    let detail = r.statusText;
    try { const j = await r.json(); detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* not JSON */ }
    throw new ApiError(r.status, detail);
  }
  return r.status === 204 ? (undefined as T) : r.json();
}

const plural = (kind: Kind) => `${kind}s`;

export const api = {
  me: () => call<User>("GET", "/api/me"),
  signUp: (email: string, name: string, password: string) => call<User>("POST", "/api/signup", { email, name, password }),
  logIn: (email: string, password: string) => call<User>("POST", "/api/login", { email, password }),
  logOut: () => call<void>("POST", "/api/logout"),
  users: (q: string) => call<User[]>("GET", `/api/users?q=${encodeURIComponent(q)}`),
  groups: () => call<Group[]>("GET", "/api/groups"),

  home: () => call<{ folders: Folder[]; files: FileRow[] }>("GET", "/api/home"),
  folder: (id: number) => call<FolderPage>("GET", `/api/folders/${id}`),
  createFolder: (name: string, parent_id: number | null) => call<Folder>("POST", "/api/folders", { name, parent_id }),
  changeFolder: (id: number, change: { name?: string; parent_id?: number; to_top?: boolean; inherit?: boolean }) =>
    call<Folder>("PATCH", `/api/folders/${id}`, change),
  deleteFolder: (id: number) => call<void>("DELETE", `/api/folders/${id}`),
  /** Straight to storage: a row first, then the bytes to a signed link, then marked ready. */
  upload: async (folderId: number, file: File, onProgress?: (fraction: number) => void): Promise<FileRow> => {
    const type = file.type || "application/octet-stream";
    const { file: row, url } = await call<{ file: FileRow; url: string }>("POST", `/api/folders/${folderId}/uploads`,
      { name: file.name, size: file.size, content_type: type });
    await putBytes(url, file, type, onProgress);
    return call<FileRow>("POST", `/api/files/${row.id}/ready`);
  },
  /** A new version of a file, the same way; it becomes current when ready. */
  uploadVersion: async (fileId: number, file: File, onProgress?: (fraction: number) => void): Promise<FileRow> => {
    const type = file.type || "application/octet-stream";
    const { version, url } = await call<{ version: Version; url: string }>("POST", `/api/files/${fileId}/versions`,
      { name: file.name, size: file.size, content_type: type });
    await putBytes(url, file, type, onProgress);
    return call<FileRow>("POST", `/api/versions/${version.id}/ready`);
  },
  versions: (fileId: number) => call<Version[]>("GET", `/api/files/${fileId}/versions`),
  restoreVersion: (id: number) => call<FileRow>("POST", `/api/versions/${id}/restore`),
  versionUrl: (id: number) => call<{ url: string }>("GET", `/api/versions/${id}/download`),
  previewUrl: (id: number) => call<{ url: string; content_type: string }>("GET", `/api/files/${id}/download?preview=true`),
  search: (q: string, more?: { kind: Kind; after: string }) => call<SearchPage>("GET", `/api/search?q=${encodeURIComponent(q)}` +
    (more ? `&kind=${more.kind}&after=${encodeURIComponent(more.after)}` : "")),
  createGroup: (name: string, parent_id: string | null) => call<Group>("POST", "/api/groups", { name, parent_id }),
  renameGroup: (id: string, name: string) => call<void>("PATCH", `/api/groups/${id}`, { name }),
  deleteGroup: (id: string) => call<void>("DELETE", `/api/groups/${id}`),
  members: (id: string) => call<{ members: Member[]; manage: boolean }>("GET", `/api/groups/${id}/members`),
  addMember: (id: string, user_id: string, is_admin: boolean) => call<void>("POST", `/api/groups/${id}/members`, { user_id, is_admin }),
  removeMember: (id: string, user_id: string) => call<void>("DELETE", `/api/groups/${id}/members/${user_id}`),
  downloadUrl: (id: number) => call<{ url: string }>("GET", `/api/files/${id}/download`),
  changeFile: (id: number, change: { name?: string; folder_id?: number }) => call<FileRow>("PATCH", `/api/files/${id}`, change),
  deleteFile: (id: number) => call<void>("DELETE", `/api/files/${id}`),

  shares: (kind: Kind, id: number) => call<ShareRow[]>("GET", `/api/${plural(kind)}/${id}/shares`),
  share: (kind: Kind, id: number, s: { relation: Relation; subject_type: "user" | "group"; subject_id: string; expires_at?: string | null }) =>
    call<void>("POST", `/api/${plural(kind)}/${id}/shares`, s),
  unshare: (kind: Kind, id: number, s: { relation: Relation; subject_type: "user" | "group"; subject_id: string }) =>
    call<void>("DELETE", `/api/${plural(kind)}/${id}/shares`, s),
  access: (kind: Kind, id: number, perm: string) => call<User[]>("GET", `/api/${plural(kind)}/${id}/access?perm=${perm}`),
  why: (kind: Kind, id: number, perm: string) => call<{ lines: string[] }>("GET", `/api/${plural(kind)}/${id}/why?perm=${perm}`),

  links: (kind: Kind, id: number) => call<{ id: string; created_at: string; expires_at: string | null; created_by: string }[]>(
    "GET", `/api/${plural(kind)}/${id}/links`),
  createLink: (kind: Kind, id: number, expires_at: string | null) =>
    call<{ token: string; path: string }>("POST", `/api/${plural(kind)}/${id}/links`, { expires_at }),
  revokeLink: (kind: Kind, id: number, linkId: string) => call<void>("DELETE", `/api/${plural(kind)}/${id}/links/${linkId}`),
  // opened with a share link: the token goes in a header, not the URL the server sees
  publicFolder: (id: number, token: string) =>
    call<Omit<FolderPage, "perms">>("GET", `/api/public/folders/${id}`, undefined, { "X-Link-Token": token }),
  publicFile: (id: number, token: string) => call<FileRow>("GET", `/api/public/files/${id}`, undefined, { "X-Link-Token": token }),
  publicDownload: (id: number, token: string) =>
    call<{ url: string }>("GET", `/api/public/files/${id}/download`, undefined, { "X-Link-Token": token }),
  requestAccess: (kind: Kind, id: number, relation: Relation, reason: string, duration: string) =>
    call<{ id: number }>("POST", `/api/${plural(kind)}/${id}/requests`, { relation, reason, duration }),
  requests: () => call<RequestRow[]>("GET", "/api/requests"),
  decide: (id: number, approve: boolean, note?: string) => call<void>("POST", `/api/requests/${id}/decision`, { approve, note }),
  cancelRequest: (id: number) => call<void>("DELETE", `/api/requests/${id}`),

  startReview: (kind: Kind, id: number) => call<{ id: number }>("POST", `/api/${plural(kind)}/${id}/reviews`),
  review: (id: number) => call<ReviewItem[]>("GET", `/api/reviews/${id}`),
  reviewDecide: (id: number, item: number, keep: boolean) => call<void>("POST", `/api/reviews/${id}/items/${item}`, { keep }),
  closeReview: (id: number, revoke_undecided: boolean) => call<{ revoked: number }>("POST", `/api/reviews/${id}/close`, { revoke_undecided }),

  breakGlass: (folderId: number, reason: string, duration: string) =>
    call<void>("POST", `/api/folders/${folderId}/break-glass`, { reason, duration }),
};

function putBytes(url: string, file: File, type: string, onProgress?: (fraction: number) => void): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url);
    xhr.setRequestHeader("Content-Type", type);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
    xhr.onload = () => (xhr.status < 300 ? resolve() : reject(new ApiError(xhr.status, `storage refused the upload (${xhr.status})`)));
    xhr.onerror = () => reject(new ApiError(0, "the upload failed"));
    xhr.send(file);
  });
}

export const previewable = (type: string) =>
  /^(image\/(png|jpeg|gif|webp)|application\/pdf|text\/plain|audio\/(mpeg|ogg)|video\/(mp4|webm))$/.test(type);

export function size(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}
