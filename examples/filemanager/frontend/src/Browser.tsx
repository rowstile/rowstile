import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, FileRow, Folder, FolderPage, Kind, previewable, Relation, size, User } from "./api";
import { go } from "./route";
import { PreviewDialog, VersionsDialog } from "./FileDialogs";
import { ShareDialog } from "./ShareDialog";

type Dialog = { share: { kind: Kind; id: number; name: string } } | { move: { kind: Kind; id: number; name: string } }
  | { preview: { id: number; name: string } } | { versions: { id: number; name: string; canEdit: boolean } } | null;

export function Browser({ folderId, me }: { folderId: number | null; me: User }) {
  const [page, setPage] = useState<FolderPage | null>(null);
  const [home, setHome] = useState<{ folders: Folder[]; files: FileRow[] } | null>(null);
  const [missing, setMissing] = useState(false);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<Dialog>(null);
  const [progress, setProgress] = useState("");
  const upload = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    setError(""); setMissing(false);
    try {
      if (folderId === null) { setHome(await api.home()); setPage(null); }
      else { setPage(await api.folder(folderId)); setHome(null); }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setMissing(true);
      else setError(String(e instanceof Error ? e.message : e));
    }
  }, [folderId]);
  useEffect(() => { load(); }, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  if (missing && folderId !== null) return <NoAccess folderId={folderId} me={me} onGranted={load} />;
  const perms = new Set(page?.perms ?? []);
  const canEdit = folderId === null || perms.has("edit");
  const folders = page?.folders ?? home?.folders ?? [];
  const files = page?.files ?? home?.files ?? [];

  const newFolder = () => {
    const name = prompt("Name of the new folder");
    if (name) act(() => api.createFolder(name, folderId));
  };
  const rename = (kind: Kind, id: number, old: string) => {
    const name = prompt("New name", old);
    if (name && name !== old) act(() => kind === "folder" ? api.changeFolder(id, { name }) : api.changeFile(id, { name }));
  };
  const remove = (kind: Kind, id: number, name: string) => {
    if (confirm(`Delete ${name}?`)) act(() => kind === "folder" ? api.deleteFolder(id) : api.deleteFile(id));
  };
  const download = (id: number) => act(async () => { window.location.href = (await api.downloadUrl(id)).url; });

  return (
    <section>
      <div className="crumbs">
        <a href="#/">My files</a>
        {page?.path.map((p) => <span key={p.id}> / <a href={`#/folder/${p.id}`}>{p.name}</a></span>)}
      </div>
      <div className="toolbar">
        {canEdit && <button onClick={newFolder}>New folder</button>}
        {canEdit && folderId !== null && <>
          <button onClick={() => upload.current?.click()}>Upload</button>
          <input ref={upload} type="file" multiple hidden onChange={(e) => {
            const chosen = Array.from(e.target.files ?? []);
            e.target.value = "";
            act(async () => {
              try {
                for (const [i, f] of chosen.entries())
                  await api.upload(folderId, f, (x) => setProgress(`Uploading ${f.name} (${i + 1} of ${chosen.length}): ${Math.round(x * 100)}%`));
              } finally { setProgress(""); }
            });
          }} />
        </>}
        {page && perms.has("share") && <>
          <button onClick={() => setDialog({ share: { kind: "folder", id: page.folder.id, name: page.folder.name } })}>Share</button>
          <button onClick={() => act(async () => go(`/review/${(await api.startReview("folder", page.folder.id)).id}`))}>Review access</button>
          <label className="check" title="Whether people who may use the folder above may also use this one">
            <input type="checkbox" checked={page.folder.inherit}
                   onChange={(e) => act(() => api.changeFolder(page.folder.id, { inherit: e.target.checked }))} />
            Access from the folder above
          </label>
        </>}
      </div>
      {progress && <p className="hint">{progress}</p>}
      {error && <p className="error">{error}</p>}
      {folders.length === 0 && files.length === 0 && (page || home) && <p className="empty">Nothing here yet.</p>}
      <table className="list">
        <tbody>
          {folders.map((f) => (
            <tr key={`d${f.id}`}>
              <td className="name"><a href={`#/folder/${f.id}`}>📁 {f.name}</a>
                {home && f.owner_id !== me.id && <span className="tag">shared with you</span>}
                {!f.inherit && <span className="tag">own access</span>}</td>
              <td />
              <td className="actions">
                {f.can_share && <button className="link" onClick={() => setDialog({ share: { kind: "folder", id: f.id, name: f.name } })}>Share</button>}
                <button className="link" onClick={() => rename("folder", f.id, f.name)}>Rename</button>
                {f.can_share && <>
                  <button className="link" onClick={() => setDialog({ move: { kind: "folder", id: f.id, name: f.name } })}>Move</button>
                  <button className="link" onClick={() => remove("folder", f.id, f.name)}>Delete</button>
                </>}
              </td>
            </tr>))}
          {files.map((f) => (
            <tr key={`f${f.id}`}>
              <td className="name"><button className="link" onClick={() =>
                previewable(f.content_type) ? setDialog({ preview: { id: f.id, name: f.name } }) : download(f.id)}>📄 {f.name}</button>
                {home && f.owner_id !== me.id && <span className="tag">shared with you</span>}</td>
              <td className="size">{size(f.size)}</td>
              <td className="actions">
                <button className="link" onClick={() => setDialog({ share: { kind: "file", id: f.id, name: f.name } })}>Share</button>
                <button className="link" onClick={() => setDialog({ versions: { id: f.id, name: f.name, canEdit } })}>Versions</button>
                <button className="link" onClick={() => rename("file", f.id, f.name)}>Rename</button>
                <button className="link" onClick={() => setDialog({ move: { kind: "file", id: f.id, name: f.name } })}>Move</button>
                <button className="link" onClick={() => remove("file", f.id, f.name)}>Delete</button>
              </td>
            </tr>))}
        </tbody>
      </table>
      {dialog && "share" in dialog && <ShareDialog {...dialog.share} onClose={() => { setDialog(null); load(); }} />}
      {dialog && "move" in dialog && <MoveDialog {...dialog.move} onClose={() => { setDialog(null); load(); }} />}
      {dialog && "preview" in dialog && <PreviewDialog {...dialog.preview} onClose={() => setDialog(null)} />}
      {dialog && "versions" in dialog && <VersionsDialog {...dialog.versions} onClose={() => { setDialog(null); load(); }} />}
    </section>
  );
}

/** A folder the user can't see: it may not exist, or not be shared with them. Ask, or (support) break the glass. */
function NoAccess({ folderId, me, onGranted }: { folderId: number; me: User; onGranted: () => void }) {
  const [relation, setRelation] = useState<Relation>("viewer");
  const [reason, setReason] = useState("");
  const [duration, setDuration] = useState("7 days");
  const [done, setDone] = useState("");
  const [error, setError] = useState("");
  const run = async (fn: () => Promise<unknown>, message: string) => {
    setError("");
    try { await fn(); setDone(message); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <section className="narrow">
      <h2>No access</h2>
      <p>This folder doesn't exist, or it isn't shared with you.</p>
      {done ? <p className="ok">{done}</p> : <>
        <h3>Ask for access</h3>
        <p className="hint">If the folder exists, the people who may share it will see your request.</p>
        <label>Access <select value={relation} onChange={(e) => setRelation(e.target.value as Relation)}>
          <option value="viewer">view</option><option value="editor">edit</option></select></label>
        <label>For <select value={duration} onChange={(e) => setDuration(e.target.value)}>
          <option>1 day</option><option>7 days</option><option>30 days</option></select></label>
        <label>Why <input value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        <button disabled={!reason} onClick={() => run(() => api.requestAccess("folder", folderId, relation, reason, duration), "Request sent.")}>
          Ask</button>
        {me.is_support && <>
          <h3>Break the glass</h3>
          <p className="hint">Support only: view access for a short time, recorded in the audit trail and announced.</p>
          <button disabled={!reason} className="danger" onClick={() => run(async () => {
            await api.breakGlass(folderId, reason, "1 hour"); onGranted();
          }, "You have view access for an hour.")}>View for an hour</button>
        </>}
      </>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

/** Pick where to move something: browse the folders the user can see. */
function MoveDialog({ kind, id, name, onClose }: { kind: Kind; id: number; name: string; onClose: () => void }) {
  const [at, setAt] = useState<number | null>(null);
  const [list, setList] = useState<Folder[]>([]);
  const [path, setPath] = useState<{ id: number; name: string }[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    (at === null ? api.home().then((h) => { setList(h.folders); setPath([]); })
                 : api.folder(at).then((p) => { setList(p.folders); setPath(p.path); })).catch((e) => setError(String(e.message ?? e)));
  }, [at]);
  const move = async () => {
    setError("");
    try {
      if (kind === "folder") await api.changeFolder(id, at === null ? { to_top: true } : { parent_id: at });
      else if (at !== null) await api.changeFile(id, { folder_id: at });
      onClose();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <div className="modal" onClick={onClose}><div className="box" onClick={(e) => e.stopPropagation()}>
      <h3>Move {name}</h3>
      <div className="crumbs">
        <button className="link" onClick={() => setAt(null)}>My files</button>
        {path.map((p) => <span key={p.id}> / <button className="link" onClick={() => setAt(p.id)}>{p.name}</button></span>)}
      </div>
      <ul className="pick">
        {list.filter((f) => !(kind === "folder" && f.id === id)).map((f) =>
          <li key={f.id}><button className="link" onClick={() => setAt(f.id)}>📁 {f.name}</button></li>)}
      </ul>
      {error && <p className="error">{error}</p>}
      <div className="buttons">
        <button onClick={move} disabled={kind === "file" && at === null}>Move here</button>
        <button className="link" onClick={onClose}>Cancel</button>
      </div>
    </div></div>
  );
}
