import { useEffect, useState } from "react";
import { api, ApiError, size, User } from "./api";
import { Browser } from "./Browser";
import { Groups } from "./Groups";
import { LinkView } from "./LinkView";
import { Search } from "./Search";
import { Requests } from "./Requests";
import { Review } from "./Review";
import { go, useRoute } from "./route";

export function App() {
  const [me, setMe] = useState<User | null | undefined>(undefined);
  const route = useRoute();
  useEffect(() => { api.me().then(setMe, () => setMe(null)); }, []);
  if (route.page === "link") return <LinkView {...route} />;      // no sign-in needed
  if (me === undefined) return null;
  if (me === null) return <SignIn onDone={setMe} />;
  return (
    <div className="app">
      <header>
        <a className="brand" href="#/">Files</a>
        <nav>
          <a href="#/" className={route.page === "home" || route.page === "folder" ? "on" : ""}>My files</a>
          <a href="#/groups" className={route.page === "groups" ? "on" : ""}>Groups</a>
          <a href="#/requests" className={route.page === "requests" ? "on" : ""}>Requests</a>
        </nav>
        <form className="search" onSubmit={(e) => {
          e.preventDefault();
          const q = new FormData(e.currentTarget).get("q")?.toString().trim();
          if (q && q.length >= 2) go(`/search/${encodeURIComponent(q)}`);
        }}><input name="q" placeholder="Search" defaultValue={route.page === "search" ? route.q : ""} /></form>
        <span className="who">{me.name}{me.is_support ? " (support)" : ""}
          {me.quota ? <span className="hint"> · {size(me.used ?? 0)} of {size(me.quota)}</span> : null}</span>
        <button className="link" onClick={() => api.logOut().then(() => setMe(null))}>Sign out</button>
      </header>
      <main>
        {route.page === "requests" ? <Requests /> :
         route.page === "groups" ? <Groups me={me} /> :
         route.page === "search" ? <Search q={route.q} /> :
         route.page === "review" ? <Review id={route.id} /> :
         <Browser folderId={route.page === "folder" ? route.id : null} me={me} />}
      </main>
    </div>
  );
}

function SignIn({ onDone }: { onDone: (u: User) => void }) {
  const [mode, setMode] = useState<"in" | "up">("in");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      onDone(mode === "in" ? await api.logIn(email, password) : await api.signUp(email, name, password));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  };
  return (
    <form className="signin" onSubmit={submit}>
      <h1>Files</h1>
      <label>Email <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus /></label>
      {mode === "up" && <label>Name <input value={name} onChange={(e) => setName(e.target.value)} required /></label>}
      <label>Password <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} /></label>
      {error && <p className="error">{error}</p>}
      <button type="submit">{mode === "in" ? "Sign in" : "Create account"}</button>
      <button type="button" className="link" onClick={() => setMode(mode === "in" ? "up" : "in")}>
        {mode === "in" ? "Create an account" : "I have an account"}
      </button>
    </form>
  );
}
