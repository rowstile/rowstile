// A server component that renders the React kit: <Can> under the layout's <AuthzProvider>. The server renders
// the fallback; the browser asks the routes (authzRoutes) and shows the button.
import { Can } from "@rowstile/react";

export default function Buttons() {
  return (
    <Can type="project" id={1} perm="edit" fallback={<span id="rename">no rename yet</span>}>
      <button id="rename">rename</button>
    </Can>
  );
}
