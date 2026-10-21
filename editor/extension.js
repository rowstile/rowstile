// Starts the rowstile language server (`rowstile lsp`) for .authz files. Everything else is in the server.
// Plain JavaScript, typed with JSDoc and checked strictly (editor/tsconfig.json).
const vscode = require("vscode");
const { LanguageClient } = require("vscode-languageclient/node");

/** @type {import("vscode-languageclient/node").LanguageClient | undefined} */
let client;

function start() {
  const [command = "rowstile", ...args] = vscode.workspace.getConfiguration("rowstile").get("command", ["rowstile", "lsp"]);
  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;     // where rowstile.toml is looked for
  // On Windows an npm install makes `rowstile.cmd`, which only a shell starts. The shell is given one line:
  // what holds a space is quoted.
  const windows = process.platform === "win32";
  const word = (/** @type {string} */ s) => (windows && /\s/.test(s) && !s.startsWith('"') ? `"${s}"` : s);
  const started = new LanguageClient("rowstile", "rowstile",
    { command: word(command), args: args.map(word), options: { cwd, shell: windows } },
    { documentSelector: [{ language: "authz" }] });
  client = started;
  // The client's own message says only that it couldn't connect: this one says what to do
  started.start().catch(async (/** @type {unknown} */ error) => {
    const why = error instanceof Error ? error.message : String(error);
    const choice = await vscode.window.showErrorMessage(
      `rowstile: the language server didn't start (${why}). Install rowstile (https://rowstile.dev/installing), ` +
      "or set rowstile.command to how to start it.", "Open settings");
    if (choice) await vscode.commands.executeCommand("workbench.action.openSettings", "rowstile.command");
  });
}

/** Stops the running server; one that didn't start has nothing to stop. */
async function stop() {
  const stopping = client;
  client = undefined;
  if (stopping?.isRunning()) await stopping.stop();
}

/** @param {import("vscode").ExtensionContext} context */
function activate(context) {
  start();
  // a new rowstile.command starts the server again with it
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration(async (event) => {
    if (event.affectsConfiguration("rowstile.command")) {
      await stop();
      start();
    }
  }));
}

function deactivate() {
  return stop();
}

module.exports = { activate, deactivate };
