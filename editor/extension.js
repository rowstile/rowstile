// Starts the rowstile language server (`rowstile lsp`) for .authz files. Everything else is in the server.
// Plain JavaScript, typed with JSDoc and checked strictly (editor/tsconfig.json).
const vscode = require("vscode");
const { LanguageClient } = require("vscode-languageclient/node");

/** @type {import("vscode-languageclient/node").LanguageClient | undefined} */
let client;
/** The last start, settled either way: a client still starting can't be stopped, so stop() waits for it. */
let starting = Promise.resolve();
/** The last restart, settled either way: restarts run one after the other, so only the last one's server is left. */
let restarting = Promise.resolve();
/**
 * The servers' log, one for all of them: kept across restarts, closed with the extension.
 * @type {import("vscode").OutputChannel | undefined}
 */
let log;

function start() {
  // In Restricted Mode, highlighting only: rowstile.command is a program to run, and the server reads the folder
  if (!vscode.workspace.isTrusted) return;
  const [command = "rowstile", ...args] = vscode.workspace.getConfiguration("rowstile").get("command", ["rowstile", "lsp"]);
  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;     // where rowstile.toml is looked for
  // On Windows an npm install makes `rowstile.cmd`, which only a shell starts. The shell is given one line: what
  // holds a space or a character cmd.exe reads (& | < > ^ ( )) is quoted. (A % stays as cmd.exe reads it.)
  const windows = process.platform === "win32";
  const word = (/** @type {string} */ s) => (windows && /[\s&|<>^()]/.test(s) && !s.startsWith('"') ? `"${s}"` : s);
  // Files, and new ones not saved yet; not the other side of a diff (git:), which has the file's path
  const documentSelector = ["file", "untitled"].map((scheme) => ({ scheme, language: "authz" }));
  const started = new LanguageClient("rowstile", "rowstile",
    { command: word(command), args: args.map(word), options: { cwd, shell: windows } },
    { documentSelector, outputChannel: log });
  client = started;
  const run = started.start();
  starting = run.then(() => undefined, () => undefined);
  // The client's own message says only that it couldn't connect: this one says what to do
  run.catch(async (/** @type {unknown} */ error) => {
    started.diagnostics?.dispose();    // it can't be stopped, and holds nothing
    const why = error instanceof Error ? error.message : String(error);
    const choice = await vscode.window.showErrorMessage(
      `rowstile: the language server didn't start (${why}). Install rowstile (https://rowstile.dev/installing), ` +
      "or set rowstile.command to how to start it.", "Open settings");
    if (choice) await vscode.commands.executeCommand("workbench.action.openSettings", "rowstile.command");
  });
}

/** Stops the server, once it has started; one that didn't start has nothing to stop. */
async function stop() {
  const stopping = client;
  const started = starting;
  client = undefined;
  await started;
  if (stopping?.isRunning()) await stopping.stop();
}

/** Runs step once the restarts before it are done. @param {() => unknown} step */
function after(step) {
  const next = restarting.then(step);
  restarting = next.then(() => undefined, () => undefined);
  return next;
}

/** @param {import("vscode").ExtensionContext} context */
function activate(context) {
  log = vscode.window.createOutputChannel("rowstile");
  context.subscriptions.push(log);
  start();
  // a new rowstile.command starts the server again with it, and trusting the folder starts it
  const restart = () => after(() => stop().finally(start));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((event) =>
    event.affectsConfiguration("rowstile.command") ? restart() : undefined));
  context.subscriptions.push(vscode.workspace.onDidGrantWorkspaceTrust(restart));
}

function deactivate() {
  return after(stop);
}

module.exports = { activate, deactivate };
