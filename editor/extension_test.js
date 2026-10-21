// extension.js against stand-ins for VS Code and its language client (node extension_test.js; editor/test.sh):
// a server that doesn't start says what to do, a new rowstile.command starts it again, and it stops once.
// Plain JavaScript, typed with JSDoc and checked strictly (editor/tsconfig.json).
const assert = require("node:assert/strict");
const Module = require("node:module");

/** What the extension did, and what the stand-ins answer. */
const world = {
  /** @type {{command: string, args: string[], cwd: string | undefined}[]} */ clients: [],
  /** @type {string[]} */ stops: [],
  /** @type {(string | undefined)[][]} */ errors: [],
  /** @type {unknown[][]} */ commands: [],
  /** @type {string[]} */ setting: ["rowstile", "lsp"],
  /** @type {unknown} */ startFails: undefined,
  /** @type {string | undefined} */ choice: undefined,
  /** @type {((event: {affectsConfiguration: (name: string) => boolean}) => Promise<void>)[]} */ listeners: [],
};

class LanguageClient {
  /** @param {string} _id @param {string} _name @param {{command: string, args: string[], options: {cwd?: string}}} server */
  constructor(_id, _name, server) {
    this.command = server.command;
    this.running = false;
    this.stopped = false;
    world.clients.push({ command: server.command, args: server.args, cwd: server.options.cwd });
  }
  start() {
    if (world.startFails !== undefined) return Promise.reject(world.startFails);
    this.running = true;
    return Promise.resolve();
  }
  isRunning() {
    return this.running;
  }
  stop() {
    // vscode-languageclient 9 throws for a client that never ran ("Client is not running and can't be stopped");
    // a second stop is counted here, though it only waits for the first
    if (!this.running && !this.stopped) throw new Error("Client is not running and can't be stopped");
    this.running = false;
    this.stopped = true;
    world.stops.push(this.command);
    return Promise.resolve();
  }
}

const vscode = {
  workspace: {
    workspaceFolders: [{ uri: { fsPath: "/work/app" } }],
    getConfiguration: () => ({ get: () => world.setting }),
    /** @param {(event: {affectsConfiguration: (name: string) => boolean}) => Promise<void>} listener */
    onDidChangeConfiguration: (listener) => {
      world.listeners.push(listener);
      return { dispose: () => world.listeners.splice(world.listeners.indexOf(listener), 1) };
    },
  },
  window: {
    /** @param {string} message @param {string[]} items */
    showErrorMessage: (message, ...items) => {
      world.errors.push([message, ...items]);
      return Promise.resolve(world.choice);
    },
  },
  commands: {
    /** @param {unknown[]} args */
    executeCommand: (...args) => {
      world.commands.push(args);
      return Promise.resolve();
    },
  },
};

// extension.js asks for these two by name: it gets the stand-ins
const load = /** @type {{_load: (request: string, ...rest: unknown[]) => unknown}} */ (/** @type {unknown} */ (Module));
const realLoad = load._load;
load._load = (/** @type {string} */ request, /** @type {unknown[]} */ ...rest) =>
  request === "vscode" ? vscode : request === "vscode-languageclient/node" ? { LanguageClient } : realLoad(request, ...rest);
const extension = require("./extension.js");

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));
/** @param {string} name */
const change = async (name) => {
  for (const listener of [...world.listeners]) await listener({ affectsConfiguration: (n) => n === name });
};
/** @param {{dispose: () => unknown}[]} subscriptions */
const shutdown = async (subscriptions) => {
  // as VS Code does: the subscriptions are disposed, and deactivate() is awaited
  for (const s of subscriptions) s.dispose();
  await extension.deactivate();
};

/** @param {string} name @param {() => Promise<void>} body */
async function check(name, body) {
  Object.assign(world, { clients: [], stops: [], errors: [], commands: [], listeners: [] });
  Object.assign(world, { setting: ["rowstile", "lsp"], startFails: undefined, choice: undefined });
  try {
    await body();
    console.log(`ok    ${name}`);
  } catch (e) {
    console.log(`FAIL  ${name}\n${e instanceof Error ? e.message : e}`);
    process.exitCode = 1;
  }
}

(async () => {
  await check("a server that doesn't start says why and what to do", async () => {
    world.startFails = "Launching server using command rowstile failed. Error: spawn rowstile ENOENT";
    world.choice = "Open settings";
    /** @type {{dispose: () => unknown}[]} */ const subscriptions = [];
    extension.activate(/** @type {any} */ ({ subscriptions }));
    await settle();
    assert.deepEqual(world.errors, [[
      "rowstile: the language server didn't start (Launching server using command rowstile failed. Error: spawn " +
        "rowstile ENOENT). Install rowstile (https://rowstile.dev/installing), or set rowstile.command to how to " +
        "start it.",
      "Open settings",
    ]]);
    assert.deepEqual(world.commands, [["workbench.action.openSettings", "rowstile.command"]]);
    await shutdown(subscriptions);   // nothing to stop, and no error
    assert.deepEqual(world.stops, []);
  });

  await check("a new rowstile.command starts the server again with it", async () => {
    /** @type {{dispose: () => unknown}[]} */ const subscriptions = [];
    extension.activate(/** @type {any} */ ({ subscriptions }));
    await settle();
    await change("editor.fontSize");
    assert.equal(world.clients.length, 1, "another setting starts nothing");
    world.setting = ["npx", "--no", "rowstile", "lsp"];
    await change("rowstile.command");
    assert.deepEqual(world.stops, ["rowstile"]);
    assert.deepEqual(world.clients, [
      { command: "rowstile", args: ["lsp"], cwd: "/work/app" },
      { command: "npx", args: ["--no", "rowstile", "lsp"], cwd: "/work/app" },
    ]);
    await shutdown(subscriptions);
    assert.deepEqual(world.stops, ["rowstile", "npx"]);
  });

  await check("the server is stopped once at shutdown", async () => {
    /** @type {{dispose: () => unknown}[]} */ const subscriptions = [];
    extension.activate(/** @type {any} */ ({ subscriptions }));
    await settle();
    await shutdown(subscriptions);
    assert.deepEqual(world.stops, ["rowstile"]);
    assert.deepEqual(world.errors, []);
  });
})();
