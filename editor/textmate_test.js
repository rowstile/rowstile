// The TextMate grammar (syntaxes/authz.tmLanguage.json: VS Code, and the site's ```authz blocks) colours each form
// of the policies in test/ as their comments say (npm ci here, then node textmate_test.js; editor/test.sh). Those
// policies are what core/authzlib/parse.py reads (unit_test.py checks), and the Tree-sitter grammar reads them as it
// does (editor/test.sh). Under a line, a comment says what scope a part of it has, as VS Code tokenizes it:
//   -- ^^^^^ keyword.other.when.authz      the characters above the carets
//   -- <---- keyword.declaration.authz     the line's first characters, one per -
// Each character there has that scope as its innermost one (source.authz: none of the grammar's own).
// Plain JavaScript, typed with JSDoc and checked strictly (editor/tsconfig.json).
const fs = require("node:fs");
const path = require("node:path");
const vsctm = require("vscode-textmate");
const oniguruma = require("vscode-oniguruma");

const HERE = __dirname;
const ASSERT = /^--(\s*)(\^+|<-+)\s+(\S+)\s*$/;

/** @returns {Promise<vsctm.IGrammar>} */
async function grammar() {
  const wasm = fs.readFileSync(path.join(path.dirname(require.resolve("vscode-oniguruma")), "onig.wasm"));
  await oniguruma.loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
  const file = path.join(HERE, "syntaxes", "authz.tmLanguage.json");
  const registry = new vsctm.Registry({
    onigLib: Promise.resolve({
      createOnigScanner: (sources) => new oniguruma.OnigScanner(sources),
      createOnigString: (text) => new oniguruma.OnigString(text),
    }),
    // the SQL inside { } is VS Code's own SQL grammar's: here one that colours nothing
    loadGrammar: async (scope) =>
      scope === "source.authz"
        ? vsctm.parseRawGrammar(fs.readFileSync(file, "utf8"), file)
        : scope === "source.sql"
          ? vsctm.parseRawGrammar(JSON.stringify({ scopeName: "source.sql", patterns: [] }), "sql.json")
          : null,
  });
  const loaded = await registry.loadGrammar("source.authz");
  if (!loaded) throw new Error("the grammar doesn't load");
  return loaded;
}

/**
 * What is wrong in one file: each part a comment names whose scope isn't the one it says.
 * @param {vsctm.IGrammar} g @param {string} name @param {string} text
 * @returns {{checked: number, wrong: string[]}}
 */
function check(g, name, text) {
  /** @type {string[]} */
  const wrong = [];
  let checked = 0;
  let stack = vsctm.INITIAL;
  /** @type {{line: string, at: number, scopes: string[]} | undefined} */
  let above;
  text.split("\n").forEach((line, i) => {
    const m = ASSERT.exec(line);
    if (!m) {
      const r = g.tokenizeLine(line, stack);
      stack = r.ruleStack;
      /** @type {string[]} */
      const scopes = [];
      for (const t of r.tokens) {
        for (let c = t.startIndex; c < Math.min(t.endIndex, line.length); c++) scopes[c] = t.scopes[t.scopes.length - 1];
      }
      above = { line, at: i + 1, scopes };
      return;
    }
    const [start, end] = m[2].startsWith("<") ? [0, m[2].length - 1] : [2 + m[1].length, 2 + m[1].length + m[2].length];
    const want = m[3];
    checked++;
    if (!above || end > above.line.length) {
      wrong.push(`${name}:${i + 1}: the comment points past the line above it`);
      return;
    }
    const got = above.scopes.slice(start, end);
    if (got.some((s) => s !== want)) {
      const seen = [...new Set(got)].join(", ");
      wrong.push(`${name}:${above.at}: ${JSON.stringify(above.line.slice(start, end))} is ${seen}, not ${want}`);
    }
  });
  return { checked, wrong };
}

async function main() {
  const g = await grammar();
  const folder = path.join(HERE, "test");
  const files = fs.readdirSync(folder).filter((f) => f.endsWith(".authz")).sort();
  let checked = 0;
  /** @type {string[]} */
  const wrong = [];
  for (const f of files) {
    const r = check(g, `test/${f}`, fs.readFileSync(path.join(folder, f), "utf8"));
    checked += r.checked;
    wrong.push(...r.wrong);
  }
  for (const w of wrong) console.log(`      ${w}`);
  if (wrong.length || !checked) {
    console.log(`FAIL  the TextMate grammar colours the forms of test/*.authz as their comments say (${wrong.length} wrong)`);
    process.exitCode = 1;
  } else {
    console.log(`ok    the TextMate grammar colours the forms of test/*.authz as their comments say (${checked} parts)`);
  }
}

main().catch((e) => {
  console.log(`FAIL  the TextMate grammar: ${e}`);
  process.exitCode = 1;
});
