// Check 14 (integrations/README.md): after a policy change and a new migration, the app works with the new generated
// names. It migrates the database the servers use, so it runs last, after every other file (vitest.config.ts), as
// one test: the running app has the new permission only once the migration ran.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeEach, expect, test } from "vitest";
import { actingAs, current } from "@rowstile/client";
import { db, pool } from "@/db";
import { seed } from "./data";

const HERE = dirname(dirname(fileURLToPath(import.meta.url)));
const ROOT = join(HERE, "..", "..");
const CLI = join(ROOT, "core", "cli", "rowstile_cli.py");
const PYTHON = process.env.PYTHON ?? "python3";
// the tools' own scripts, run with this Node
const TOOL: Record<string, string> = {
  tsc: join(ROOT, "node_modules", "typescript", "bin", "tsc"),
  prisma: join(ROOT, "node_modules", "prisma", "build", "index.js"),
};
const run = (tool: string, args: string[], cwd: string) =>
  spawnSync(process.execPath, [TOOL[tool], ...args], { cwd, encoding: "utf8", env: process.env });

beforeEach(seed);
afterAll(async () => {
  await pool.end();
  await db.$disconnect();
});

test("14: a policy change ships as the next migration, and the running app has it", async () => {
  const work = join(HERE, ".work", "check14");
  rmSync(work, { recursive: true, force: true });
  for (const part of ["db", "prisma", "rowstile.toml", "prisma.config.ts"]) cpSync(join(HERE, part), join(work, part), { recursive: true });
  const policy = join(work, "db", "policy.authz");
  writeFileSync(policy, readFileSync(policy, "utf8").replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"));
  const env = { ...process.env };
  execFileSync(PYTHON, [CLI, "migrate", "--name", "reply"], { cwd: work, stdio: "pipe", env });
  const deploy = run("prisma", ["migrate", "deploy"], work);
  expect(deploy.status, deploy.stdout + deploy.stderr).toBe(0);
  execFileSync(PYTHON, [CLI, "client"], { cwd: work, stdio: "pipe", env });
  const names = readFileSync(join(work, "src", "authz.gen.ts"), "utf8");
  expect(names).toContain('"reply"');
  writeFileSync(join(work, "use.ts"), 'import "./src/authz.gen.ts";\nimport type { Permission } from "@rowstile/client";\n' +
    'export const p: Permission<"message"> = "reply";\n');
  writeFileSync(join(work, "tsconfig.json"), JSON.stringify({ extends: "../../tsconfig.json", compilerOptions: { incremental: false, plugins: [] }, exclude: [], include: ["use.ts", "src/authz.gen.ts"] }));
  const tsc = run("tsc", ["-p", "tsconfig.json", "--noEmit"], work);
  expect(tsc.status, tsc.stdout).toBe(0);

  const inbox = await actingAs("1", () => db.$executeRaw`INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi')`);
  expect(inbox).toBe(1);
  const perms = await actingAs("2", async () => {
    const [m] = await db.message.findMany({ where: { recipient_id: 2 } });
    return db.$authz.perms("message", m.id);
  });
  expect(perms).toContain("reply");
  expect(current()).toBeUndefined();
});
