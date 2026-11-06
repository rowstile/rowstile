import { basename } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { BaseSequencer, type TestSpecification } from "vitest/node";

// The SDK's packages, as the app imports them (their built files): test.sh builds them with source maps (tsc -b
// --sourceMap), so what the checks run of them is reported on sdk/typescript/*/src
const sdk = fileURLToPath(new URL("../../sdk/typescript/", import.meta.url));

// Check 14 (tests/policy-change.test.ts) migrates the database the servers use: it runs after every other file
class PolicyChangeLast extends BaseSequencer {
  override async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    const last = (f: TestSpecification) => basename(f.moduleId) === "policy-change.test.ts";
    const sorted = await super.sort(files);
    return [...sorted.filter((f) => !last(f)), ...sorted.filter(last)];
  }
}

export default defineConfig({
  test: {
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/setup.ts"],
    fileParallelism: false,                  // the tests share one database, and the servers test.sh started
    sequence: { sequencer: PolicyChangeLast },
    testTimeout: 120_000,
    hookTimeout: 60_000,
    // `vitest run --coverage` (test.sh): the report printed, and kept with its details in CONFORMANCE_COVERAGE
    coverage: {
      provider: "v8",
      include: [`${sdk}*/dist/*.js`],
      // @rowstile/jest: integrations/node's suite runs it; Electric's proxy (client's electric.js), integrations/electric's
      exclude: [`${sdk}jest/**`, `${sdk}client/dist/electric.js`],
      allowExternal: true,
      reporter: ["text", ["text", { file: "report.txt" }], "json-summary", "json"],
      reportsDirectory: process.env.CONFORMANCE_COVERAGE ?? "coverage",
      reportOnFailure: true,
    },
  },
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
});
