import { fileURLToPath } from "node:url";
import { BaseSequencer, type TestSpecification } from "vitest/node";
import { defineConfig } from "vitest/config";

// one file after the other, by name (api, then live): they share the server test.sh started and its database, and
// the live checks add tickets and comments the API's checks would count
class ByName extends BaseSequencer {
  async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    return [...files].sort((a, b) => a.moduleId.localeCompare(b.moduleId));
  }
}

export default defineConfig({
  test: { include: ["tests/**/*.test.ts"], fileParallelism: false, testTimeout: 60_000, sequence: { sequencer: ByName } },
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
});
