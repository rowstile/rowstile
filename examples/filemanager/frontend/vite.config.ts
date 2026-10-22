import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// npm run dev: the backend on :8000 answers /api
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://localhost:8000" } },
  // npm test: the web app against a fake API (src/*.test.tsx), west of UTC, where dates go wrong first
  test: { environment: "jsdom", env: { TZ: "America/Los_Angeles" } },
});
