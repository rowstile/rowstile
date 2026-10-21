import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// npm run dev: the backend on :8001 answers /api (and the live updates' WebSocket)
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: "http://localhost:8001", ws: true } } },
  test: { environment: "jsdom" },     // npm test: the web app against a fake API (src/*.test.tsx)
});
