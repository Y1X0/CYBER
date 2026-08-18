import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Component tests run in jsdom against the real components — the point of testing the attack-graph
// view at all is that its failure modes (an error rendered as an empty graph) are only visible when
// something actually renders it.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
