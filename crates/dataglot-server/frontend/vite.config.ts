import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The SPA is served by dataglot-server at `/ui` (see src/embed.rs), so
// assets must be requested relative to that base, not the server root.
export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Single chunk keeps the embedded asset set small and the
    // cache-control story simple (index.html no-cache, hashed assets
    // immutable — mirrors the testbench embed).
    chunkSizeWarningLimit: 1500,
  },
});
