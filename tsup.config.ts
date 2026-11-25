import { defineConfig } from "tsup";

// Standalone: no Palisec code inside. viem stays external (a peer dependency).
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm"],
  dts: true,
  clean: true,
  target: "es2022",
  external: ["viem"],
});
