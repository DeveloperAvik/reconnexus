import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const r = (p: string): string => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@reconnexus/contracts": r("./packages/contracts/src/index.ts"),
      "@reconnexus/normalization": r("./packages/normalization/src/index.ts"),
      "@reconnexus/logging": r("./packages/logging/src/index.ts"),
      "@reconnexus/configuration": r("./packages/configuration/src/index.ts"),
      "@reconnexus/scope-policy": r("./packages/scope-policy/src/index.ts"),
      "@reconnexus/evidence-contracts": r("./packages/evidence-contracts/src/index.ts"),
      "@reconnexus/control-plane": r("./apps/control-plane/src/index.ts"),
    },
  },
  test: {
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts", "test/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    environment: "node",
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
