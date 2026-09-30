import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Multi-MiB attachment round-trips are slow on shared CI runners.
    testTimeout: 60_000,
  },
});
