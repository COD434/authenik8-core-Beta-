import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      ioredis: "ioredis-mock"
    }
  },
  test: {
    globals: true,
    environment: "node",
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 15000,
    include: [
      "src/tests/integration/con.test.ts",
      "src/tests/integration/full.intergration.test.ts",
      "src/tests/integration/oauthIdentity.integration.test.ts",
      "src/tests/integration/sessionPersistence.integration.test.ts"
    ],
    exclude: ["dist/**", "node_modules/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/tests/**",
        "dist/**"
      ]
    }
  }
});
