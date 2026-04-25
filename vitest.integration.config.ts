import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 15000,
    include: [
      "src/tests/con.test.ts",
      "src/tests/full.intergration.test.ts",
      "src/tests/oauthIdentity.integration.test.ts",
      "src/tests/sessionPersistence.integration.test.ts"
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
