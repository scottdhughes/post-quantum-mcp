import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: { bindings: { RELAY_ADMIN_TOKEN: "local-admin-secret" } },
    }),
  ],
  test: { include: ["test/relay.test.ts"] },
});
