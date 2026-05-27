import { defineConfig } from "@playwright/test";

const port = Number(process.env.OPENVPN_MANAGER_TEST_PORT || 8765);
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./specs",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  webServer: {
    command: `cd ../../.. && .venv/bin/python -m openvpn_manager.testing.http_harness ${port}`,
    url: `${baseURL}/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
