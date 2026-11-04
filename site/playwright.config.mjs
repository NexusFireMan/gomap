import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  use: {
    baseURL: 'http://127.0.0.1:4322/gomap/',
    launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE, args: ['--no-sandbox'] },
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } },
    { name: 'mobile', use: { ...devices['iPhone 13'], defaultBrowserType: 'chromium' } },
  ],
  webServer: {
    command: 'node node_modules/astro/bin/astro.mjs preview --ignore-lock --host 127.0.0.1 --port 4322',
    url: 'http://127.0.0.1:4322/gomap/',
    reuseExistingServer: !process.env.CI,
  },
});
