import { defineConfig } from '@playwright/test';
import { resolveSecureBrowserLaunchOptions } from './src/browser-security';

// Resolve patched Chromium browser baseline (>= 156.0.8078.73) with enforced
// sandboxing, profile isolation, and verified executable integrity.
// Fails closed if the executable is missing, wrong, unverified, or below baseline.
const secureBrowser = resolveSecureBrowserLaunchOptions();

export default defineConfig({
  testDir: './e2e',
  testIgnore: ['**/manual-record.spec.ts', '**/debug-issues.spec.ts'],
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
    screenshot: 'retain-on-failure',
    video: 'retain-on-failure',
    launchOptions: {
      executablePath: secureBrowser.executablePath,
      args: secureBrowser.args,
      chromiumSandbox: secureBrowser.chromiumSandbox,
    },
    // Enforce strict CSP; bypass is forbidden to preserve origin boundaries.
    bypassCSP: false,
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  outputDir: 'test-results',
});
