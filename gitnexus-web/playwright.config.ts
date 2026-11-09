import { defineConfig } from '@playwright/test';
import { resolveSecureBrowserLaunchOptions } from './e2e/support/browser-security';

// Resolves an explicit Chromium executable at or above the advisory floor and fails closed
// otherwise; Playwright's bundled Chromium is never used. See e2e/support/browser-security.ts.
const secureBrowser = resolveSecureBrowserLaunchOptions();

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/support/global-setup.ts',
  testIgnore: ['**/manual-record.spec.ts', '**/debug-issues.spec.ts'],
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    launchOptions: {
      executablePath: secureBrowser.executablePath,
      args: secureBrowser.args,
      chromiumSandbox: secureBrowser.chromiumSandbox,
    },
    // Page CSP stays enforced; bypassing it would weaken origin boundaries under test.
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
