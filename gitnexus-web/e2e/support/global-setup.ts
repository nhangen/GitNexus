import { chromium } from '@playwright/test';
import { resolveSecureBrowserLaunchOptions, verifyLiveBrowserVersion } from './browser-security';

/**
 * Playwright Global Setup:
 * Enforces actual executable launch and post-launch live version verification before any E2E test runs.
 * Closes the gap between pre-launch probe and actual controller launch.
 */
export default async function globalSetup() {
  const secure = resolveSecureBrowserLaunchOptions();
  const browser = await chromium.launch({
    executablePath: secure.executablePath,
    args: secure.args,
    chromiumSandbox: secure.chromiumSandbox,
    headless: true,
  });
  try {
    const liveVersion = browser.version();
    verifyLiveBrowserVersion(browser);
    if (!liveVersion) {
      throw new Error(
        `Failed to query version from live browser launched at "${secure.executablePath}".`,
      );
    }
  } finally {
    await browser.close();
  }
}
