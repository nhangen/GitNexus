import { chromium } from '@playwright/test';
import {
  resolveSecureBrowserLaunchOptions,
  verifyLiveBrowserVersion,
  type SecureBrowserResolution,
} from './browser-security';

interface LaunchedBrowser {
  version(): string;
  close(): Promise<void>;
}

export interface GlobalSetupDeps {
  resolve: () => SecureBrowserResolution;
  launch: (options: {
    executablePath: string;
    args: string[];
    chromiumSandbox: boolean;
    headless: boolean;
  }) => Promise<LaunchedBrowser>;
  platform: NodeJS.Platform;
  expectedExactVersion?: string;
}

/**
 * Launches the resolved executable once before any E2E test and checks the version the
 * running browser reports, which the pre-launch `--version` probe cannot guarantee.
 */
export function createGlobalSetup(deps: GlobalSetupDeps): () => Promise<void> {
  return async () => {
    const secure = deps.resolve();
    const browser = await deps.launch({
      executablePath: secure.executablePath,
      args: secure.args,
      chromiumSandbox: secure.chromiumSandbox,
      headless: true,
    });
    try {
      verifyLiveBrowserVersion(browser, deps.platform, deps.expectedExactVersion);
    } finally {
      await browser.close();
    }
  };
}

export function defaultGlobalSetupDeps(
  env: Record<string, string | undefined>,
  platform: NodeJS.Platform,
): GlobalSetupDeps {
  return {
    resolve: () => resolveSecureBrowserLaunchOptions({ env, platform }),
    launch: (options) => chromium.launch(options),
    platform,
    expectedExactVersion: env.GITNEXUS_EXPECTED_CHROME_VERSION || undefined,
  };
}

export default createGlobalSetup(defaultGlobalSetupDeps(process.env, process.platform));
