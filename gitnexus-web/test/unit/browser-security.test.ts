import { describe, expect, it } from 'vitest';
import * as path from 'path';
import {
  compareChromiumVersions,
  isSecureChromiumVersion,
  parseChromiumVersion,
  probeBrowserVersion,
  sanitizeLaunchArgs,
  resolveSecureBrowserLaunchOptions,
  MIN_CHROMIUM_SECURITY_VERSION,
  PINNED_CFT_VERSION,
  CRITICAL_CHROME_CNA_RECORDS,
  DISALLOWED_SECURITY_FLAGS,
  REQUIRED_BASE_LAUNCH_ARGS,
} from '../../src/browser-security';

describe('Browser Security Baseline — Chromium Version Verification', () => {
  describe('compareChromiumVersions', () => {
    it('compares identical versions as equal (0)', () => {
      expect(compareChromiumVersions('156.0.8078.73', '156.0.8078.73')).toBe(0);
      expect(compareChromiumVersions('156.0.8078.80', '156.0.8078.80')).toBe(0);
    });

    it('correctly compares major, minor, build, and patch components', () => {
      expect(compareChromiumVersions('157.0.0.0', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('155.0.0.0', '156.0.8078.80')).toBe(-1);
      expect(compareChromiumVersions('156.1.0.0', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('156.0.8079.0', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('156.0.8078.81', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('156.0.8078.79', '156.0.8078.80')).toBe(-1);
    });

    it('handles 3-component versions by assuming 0 for patch', () => {
      expect(compareChromiumVersions('156.0.8078', '156.0.8078.0')).toBe(0);
      expect(compareChromiumVersions('156.0.8078', '156.0.8078.1')).toBe(-1);
    });

    it('throws error for invalid version formatting', () => {
      expect(() => compareChromiumVersions('invalid', '156.0.8078.73')).toThrow();
      expect(() => compareChromiumVersions('156.0', '156.0.8078.73')).toThrow();
      expect(() => compareChromiumVersions('156.0.8078.73.1', '156.0.8078.73')).toThrow();
    });
  });

  describe('isSecureChromiumVersion', () => {
    it('accepts versions at or above minimum secure baseline 156.0.8078.73', () => {
      expect(isSecureChromiumVersion(MIN_CHROMIUM_SECURITY_VERSION)).toBe(true);
      expect(isSecureChromiumVersion(PINNED_CFT_VERSION)).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.73')).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.74')).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.80')).toBe(true);
      expect(isSecureChromiumVersion('157.0.0.0')).toBe(true);
    });

    it('rejects Playwright 1.58.2 bundled Chromium (145.0.7632.6)', () => {
      expect(isSecureChromiumVersion('145.0.7632.6')).toBe(false);
    });

    it('rejects Playwright 1.64.1 mapped Chromium (156.0.8078.4)', () => {
      // 156.0.8078.4 is below the 156.0.8078.73 fix boundary
      expect(isSecureChromiumVersion('156.0.8078.4')).toBe(false);
    });

    it('rejects older desktop releases vulnerable to Critical CNA records', () => {
      expect(isSecureChromiumVersion('156.0.8078.72')).toBe(false);
      expect(isSecureChromiumVersion('150.0.0.0')).toBe(false);
      expect(isSecureChromiumVersion('140.0.0.0')).toBe(false);
    });
  });

  describe('parseChromiumVersion', () => {
    it('parses Google Chrome output', () => {
      expect(parseChromiumVersion('Google Chrome 156.0.8078.80')).toBe('156.0.8078.80');
      expect(parseChromiumVersion('Google Chrome 156.0.8078.73 unknown\n')).toBe('156.0.8078.73');
    });

    it('parses Chromium output', () => {
      expect(parseChromiumVersion('Chromium 156.0.8078.73 Built on Ubuntu\n')).toBe(
        '156.0.8078.73',
      );
    });

    it('parses Google Chrome for Testing output', () => {
      expect(parseChromiumVersion('Google Chrome for Testing 156.0.8078.80\n')).toBe(
        '156.0.8078.80',
      );
    });

    it('parses HeadlessChrome output', () => {
      expect(parseChromiumVersion('HeadlessChrome/156.0.8078.80\n')).toBe('156.0.8078.80');
    });

    it('throws when output is not a Chromium executable output', () => {
      expect(() => parseChromiumVersion('Mozilla Firefox 130.0')).toThrow(
        /cannot parse Chromium version/,
      );
      expect(() => parseChromiumVersion('v22.22.3')).toThrow(/cannot parse Chromium version/);
      expect(() => parseChromiumVersion('')).toThrow(/cannot parse Chromium version/);
      expect(() => parseChromiumVersion('command not found: chrome')).toThrow(
        /cannot parse Chromium version/,
      );
    });
  });

  describe('probeBrowserVersion', () => {
    it('probes executable and returns parsed version', () => {
      const mockExec = () => 'Google Chrome 156.0.8078.80\n';
      expect(probeBrowserVersion('/mock/chrome', mockExec)).toBe('156.0.8078.80');
    });

    it('throws descriptive error if binary execution fails', () => {
      const mockExec = () => {
        throw new Error('ENOENT: no such file or directory');
      };
      expect(() => probeBrowserVersion('/nonexistent/chrome', mockExec)).toThrow(
        /execution failed/,
      );
    });
  });
});

describe('Browser Security Baseline — Launch Arguments & Sandboxing Enforcement', () => {
  it('preserves required WebGL rendering flags', () => {
    const args = sanitizeLaunchArgs();
    for (const flag of REQUIRED_BASE_LAUNCH_ARGS) {
      expect(args).toContain(flag);
    }
  });

  it('strips all disallowed security-bypassing flags', () => {
    const unsafeInput = [
      '--no-sandbox',
      '--disable-web-security',
      '--disable-site-isolation-trials',
      '--disable-setuid-sandbox',
      '--single-process',
      '--custom-safe-flag',
    ];

    const sanitized = sanitizeLaunchArgs(unsafeInput);

    for (const disallowed of DISALLOWED_SECURITY_FLAGS) {
      expect(sanitized).not.toContain(disallowed);
    }
    expect(sanitized).toContain('--custom-safe-flag');
    expect(sanitized).toContain('--enable-webgl');
  });

  it('enforces chromiumSandbox: true in resolution output', () => {
    const mockFsExists = () => true;
    const mockExec = () => 'Google Chrome 156.0.8078.80\n';

    const resolution = resolveSecureBrowserLaunchOptions({
      customExecutablePath: '/usr/bin/google-chrome',
      fsExists: mockFsExists,
      execCommand: mockExec,
    });

    expect(resolution.chromiumSandbox).toBe(true);
    expect(resolution.args).not.toContain('--no-sandbox');
    expect(resolution.args).not.toContain('--disable-web-security');
  });
});

describe('Browser Security Baseline — Fail-Closed Acceptance Loop', () => {
  it('refuses old executable below baseline and names Critical CNA records', () => {
    const mockFsExists = () => true;
    const mockExec = () => 'Google Chrome 145.0.7632.6\n';

    expect(() =>
      resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/mock/old-chrome',
        fsExists: mockFsExists,
        execCommand: mockExec,
      }),
    ).toThrowError(/version 145\.0\.7632\.6 is below minimum secure baseline 156\.0\.8078\.73/);

    // Verify all 4 critical CNA records are included in the error
    let thrownError: Error | null = null;
    try {
      resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/mock/old-chrome',
        fsExists: mockFsExists,
        execCommand: mockExec,
      });
    } catch (err) {
      thrownError = err as Error;
    }
    expect(thrownError).not.toBeNull();
    for (const cna of CRITICAL_CHROME_CNA_RECORDS) {
      expect(thrownError?.message).toContain(cna);
    }
  });

  it('refuses Playwright 1.64.1 mapped Chromium 156.0.8078.4 (below fix)', () => {
    const mockFsExists = () => true;
    const mockExec = () => 'Chromium 156.0.8078.4\n';

    expect(() =>
      resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/mock/playwright-1.64-chromium',
        fsExists: mockFsExists,
        execCommand: mockExec,
      }),
    ).toThrowError(/version 156\.0\.8078\.4 is below minimum secure baseline/);
  });

  it('refuses missing executable path without falling back to stale cache', () => {
    const mockFsExists = () => false;

    expect(() =>
      resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/nonexistent/path/to/chrome',
        fsExists: mockFsExists,
      }),
    ).toThrowError(/executable file not found\. Stale cache and unverified fallbacks are rejected/);
  });

  it('refuses wrong executable output (non-Chromium binary)', () => {
    const mockFsExists = () => true;
    const mockExec = () => 'bash 5.2.15(1)-release\n';

    expect(() =>
      resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/bin/bash',
        fsExists: mockFsExists,
        execCommand: mockExec,
      }),
    ).toThrowError(/cannot parse Chromium version from output/);
  });

  it('refuses silent fallback when no secure candidate exists', () => {
    const mockFsExists = () => false;
    const emptyEnv = {};

    expect(() =>
      resolveSecureBrowserLaunchOptions({
        env: emptyEnv,
        platform: 'linux',
        fsExists: mockFsExists,
      }),
    ).toThrowError(
      /No secure Chromium browser executable resolved \(minimum baseline: 156\.0\.8078\.73\)/,
    );
  });

  it('succeeds on explicit patched candidate selection via env variable', () => {
    const mockFsExists = (p: string) => p.includes('google-chrome');
    const mockExec = () => 'Google Chrome 156.0.8078.80\n';

    const resolution = resolveSecureBrowserLaunchOptions({
      env: { CHROME_BIN: '/usr/bin/google-chrome' },
      fsExists: mockFsExists,
      execCommand: mockExec,
    });

    expect(resolution.executablePath).toBe(path.resolve('/usr/bin/google-chrome'));
    expect(resolution.version).toBe('156.0.8078.80');
    expect(resolution.source).toBe('env');
    expect(resolution.chromiumSandbox).toBe(true);
    expect(resolution.args).not.toContain('--no-sandbox');
    expect(resolution.args).not.toContain('--disable-web-security');
  });

  it('succeeds on system candidate matching or exceeding baseline', () => {
    const mockFsExists = (p: string) => p === '/usr/bin/google-chrome';
    const mockExec = () => 'Google Chrome 156.0.8078.74\n';

    const resolution = resolveSecureBrowserLaunchOptions({
      env: {},
      platform: 'linux',
      fsExists: mockFsExists,
      execCommand: mockExec,
    });

    expect(resolution.executablePath).toBe('/usr/bin/google-chrome');
    expect(resolution.version).toBe('156.0.8078.74');
    expect(resolution.source).toBe('system');
    expect(resolution.chromiumSandbox).toBe(true);
  });
});

describe('Browser Security Baseline — Real Environment Sandboxing & Isolation', () => {
  it('resolves the real system Chrome on this host meeting security baseline', () => {
    const resolution = resolveSecureBrowserLaunchOptions();
    expect(resolution.executablePath).toBeTruthy();
    expect(isSecureChromiumVersion(resolution.version)).toBe(true);
    expect(resolution.chromiumSandbox).toBe(true);
    expect(resolution.args).not.toContain('--no-sandbox');
  });

  it('launches patched browser with Playwright verifying sandbox and profile isolation', async () => {
    const { chromium } = await import('@playwright/test');
    const resolution = resolveSecureBrowserLaunchOptions();

    const browser = await chromium.launch({
      executablePath: resolution.executablePath,
      args: resolution.args,
      chromiumSandbox: resolution.chromiumSandbox,
      headless: true,
    });

    try {
      // 1. Verify launched browser version matches or exceeds security baseline
      const launchedVersion = browser.version();
      expect(isSecureChromiumVersion(launchedVersion)).toBe(true);

      // 2. Profile isolation: test two independent contexts
      const contextA = await browser.newContext();
      const contextB = await browser.newContext();

      const _pageA = await contextA.newPage();
      const _pageB = await contextB.newPage();

      // Set cookie in Context A
      await contextA.addCookies([
        {
          name: 'session_token',
          value: 'secret_123',
          domain: 'localhost',
          path: '/',
        },
      ]);

      const cookiesA = await contextA.cookies();
      const cookiesB = await contextB.cookies();

      expect(cookiesA.some((c) => c.name === 'session_token')).toBe(true);
      expect(cookiesB.some((c) => c.name === 'session_token')).toBe(false);

      await contextA.close();
      await contextB.close();
    } finally {
      await browser.close();
    }
  });
});
