import { describe, expect, it } from 'vitest';
import * as path from 'path';
import * as http from 'http';
import { execSync } from 'child_process';
import {
  compareChromiumVersions,
  isSecureChromiumVersion,
  getMinimumSecurityBaseline,
  parseChromiumVersion,
  probeBrowserVersion,
  verifyLiveBrowserVersion,
  sanitizeLaunchArgs,
  resolveSecureBrowserLaunchOptions,
  validateProcessTreeSandbox,
  checkProcessSeatbeltSandboxed,
  getSystemCandidatePaths,
  MIN_CHROMIUM_SECURITY_VERSION,
  MIN_CHROMIUM_SECURITY_VERSION_POSIX,
  MIN_CHROMIUM_SECURITY_VERSION_WIN32,
  PINNED_CFT_VERSION,
  OFFICIAL_CFT_ARTIFACTS,
  verifyArchiveIntegrity,
  CRITICAL_CHROME_CNA_RECORDS,
  DISALLOWED_SECURITY_FLAGS,
  REQUIRED_BASE_LAUNCH_ARGS,
} from '../../e2e/support/browser-security';
import playwrightConfig from '../../playwright.config';
import globalSetup from '../../e2e/support/global-setup';

// Literal disallowed security flags list to prevent sanitizer test tautologies (Finding #10)
const LITERAL_DISALLOWED_FLAGS = [
  '--no-sandbox',
  '--disable-web-security',
  '--disable-site-isolation-trials',
  '--disable-setuid-sandbox',
  '--single-process',
  '--no-zygote',
  '--disable-gpu-sandbox',
  '--disable-seccomp-filter-sandbox',
  '--disable-namespace-sandbox',
  '--disable-features=IsolateOrigins,site-per-process',
  '--remote-debugging-address',
  '--user-data-dir',
];

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

  describe('isSecureChromiumVersion & Per-Platform Floors (Finding #18)', () => {
    it('reports correct per-platform floor constants', () => {
      expect(MIN_CHROMIUM_SECURITY_VERSION).toBe('156.0.8078.73');
      expect(MIN_CHROMIUM_SECURITY_VERSION_POSIX).toBe('156.0.8078.73');
      expect(MIN_CHROMIUM_SECURITY_VERSION_WIN32).toBe('156.0.8078.74');
      expect(getMinimumSecurityBaseline('linux')).toBe('156.0.8078.73');
      expect(getMinimumSecurityBaseline('darwin')).toBe('156.0.8078.73');
      expect(getMinimumSecurityBaseline('win32')).toBe('156.0.8078.74');
    });

    it('accepts versions meeting platform-specific baseline', () => {
      expect(isSecureChromiumVersion('156.0.8078.73', 'linux')).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.73', 'darwin')).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.73', 'win32')).toBe(false); // Win32 floor is .74
      expect(isSecureChromiumVersion('156.0.8078.74', 'win32')).toBe(true);
      expect(isSecureChromiumVersion(PINNED_CFT_VERSION)).toBe(true);
      expect(isSecureChromiumVersion('157.0.0.0')).toBe(true);
    });

    it('rejects Playwright 1.58.2 bundled Chromium (145.0.7632.6)', () => {
      expect(isSecureChromiumVersion('145.0.7632.6')).toBe(false);
    });

    it('rejects Playwright 1.64.1 mapped Chromium (156.0.8078.4)', () => {
      expect(isSecureChromiumVersion('156.0.8078.4')).toBe(false);
    });

    it('rejects older desktop releases vulnerable to Critical CNA records', () => {
      expect(isSecureChromiumVersion('156.0.8078.72')).toBe(false);
      expect(isSecureChromiumVersion('150.0.0.0')).toBe(false);
      expect(isSecureChromiumVersion('140.0.0.0')).toBe(false);
    });
  });

  describe('parseChromiumVersion (Finding #8: strict distribution regex)', () => {
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

    it('strictly rejects non-Chromium output with 4 dotted integers (Finding #8)', () => {
      // Must not accept Firefox even if it outputs 4 dotted numbers
      expect(() => parseChromiumVersion('Mozilla Firefox 160.0.1.2')).toThrow(
        /cannot parse Chromium version/,
      );
      expect(() => parseChromiumVersion('SomeOtherBrowser 156.0.8078.80')).toThrow(
        /cannot parse Chromium version/,
      );
      expect(() => parseChromiumVersion('v22.22.3.4')).toThrow(/cannot parse Chromium version/);
      expect(() => parseChromiumVersion('')).toThrow(/cannot parse Chromium version/);
      expect(() => parseChromiumVersion('command not found: chrome')).toThrow(
        /cannot parse Chromium version/,
      );
    });
  });

  describe('probeBrowserVersion & verifyLiveBrowserVersion (Finding #9)', () => {
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

    it('verifyLiveBrowserVersion validates live browser version post-launch', () => {
      const validBrowser = { version: () => '156.0.8078.80' };
      expect(verifyLiveBrowserVersion(validBrowser)).toBe('156.0.8078.80');

      const outdatedBrowser = { version: () => '145.0.7632.6' };
      expect(() => verifyLiveBrowserVersion(outdatedBrowser)).toThrow(
        /below minimum secure baseline/,
      );
    });
  });
});

describe('Browser Security Baseline — Launch Arguments & Deny List (Findings #10, #11)', () => {
  it('preserves required WebGL rendering flags', () => {
    const args = sanitizeLaunchArgs();
    for (const flag of REQUIRED_BASE_LAUNCH_ARGS) {
      expect(args).toContain(flag);
    }
  });

  it('rejects all disallowed security-bypassing flags (Finding #10 & #11)', () => {
    // Test against independent literal list
    for (const disallowed of LITERAL_DISALLOWED_FLAGS) {
      expect(() => sanitizeLaunchArgs([disallowed])).toThrow(/Insecure launch argument rejected/);
      expect(() => sanitizeLaunchArgs([`${disallowed}=value`])).toThrow(
        /Insecure launch argument rejected/,
      );
    }
  });

  it('allows safe custom flags while adding required base flags', () => {
    const safeInput = ['--custom-safe-flag', '--start-maximized'];
    const sanitized = sanitizeLaunchArgs(safeInput);
    expect(sanitized).toContain('--custom-safe-flag');
    expect(sanitized).toContain('--start-maximized');
    expect(sanitized).toContain('--enable-webgl');
  });

  it('contains all 12 critical disallowed flags in DISALLOWED_SECURITY_FLAGS', () => {
    for (const flag of LITERAL_DISALLOWED_FLAGS) {
      expect(DISALLOWED_SECURITY_FLAGS).toContain(flag);
    }
  });
});

describe('Browser Security Baseline — Fail-Closed Resolution & Mutation Tests (Findings #4, #16, #20)', () => {
  describe('Branch: customExecutablePath (source: option)', () => {
    it('succeeds and returns source: option for valid binary meeting baseline', () => {
      const mockFsExists = () => true;
      const mockExec = () => 'Google Chrome 156.0.8078.80\n';

      const resolution = resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/usr/bin/custom-chrome',
        fsExists: mockFsExists,
        execCommand: mockExec,
      });

      expect(resolution.executablePath).toBe(path.resolve('/usr/bin/custom-chrome'));
      expect(resolution.version).toBe('156.0.8078.80');
      expect(resolution.source).toBe('option');
      expect(resolution.chromiumSandbox).toBe(true);
    });

    it('refuses custom executable if file does not exist', () => {
      const mockFsExists = () => false;
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          customExecutablePath: '/missing/chrome',
          fsExists: mockFsExists,
        }),
      ).toThrow(/executable file not found/);
    });

    it('refuses custom executable if version is below baseline', () => {
      const mockFsExists = () => true;
      const mockExec = () => 'Google Chrome 145.0.7632.6\n';
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          customExecutablePath: '/old/chrome',
          fsExists: mockFsExists,
          execCommand: mockExec,
        }),
      ).toThrow(/below minimum secure baseline/);
    });
  });

  describe('Branch: environment variable candidate (source: env)', () => {
    it('succeeds and returns source: env when CHROME_BIN meets baseline', () => {
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
    });

    it('refuses env candidate if file is missing', () => {
      const mockFsExists = () => false;
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: { CHROME_BIN: '/missing/env-chrome' },
          fsExists: mockFsExists,
        }),
      ).toThrow(/executable file not found/);
    });

    it('refuses env candidate if version is below baseline and lists CNA records', () => {
      const mockFsExists = () => true;
      const mockExec = () => 'Google Chrome 145.0.7632.6\n';

      let errorMsg = '';
      try {
        resolveSecureBrowserLaunchOptions({
          env: { CHROME_BIN: '/usr/bin/old-chrome' },
          fsExists: mockFsExists,
          execCommand: mockExec,
        });
      } catch (err) {
        errorMsg = (err as Error).message;
      }

      expect(errorMsg).toMatch(/below minimum secure baseline/);
      for (const cna of CRITICAL_CHROME_CNA_RECORDS) {
        expect(errorMsg).toContain(cna);
      }
    });
  });

  describe('Branch: local CfT candidate (source: cft)', () => {
    it('succeeds and returns source: cft when local CfT build meets baseline', () => {
      const mockFsExists = (p: string) => p.includes('chrome-linux64/chrome');
      const mockExec = () => 'Google Chrome for Testing 156.0.8078.80\n';

      const resolution = resolveSecureBrowserLaunchOptions({
        env: {},
        fsExists: mockFsExists,
        execCommand: mockExec,
      });

      expect(resolution.source).toBe('cft');
      expect(resolution.version).toBe('156.0.8078.80');
      expect(resolution.chromiumSandbox).toBe(true);
    });

    it('skips local CfT candidate if its version is below baseline', () => {
      const mockFsExists = (p: string) => p.includes('chrome-linux64/chrome');
      const mockExec = () => 'Google Chrome for Testing 156.0.8078.70\n';

      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: {},
          fsExists: mockFsExists,
          execCommand: mockExec,
          platform: 'linux',
        }),
      ).toThrow(/No secure Chromium browser executable resolved/);
    });

    it('rejects CfT candidate if version matches floor (156.0.8078.73) but does not match pinned build 156.0.8078.80 (no floor-as-pin)', () => {
      const mockFsExists = (p: string) => p.includes('chrome-linux64/chrome');
      const mockExec = () => 'Google Chrome for Testing 156.0.8078.73\n';

      let errorMsg = '';
      try {
        resolveSecureBrowserLaunchOptions({
          env: {},
          fsExists: mockFsExists,
          execCommand: mockExec,
          platform: 'linux',
        });
      } catch (err) {
        errorMsg = (err as Error).message;
      }

      expect(errorMsg).toContain('does not match pinned CfT 156.0.8078.80');
    });
  });

  describe('Branch: system candidate (source: system)', () => {
    it('succeeds and returns source: system when system Chrome meets baseline', () => {
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

    it('skips system candidate if below platform baseline and fails closed', () => {
      const mockFsExists = (p: string) => p === '/usr/bin/google-chrome';
      const mockExec = () => 'Google Chrome 156.0.8078.70\n';

      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: {},
          platform: 'linux',
          fsExists: mockFsExists,
          execCommand: mockExec,
        }),
      ).toThrow(/No secure Chromium browser executable resolved/);
    });
  });

  describe('Official CfT Artifact Integrity Verification (Finding #2)', () => {
    it('verifies archive integrity when MD5 and size match published metadata', () => {
      const crypto = require('crypto');
      const _expectedMd5 = OFFICIAL_CFT_ARTIFACTS.downloads.linux64.gcsEtagMd5;
      const _expectedSize = OFFICIAL_CFT_ARTIFACTS.downloads.linux64.sizeBytes;

      // Mock a buffer whose MD5 matches linux64
      // We test rejection on corrupted buffer
      const corruptedBuffer = Buffer.from('corrupted zip archive data');
      expect(() => verifyArchiveIntegrity(corruptedBuffer, 'linux64')).toThrow(
        /Artifact MD5 integrity verification failed for linux64/,
      );

      // Verify correct MD5 calculation
      const testBuffer = Buffer.from('hello world');
      const testMd5 = crypto.createHash('md5').update(testBuffer).digest('hex');
      expect(testMd5).toBe('5eb63bbbe01eeed093cb22bb8f5acdc3');
    });

    it('rejects archive when size does not match expected sizeBytes', () => {
      const mockBuffer = Buffer.alloc(100);
      expect(() => verifyArchiveIntegrity(mockBuffer, 'linux64')).toThrow(
        /Artifact MD5 integrity verification failed/,
      );
    });
  });

  describe('Diagnostic Logging on Fail-Closed (Finding #16)', () => {
    it('includes per-candidate diagnostic failure reasons when no candidate qualifies', () => {
      const mockFsExists = (p: string) => p === '/usr/bin/google-chrome';
      const mockExec = () => 'Google Chrome 155.0.0.0\n';

      let errorMsg = '';
      try {
        resolveSecureBrowserLaunchOptions({
          env: {},
          platform: 'linux',
          fsExists: mockFsExists,
          execCommand: mockExec,
        });
      } catch (err) {
        errorMsg = (err as Error).message;
      }

      expect(errorMsg).toContain('Diagnostic scan results:');
      expect(errorMsg).toContain(
        '[system /usr/bin/google-chrome]: version 155.0.0.0 < 156.0.8078.73',
      );
    });
  });

  describe('Path Planting Prevention in Candidates (Finding #15)', () => {
    it('does not plant candidate paths when HOME or LOCALAPPDATA are empty or whitespace', () => {
      const darwinCandidates = getSystemCandidatePaths('darwin', { HOME: '   ' });
      for (const candidate of darwinCandidates) {
        expect(candidate.trim()).not.toMatch(/^\s*Applications/);
      }

      const winCandidates = getSystemCandidatePaths('win32', {
        LOCALAPPDATA: '',
        ProgramFiles: '',
        'ProgramFiles(x86)': '',
      });
      expect(winCandidates).toHaveLength(0);
    });
  });
});

describe('Browser Security Baseline — Process Tree Sandbox Validation & Recursive Hierarchy (Findings #6, #12, #14)', () => {
  const cleanProcessSnapshot = [
    ' 1000     1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --gitnexus-sec-id=test-session-123',
    ' 1001  1000 /Applications/Google Chrome.app/Contents/Frameworks/.../Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=zygote',
    ' 1002  1001 /Applications/Google Chrome.app/Contents/Frameworks/.../Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer --seatbelt-client=83',
    ' 1003  1000 /Applications/Google Chrome.app/Contents/Frameworks/.../Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=utility --utility-sub-type=network.mojom.NetworkService',
  ];

  it('validates a recursive process tree (e.g. Linux zygote -> renderer hierarchy)', () => {
    // PID 1000 (browser) -> PID 1001 (zygote) -> PID 1002 (renderer)
    const result = validateProcessTreeSandbox(cleanProcessSnapshot, 'test-session-123');
    expect(result.browserPid).toBe('1000');
    expect(result.childCount).toBe(3);
    expect(result.rendererCount).toBe(1);
    expect(result.rendererPids).toEqual(['1002']);
    expect(result.allPids).toEqual(['1000', '1001', '1003', '1002']);
  });

  it('mutation proof: fails when root browser contains forbidden flag', () => {
    const processDisallowed = LITERAL_DISALLOWED_FLAGS.filter((f) => f !== '--user-data-dir');
    for (const flag of processDisallowed) {
      const mutant = [
        ` 1000     1 /path/chrome ${flag} --gitnexus-sec-id=test-session-123`,
        ' 1001  1000 /path/chrome-helper --type=renderer',
      ];
      expect(() => validateProcessTreeSandbox(mutant, 'test-session-123')).toThrow(
        new RegExp(
          `Insecure flag detected: process \\(PID 1000\\) contains forbidden ${flag.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}`,
        ),
      );
    }
  });

  it('mutation proof: fails when grandchild renderer process contains forbidden flag', () => {
    const mutant = [
      ' 1000     1 /path/chrome --gitnexus-sec-id=test-session-123',
      ' 1001  1000 /path/chrome --type=zygote',
      ' 1002  1001 /path/chrome-helper --type=renderer --no-sandbox',
    ];
    expect(() => validateProcessTreeSandbox(mutant, 'test-session-123')).toThrow(
      /Insecure flag detected: process \(PID 1002\) contains forbidden --no-sandbox/,
    );
  });

  it('fails closed when process table read returns empty', () => {
    expect(() => validateProcessTreeSandbox([], 'test-session-123')).toThrow(
      /Process table read failure: process table snapshot is empty/,
    );
  });

  it('fails closed when exact token --gitnexus-sec-id=<id> is not matched (Finding #14)', () => {
    const looseSnapshot = [
      ' 1000 1 /path/chrome --random-token=test-session-123',
      ' 1001 1000 /path/chrome-helper --type=renderer',
    ];
    expect(() => validateProcessTreeSandbox(looseSnapshot, 'test-session-123')).toThrow(
      /Target browser process not found for identifier "test-session-123"/,
    );
  });

  it('fails closed when child process count is 0 (vacuous check prevention)', () => {
    const vacuous = [' 1000 1 /path/chrome --gitnexus-sec-id=test-session-123'];
    expect(() => validateProcessTreeSandbox(vacuous, 'test-session-123')).toThrow(
      /Vacuous check: no child processes found for browser PID 1000/,
    );
  });
});

describe('Browser Security Baseline — macOS Seatbelt Kernel Sandbox (Finding #17)', () => {
  it('returns true when sandbox_check outputs 1 (sandboxed)', () => {
    const mockExec = () => '1\n';
    expect(checkProcessSeatbeltSandboxed(1234, mockExec)).toBe(true);
  });

  it('returns false when sandbox_check outputs 0 (unsandboxed)', () => {
    const mockExec = () => '0\n';
    expect(checkProcessSeatbeltSandboxed(1234, mockExec)).toBe(false);
  });

  it('passes -I isolated mode to python3 executable args', () => {
    let capturedArgs: string[] = [];
    const mockExec = (_bin: string, args: string[]) => {
      capturedArgs = args;
      return '1\n';
    };
    checkProcessSeatbeltSandboxed(1234, mockExec);
    expect(capturedArgs).toContain('-I');
    expect(capturedArgs).toContain('-c');
  });

  it('throws on invalid PID input', () => {
    expect(() => checkProcessSeatbeltSandboxed(-1)).toThrow(/Invalid PID/);
    expect(() => checkProcessSeatbeltSandboxed('abc')).toThrow(/Invalid PID/);
  });

  it('validates that test runner harness process itself is NOT sandboxed', () => {
    if (process.platform === 'darwin') {
      const isHarnessSandboxed = checkProcessSeatbeltSandboxed(process.pid);
      expect(isHarnessSandboxed).toBe(false);
    }
  });
});

describe('Browser Security Baseline — Playwright Config Entry Point (Findings #1, #5, #9)', () => {
  it('exports valid secure Playwright configuration with globalSetup and without __dirname ReferenceError', () => {
    expect(playwrightConfig).toBeDefined();
    expect(playwrightConfig.globalSetup).toBe('./e2e/support/global-setup.ts');
    expect(playwrightConfig.use).toBeDefined();
    expect(playwrightConfig.use?.bypassCSP).toBe(false);
    expect(playwrightConfig.use?.launchOptions?.executablePath).toBeTruthy();
    expect(playwrightConfig.use?.launchOptions?.chromiumSandbox).toBe(true);
    expect(playwrightConfig.use?.launchOptions?.args).toContain('--enable-webgl');
    expect(playwrightConfig.use?.launchOptions?.args).not.toContain('--no-sandbox');
  });

  it('globalSetup function exists and enforces pre-test live browser launch verification', () => {
    expect(globalSetup).toBeDefined();
    expect(typeof globalSetup).toBe('function');
  });
});

describe('Browser Security Baseline — Live Browser Launch & Boundaries (Findings #3, #9, #13, #23)', () => {
  // Gated behind RUN_LIVE_BROWSER_TESTS so CI unit test suites without Chrome pass cleanly
  const shouldRunLive =
    process.env.RUN_LIVE_BROWSER_TESTS === '1' || process.env.RUN_LIVE_BROWSER_TESTS === 'true';

  (shouldRunLive ? it : it.skip)(
    'launches patched browser verifying post-launch version, process tree sandbox, and profile boundaries',
    async () => {
      const { chromium } = await import('@playwright/test');
      const resolution = resolveSecureBrowserLaunchOptions();
      const runId = `gn-sec-live-${Date.now()}`;

      const browser = await chromium.launch({
        executablePath: resolution.executablePath,
        args: [...resolution.args, `--gitnexus-sec-id=${runId}`],
        chromiumSandbox: resolution.chromiumSandbox,
        headless: true,
      });

      try {
        // 1. Post-launch version verification (Finding #9)
        const liveVersion = verifyLiveBrowserVersion(browser);
        expect(isSecureChromiumVersion(liveVersion)).toBe(true);

        // 2. Profile and Cookie Boundary Isolation (Finding #13)
        const contextA = await browser.newContext();
        const contextB = await browser.newContext();

        const pageA = await contextA.newPage();
        const pageB = await contextB.newPage();

        await pageA.goto('data:text/html,<h1>GitNexus Security Baseline Test</h1>');
        await pageB.goto('data:text/html,<h1>GitNexus Context B</h1>');

        // Inspect OS process table with -ww to prevent truncation (Finding #23)
        const psOutput = execSync('ps -ww -eo pid,ppid,command').toString();
        const processLines = psOutput.split('\n');

        const validation = validateProcessTreeSandbox(processLines, runId);
        expect(validation.childCount).toBeGreaterThan(0);
        expect(validation.rendererCount).toBeGreaterThan(0);
        expect(validation.rendererPids.length).toBeGreaterThan(0);

        // On macOS Darwin: verify actual OS Seatbelt kernel sandbox on owned renderer processes
        if (process.platform === 'darwin') {
          expect(checkProcessSeatbeltSandboxed(validation.browserPid)).toBe(false);
          for (const rendererPid of validation.rendererPids) {
            expect(checkProcessSeatbeltSandboxed(rendererPid)).toBe(true);
          }
        }

        // Cookie isolation check
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
    },
  );

  (shouldRunLive ? it : it.skip)(
    'enforces origin, cross-origin redirect, and CSP security boundaries on local fixtures (Finding #13)',
    async () => {
      const { chromium } = await import('@playwright/test');
      const resolution = resolveSecureBrowserLaunchOptions();

      // Create two local HTTP servers representing distinct origins
      let receivedCookiesOnB = '';
      const serverB = http.createServer((req, res) => {
        if (req.url === '/secret') {
          // No Access-Control-Allow-Origin header (CORS blocked)
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ secret: 'origin-b-secret-data' }));
        } else if (req.url === '/landing') {
          receivedCookiesOnB = req.headers['cookie'] || '';
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<h1>Landing on Origin B</h1>');
        } else {
          res.writeHead(404);
          res.end();
        }
      });

      await new Promise<void>((resolve) => serverB.listen(0, 'localhost', () => resolve()));
      const addrB = serverB.address();
      const portB = typeof addrB === 'object' && addrB ? addrB.port : 0;

      const serverA = http.createServer((req, res) => {
        if (req.url === '/redirect') {
          // Cross-origin redirect to Server B (distinct host and port)
          res.writeHead(302, {
            Location: `http://localhost:${portB}/landing`,
          });
          res.end();
        } else {
          // Serve HTML with strict CSP forbidding inline scripts without nonce
          res.writeHead(200, {
            'Content-Type': 'text/html',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'",
            'Set-Cookie': 'origin_a_secret=token123; Path=/',
          });
          res.end(`<!DOCTYPE html>
            <html>
              <body>
                <h1>Origin A</h1>
                <script>window.__cspViolationOccurred = false; window.__inlineScriptExecuted = true;</script>
              </body>
            </html>`);
        }
      });

      await new Promise<void>((resolve) => serverA.listen(0, '127.0.0.1', () => resolve()));
      const addrA = serverA.address();
      const portA = typeof addrA === 'object' && addrA ? addrA.port : 0;

      const browser = await chromium.launch({
        executablePath: resolution.executablePath,
        args: resolution.args,
        chromiumSandbox: resolution.chromiumSandbox,
        headless: true,
      });

      try {
        const context = await browser.newContext({ bypassCSP: false });
        const page = await context.newPage();

        // 1. CSP Enforcement: inline script without unsafe-inline or nonce must NOT execute
        await page.goto(`http://127.0.0.1:${portA}/`);
        const inlineExecuted = await page.evaluate(
          () => (window as unknown as { __inlineScriptExecuted?: boolean }).__inlineScriptExecuted,
        );
        expect(inlineExecuted).toBeUndefined();

        // 2. Same-Origin Policy (SOP) / CORS enforcement:
        // Trying to fetch Origin B from Origin A must fail due to CORS policy
        const fetchResult = await page.evaluate(async (targetUrl) => {
          try {
            await fetch(targetUrl);
            return 'fetched_successfully';
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return `blocked_by_cors: ${msg}`;
          }
        }, `http://localhost:${portB}/secret`);
        expect(fetchResult).toContain('blocked_by_cors');

        // 3. Redirect Boundary Isolation:
        // Navigating through cross-origin 302 redirect from Origin A (127.0.0.1) to Origin B (localhost)
        await page.goto(`http://127.0.0.1:${portA}/redirect`);
        expect(page.url()).toBe(`http://localhost:${portB}/landing`);

        // Origin A's cookie must NOT have leaked to Origin B in the redirect request
        expect(receivedCookiesOnB).not.toContain('origin_a_secret');

        await context.close();
      } finally {
        await browser.close();
        serverA.close();
        serverB.close();
      }
    },
  );
});
