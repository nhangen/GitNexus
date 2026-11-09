import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { execSync, spawnSync } from 'child_process';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import {
  compareChromiumVersions,
  isSecureChromiumVersion,
  getMinimumSecurityBaseline,
  parseChromiumVersion,
  probeBrowserVersion,
  verifyLiveBrowserVersion,
  sanitizeLaunchArgs,
  findDisallowedFlag,
  resolveSecureBrowserLaunchOptions,
  collectProcessTree,
  validateProcessTreeSandbox,
  checkProcessSeatbeltSandboxed,
  readLinuxSandboxState,
  getSystemCandidatePaths,
  MIN_CHROMIUM_SECURITY_VERSION,
  MIN_CHROMIUM_SECURITY_VERSION_POSIX,
  MIN_CHROMIUM_SECURITY_VERSION_WIN32,
  PINNED_CFT_VERSION,
  OFFICIAL_CFT_ARTIFACTS,
  CRITICAL_CHROME_CNA_RECORDS,
  DISALLOWED_SECURITY_FLAGS,
  DISALLOWED_PROCESS_FLAGS,
  REQUIRED_BASE_LAUNCH_ARGS,
  SYSTEM_PYTHON3,
  type LinuxProcReader,
  type SecureBrowserResolution,
} from '../../e2e/support/browser-security';
import globalSetup, {
  createGlobalSetup,
  defaultGlobalSetupDeps,
} from '../../e2e/support/global-setup';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(TEST_DIR, '../..');
const REPO_ROOT = path.resolve(WEB_ROOT, '..');

const BROWSER_ENV_VARS = [
  'PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH',
  'CHROME_BIN',
  'CHROME_PATH',
  'CHROMIUM_PATH',
] as const;

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
  '--remote-debugging-address',
  '--remote-debugging-port',
  '--remote-allow-origins',
  '--renderer-cmd-prefix',
  '--browser-subprocess-path',
  '--disable-site-isolation-for-policy',
  '--no-sandbox-and-elevated',
  '--ignore-certificate-errors',
  '--allow-running-insecure-content',
  '--allow-file-access-from-files',
  '--in-process-gpu',
  '--zygote-cmd-prefix',
  '--utility-cmd-prefix',
  '--gpu-launcher',
  '--no-zygote-sandbox',
  '--allow-insecure-localhost',
  '--unsafely-treat-insecure-origin-as-secure',
  '--user-data-dir',
];

const LITERAL_DISALLOWED_PROCESS_FLAGS = [
  '--no-sandbox',
  '--disable-web-security',
  '--disable-site-isolation-trials',
  '--disable-setuid-sandbox',
  '--single-process',
  '--no-zygote',
  '--disable-gpu-sandbox',
  '--disable-seccomp-filter-sandbox',
  '--disable-namespace-sandbox',
  '--remote-debugging-address',
  '--remote-debugging-port',
  '--renderer-cmd-prefix',
  '--browser-subprocess-path',
  '--disable-site-isolation-for-policy',
  '--no-sandbox-and-elevated',
];

function writeStubBrowser(dir: string, versionLine: string): string {
  const stub = path.join(dir, `chrome-stub-${versionLine.replace(/\W+/g, '_')}`);
  fs.writeFileSync(stub, `#!/bin/sh\necho "${versionLine}"\n`, { mode: 0o755 });
  return stub;
}

function envWithoutBrowserOverrides(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const name of BROWSER_ENV_VARS) delete env[name];
  delete env.GITNEXUS_EXPECTED_CHROME_VERSION;
  return env;
}

describe('Chromium version verification', () => {
  describe('compareChromiumVersions', () => {
    it('compares identical versions as equal', () => {
      expect(compareChromiumVersions('156.0.8078.73', '156.0.8078.73')).toBe(0);
      expect(compareChromiumVersions('156.0.8078.80', '156.0.8078.80')).toBe(0);
    });

    it('compares major, minor, build, and patch components', () => {
      expect(compareChromiumVersions('157.0.0.0', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('155.0.0.0', '156.0.8078.80')).toBe(-1);
      expect(compareChromiumVersions('156.1.0.0', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('156.0.8079.0', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('156.0.8078.81', '156.0.8078.80')).toBe(1);
      expect(compareChromiumVersions('156.0.8078.79', '156.0.8078.80')).toBe(-1);
    });

    it('treats a 3-component version as patch 0', () => {
      expect(compareChromiumVersions('156.0.8078', '156.0.8078.0')).toBe(0);
      expect(compareChromiumVersions('156.0.8078', '156.0.8078.1')).toBe(-1);
    });

    it('rejects malformed versions', () => {
      expect(() => compareChromiumVersions('invalid', '156.0.8078.73')).toThrow();
      expect(() => compareChromiumVersions('156.0', '156.0.8078.73')).toThrow();
      expect(() => compareChromiumVersions('156.0.8078.73.1', '156.0.8078.73')).toThrow();
    });

    it('rejects empty, hex, signed, and exponent components', () => {
      for (const bad of ['156..8078.80', '0x9c.0.8078.80', '156.0.8078.+80', '156.0.1e3.80']) {
        expect(() => compareChromiumVersions(bad, '156.0.8078.73')).toThrow(
          /Invalid version component/,
        );
      }
    });
  });

  describe('isSecureChromiumVersion and per-platform floors', () => {
    it('reports the per-platform floor constants', () => {
      expect(MIN_CHROMIUM_SECURITY_VERSION).toBe('156.0.8078.73');
      expect(MIN_CHROMIUM_SECURITY_VERSION_POSIX).toBe('156.0.8078.73');
      expect(MIN_CHROMIUM_SECURITY_VERSION_WIN32).toBe('156.0.8078.74');
      expect(getMinimumSecurityBaseline('linux')).toBe('156.0.8078.73');
      expect(getMinimumSecurityBaseline('darwin')).toBe('156.0.8078.73');
      expect(getMinimumSecurityBaseline('win32')).toBe('156.0.8078.74');
    });

    it('accepts versions meeting the platform floor', () => {
      expect(isSecureChromiumVersion('156.0.8078.73', 'linux')).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.73', 'darwin')).toBe(true);
      expect(isSecureChromiumVersion('156.0.8078.73', 'win32')).toBe(false);
      expect(isSecureChromiumVersion('156.0.8078.74', 'win32')).toBe(true);
      expect(isSecureChromiumVersion(PINNED_CFT_VERSION)).toBe(true);
      expect(isSecureChromiumVersion('157.0.0.0')).toBe(true);
    });

    it('rejects the Playwright 1.58.2 bundled Chromium (145.0.7632.6)', () => {
      expect(isSecureChromiumVersion('145.0.7632.6')).toBe(false);
    });

    it('rejects the Playwright 1.64.1 mapped Chromium (156.0.8078.4)', () => {
      expect(isSecureChromiumVersion('156.0.8078.4')).toBe(false);
    });

    it('rejects builds below the floor', () => {
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

    it('rejects non-Chromium output even with four dotted integers', () => {
      for (const output of [
        'Mozilla Firefox 160.0.1.2',
        'SomeOtherBrowser 156.0.8078.80',
        'v22.22.3.4',
        '',
        'command not found: chrome',
      ]) {
        expect(() => parseChromiumVersion(output)).toThrow(/cannot parse Chromium version/);
      }
    });

    it('rejects a recognized product name that does not start the line', () => {
      expect(() => parseChromiumVersion('NotChrome wrapper; Chromium 999.0.0.0')).toThrow(
        /cannot parse Chromium version/,
      );
    });

    it('rejects a recognized product line that is not the first line of output', () => {
      expect(() => parseChromiumVersion('Wrapper banner\nChromium 999.0.0.0')).toThrow(
        /cannot parse Chromium version/,
      );
    });

    it('rejects a version token glued to trailing characters', () => {
      expect(() => parseChromiumVersion('Google Chrome 156.0.8078.80beta')).toThrow(
        /cannot parse Chromium version/,
      );
    });
  });

  describe('probeBrowserVersion and verifyLiveBrowserVersion', () => {
    it('probes the executable and returns the parsed version', () => {
      const mockExec = () => 'Google Chrome 156.0.8078.80\n';
      expect(probeBrowserVersion('/mock/chrome', mockExec)).toBe('156.0.8078.80');
    });

    it('refuses the executable when running it fails', () => {
      const mockExec = () => {
        throw new Error('ENOENT: no such file or directory');
      };
      expect(() => probeBrowserVersion('/nonexistent/chrome', mockExec)).toThrow(
        /execution failed/,
      );
    });

    it('rejects a live version below the floor', () => {
      expect(verifyLiveBrowserVersion({ version: () => '156.0.8078.80' }, 'linux')).toBe(
        '156.0.8078.80',
      );
      expect(() => verifyLiveBrowserVersion({ version: () => '145.0.7632.6' }, 'linux')).toThrow(
        /below minimum secure baseline/,
      );
    });

    it('applies the Windows floor to a Windows live browser', () => {
      expect(() => verifyLiveBrowserVersion({ version: () => '156.0.8078.73' }, 'win32')).toThrow(
        /below minimum secure baseline 156.0.8078.74/,
      );
    });

    it('rejects a live version that differs from a required exact pin', () => {
      expect(() =>
        verifyLiveBrowserVersion({ version: () => '156.0.8078.81' }, 'linux', '156.0.8078.80'),
      ).toThrow(/does not match the required pinned version 156.0.8078.80/);
    });
  });
});

describe('Launch argument deny list', () => {
  it('preserves the required WebGL rendering flags', () => {
    const args = sanitizeLaunchArgs();
    for (const flag of [
      '--use-gl=angle',
      '--use-angle=swiftshader',
      '--enable-webgl',
      '--enable-unsafe-swiftshader',
    ]) {
      expect(args).toContain(flag);
    }
    expect([...REQUIRED_BASE_LAUNCH_ARGS].sort()).toEqual([
      '--enable-unsafe-swiftshader',
      '--enable-webgl',
      '--use-angle=swiftshader',
      '--use-gl=angle',
    ]);
  });

  it('rejects every disallowed flag, bare and with a value', () => {
    for (const disallowed of LITERAL_DISALLOWED_FLAGS) {
      expect(() => sanitizeLaunchArgs([disallowed])).toThrow(/Insecure launch argument rejected/);
      expect(() => sanitizeLaunchArgs([`${disallowed}=value`])).toThrow(
        /Insecure launch argument rejected/,
      );
    }
  });

  it('rejects single-dash and upper-case spellings Chromium also accepts', () => {
    for (const arg of ['-no-sandbox', '--NO-SANDBOX', '-Disable-Web-Security', '---no-sandbox']) {
      expect(() => sanitizeLaunchArgs([arg])).toThrow(/Insecure launch argument rejected/);
    }
  });

  it('rejects disabling site isolation features alone or inside a feature list', () => {
    for (const arg of [
      '--disable-features=site-per-process',
      '--disable-features=IsolateOrigins',
      '--disable-features=IsolateOrigins,site-per-process',
      '--disable-features=Translate, site-per-process',
      '--disable-features=isolateorigins',
      '--disable-features=SitePerProcess',
      '--disable-features=Translate,SitePerProcess',
      '--disable-features=IsolateSandboxedIframes',
      '--disable-features=IsolateOrigins<Study',
      '--disable-features=SitePerProcess:param/value',
      '--disable-features=*IsolateOrigins',
      '--disable-features="site-per-process"',
      '"--disable-features=SitePerProcess"',
    ]) {
      expect(() => sanitizeLaunchArgs([arg])).toThrow(/Insecure launch argument rejected/);
    }
  });

  it('rejects the Windows slash switch prefix only on Windows', () => {
    expect(findDisallowedFlag('/no-sandbox', DISALLOWED_SECURITY_FLAGS, 'win32')).toBe(
      '--no-sandbox',
    );
    expect(findDisallowedFlag('/NO-SANDBOX', DISALLOWED_PROCESS_FLAGS, 'win32')).toBe(
      '--no-sandbox',
    );
    expect(findDisallowedFlag('/no-sandbox', DISALLOWED_SECURITY_FLAGS, 'linux')).toBeUndefined();
  });

  it('allows unrelated disabled features and safe custom flags', () => {
    const sanitized = sanitizeLaunchArgs([
      '--custom-safe-flag',
      '--start-maximized',
      '--disable-features=Translate,MediaRouter',
    ]);
    expect(sanitized).toContain('--custom-safe-flag');
    expect(sanitized).toContain('--start-maximized');
    expect(sanitized).toContain('--disable-features=Translate,MediaRouter');
    expect(sanitized).toContain('--enable-webgl');
  });

  it('lists every literal disallowed flag', () => {
    for (const flag of LITERAL_DISALLOWED_FLAGS) {
      expect(DISALLOWED_SECURITY_FLAGS).toContain(flag);
    }
    for (const flag of LITERAL_DISALLOWED_PROCESS_FLAGS) {
      expect(DISALLOWED_PROCESS_FLAGS).toContain(flag);
    }
  });

  it('ignores non-flag tokens such as executable paths', () => {
    expect(findDisallowedFlag('/opt/no-sandbox/chrome', DISALLOWED_PROCESS_FLAGS)).toBeUndefined();
  });
});

describe('Fail-closed executable resolution', () => {
  describe('option branch', () => {
    it('returns source option for a binary at the floor or above', () => {
      const resolution = resolveSecureBrowserLaunchOptions({
        customExecutablePath: '/usr/bin/custom-chrome',
        fsExists: () => true,
        execCommand: () => 'Google Chrome 156.0.8078.80\n',
      });

      expect(resolution.executablePath).toBe(path.resolve('/usr/bin/custom-chrome'));
      expect(resolution.version).toBe('156.0.8078.80');
      expect(resolution.source).toBe('option');
      expect(resolution.chromiumSandbox).toBe(true);
    });

    it('refuses a missing custom executable', () => {
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          customExecutablePath: '/missing/chrome',
          fsExists: () => false,
        }),
      ).toThrow(/executable file not found/);
    });

    it('refuses a custom executable below the floor', () => {
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          customExecutablePath: '/old/chrome',
          fsExists: () => true,
          execCommand: () => 'Google Chrome 145.0.7632.6\n',
        }),
      ).toThrow(/below minimum secure baseline/);
    });
  });

  describe('environment branch', () => {
    it('returns source env when CHROME_BIN meets the floor', () => {
      const resolution = resolveSecureBrowserLaunchOptions({
        env: { CHROME_BIN: '/usr/bin/google-chrome' },
        fsExists: (p: string) => p.includes('google-chrome'),
        execCommand: () => 'Google Chrome 156.0.8078.80\n',
      });

      expect(resolution.executablePath).toBe(path.resolve('/usr/bin/google-chrome'));
      expect(resolution.version).toBe('156.0.8078.80');
      expect(resolution.source).toBe('env');
      expect(resolution.chromiumSandbox).toBe(true);
    });

    it('refuses a missing env candidate', () => {
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: { CHROME_BIN: '/missing/env-chrome' },
          fsExists: () => false,
        }),
      ).toThrow(/executable file not found/);
    });

    it('refuses an env candidate below the floor and names the advisory records', () => {
      let errorMsg = '';
      try {
        resolveSecureBrowserLaunchOptions({
          env: { CHROME_BIN: '/usr/bin/old-chrome' },
          fsExists: () => true,
          execCommand: () => 'Google Chrome 145.0.7632.6\n',
        });
      } catch (err) {
        errorMsg = (err as Error).message;
      }

      expect(errorMsg).toMatch(/below minimum secure baseline/);
      for (const cna of ['118306', '118331', '118348', '118344']) {
        expect(errorMsg).toContain(cna);
      }
      expect([...CRITICAL_CHROME_CNA_RECORDS]).toEqual(['118306', '118331', '118348', '118344']);
    });
  });

  describe('local Chrome for Testing branch', () => {
    it('returns source cft for the pinned build', () => {
      const resolution = resolveSecureBrowserLaunchOptions({
        env: {},
        fsExists: (p: string) => p.includes('chrome-linux64/chrome'),
        execCommand: () => 'Google Chrome for Testing 156.0.8078.80\n',
      });

      expect(resolution.source).toBe('cft');
      expect(resolution.version).toBe('156.0.8078.80');
      expect(resolution.chromiumSandbox).toBe(true);
    });

    it('fails closed when the local build is below the floor', () => {
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: {},
          fsExists: (p: string) => p.includes('chrome-linux64/chrome'),
          execCommand: () => 'Google Chrome for Testing 156.0.8078.70\n',
          platform: 'linux',
        }),
      ).toThrow(/No secure Chromium browser executable resolved/);
    });

    it('rejects a local build at the floor that is not the pinned build', () => {
      let errorMsg = '';
      try {
        resolveSecureBrowserLaunchOptions({
          env: {},
          fsExists: (p: string) => p.includes('chrome-linux64/chrome'),
          execCommand: () => 'Google Chrome for Testing 156.0.8078.73\n',
          platform: 'linux',
        });
      } catch (err) {
        errorMsg = (err as Error).message;
      }

      expect(errorMsg).toContain('does not match pinned CfT 156.0.8078.80');
    });

    it('looks for local builds under the package and repo roots, not the working directory', () => {
      const probed: string[] = [];
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: {},
          platform: 'linux',
          fsExists: (p: string) => {
            probed.push(p);
            return false;
          },
        }),
      ).toThrow(/No secure Chromium browser executable resolved/);

      const cftProbes = probed.filter((p) => p.includes(`${path.sep}.browsers${path.sep}`));
      expect(cftProbes.length).toBeGreaterThan(0);
      for (const candidate of cftProbes) {
        const root = candidate.slice(0, candidate.indexOf(`${path.sep}.browsers${path.sep}`));
        expect([WEB_ROOT, REPO_ROOT]).toContain(root);
      }
    });
  });

  describe('system branch', () => {
    it('returns source system when system Chrome meets the floor', () => {
      const resolution = resolveSecureBrowserLaunchOptions({
        env: {},
        platform: 'linux',
        fsExists: (p: string) => p === '/usr/bin/google-chrome',
        execCommand: () => 'Google Chrome 156.0.8078.74\n',
      });

      expect(resolution.executablePath).toBe('/usr/bin/google-chrome');
      expect(resolution.version).toBe('156.0.8078.74');
      expect(resolution.source).toBe('system');
      expect(resolution.chromiumSandbox).toBe(true);
    });

    it('fails closed when system Chrome is below the floor', () => {
      expect(() =>
        resolveSecureBrowserLaunchOptions({
          env: {},
          platform: 'linux',
          fsExists: (p: string) => p === '/usr/bin/google-chrome',
          execCommand: () => 'Google Chrome 156.0.8078.70\n',
        }),
      ).toThrow(/No secure Chromium browser executable resolved/);
    });

    it('fails closed when no candidate exists at all', () => {
      expect(() =>
        resolveSecureBrowserLaunchOptions({ env: {}, platform: 'linux', fsExists: () => false }),
      ).toThrow(/No secure Chromium browser executable resolved/);
    });
  });

  it('lists per-candidate reasons when no candidate qualifies', () => {
    let errorMsg = '';
    try {
      resolveSecureBrowserLaunchOptions({
        env: {},
        platform: 'linux',
        fsExists: (p: string) => p === '/usr/bin/google-chrome',
        execCommand: () => 'Google Chrome 155.0.0.0\n',
      });
    } catch (err) {
      errorMsg = (err as Error).message;
    }

    expect(errorMsg).toContain('Diagnostic scan results:');
    expect(errorMsg).toContain(
      '[system /usr/bin/google-chrome]: version 155.0.0.0 < 156.0.8078.73',
    );
  });

  it('does not build candidate paths from empty or whitespace base directories', () => {
    const darwinCandidates = getSystemCandidatePaths('darwin', { HOME: '   ' });
    for (const candidate of darwinCandidates) {
      expect(path.isAbsolute(candidate)).toBe(true);
      expect(candidate.startsWith('/Applications/')).toBe(true);
    }

    const winCandidates = getSystemCandidatePaths('win32', {
      LOCALAPPDATA: '',
      ProgramFiles: '',
      'ProgramFiles(x86)': '',
    });
    expect(winCandidates).toHaveLength(0);
  });
});

const EXPECTED_PATH_FILTER = [
  '          filters: |',
  '            web:',
  "              - 'gitnexus-web/**'",
  "              - '.github/workflows/ci-e2e.yml'",
  "              - '.github/actions/setup-gitnexus-web/**'",
];

const EXPECTED_E2E_JOB_HEADER = [
  '  e2e:',
  '    name: e2e (chrome)',
  '    needs: check-changes',
  "    if: needs.check-changes.result == 'success' && needs.check-changes.outputs.web_changed == 'true'",
  '    runs-on: ubuntu-latest',
  '    timeout-minutes: 20',
  '    steps:',
  '      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2',
  '        with:',
  '          persist-credentials: false',
];

const EXPECTED_CFT_INSTALL_STEP = [
  '      - name: Install pinned Chrome for Testing (GCS object size/MD5 check, not a signature)',
  '        run: |',
  '          CFT_VERSION="156.0.8078.80"',
  '          CFT_URL="https://storage.googleapis.com/chrome-for-testing-public/${CFT_VERSION}/linux64/chrome-linux64.zip"',
  '          EXPECTED_MD5="6a158ba7e01da016f1988bae0643d9e5"',
  '          EXPECTED_SIZE="201329937"',
  '          DEST_DIR="${RUNNER_TEMP}/chrome-for-testing"',
  '',
  '          mkdir -p "${DEST_DIR}"',
  '          cd "${DEST_DIR}"',
  '',
  '          echo "Downloading official Chrome for Testing ${CFT_VERSION}..."',
  "          curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \\",
  '            --retry 3 --retry-delay 5 -o chrome-linux64.zip "${CFT_URL}"',
  '',
  '          # Verify exact archive file size',
  "          ACTUAL_SIZE=$(wc -c < chrome-linux64.zip | tr -d ' ')",
  '          if [ "${ACTUAL_SIZE}" != "${EXPECTED_SIZE}" ]; then',
  '            echo "::error::CfT archive size mismatch: expected ${EXPECTED_SIZE}, got ${ACTUAL_SIZE}"',
  '            exit 1',
  '          fi',
  '',
  '          echo "${EXPECTED_MD5}  chrome-linux64.zip" | md5sum -c - || {',
  '            echo "::error::CfT archive MD5 does not match recorded GCS object metadata"',
  '            exit 1',
  '          }',
  '',
  '          echo "Archive matches recorded GCS object size and MD5. Extracting..."',
  '          unzip -q chrome-linux64.zip',
  '          chmod +x chrome-linux64/chrome',
  '',
  "          PROBED_OUTPUT=$(./chrome-linux64/chrome --version | tr -d '\\r' | sed -e 's/[[:space:]]*$//')",
  '          echo "Probed executable: ${PROBED_OUTPUT}"',
  '          if [ "${PROBED_OUTPUT}" != "Google Chrome for Testing ${CFT_VERSION}" ]; then',
  "            echo \"::error::Executable reports '${PROBED_OUTPUT}', expected 'Google Chrome for Testing ${CFT_VERSION}'\"",
  '            exit 1',
  '          fi',
  '',
  '          echo "CHROME_BIN=${DEST_DIR}/chrome-linux64/chrome" >> "$GITHUB_ENV"',
  '          echo "GITNEXUS_EXPECTED_CHROME_VERSION=${CFT_VERSION}" >> "$GITHUB_ENV"',
  '        working-directory: gitnexus-web',
  '',
  '      - name: Install backend dependencies',
];

const EXPECTED_LIVE_CHECK_STEP = [
  '      # Launches the pinned build with chromiumSandbox: true and checks the live process tree,',
  '      # the kernel sandbox state of its renderers (/proc Seccomp and namespaces on Linux), and',
  '      # that the configured context enforces CSP and CORS. The results check fails unless every',
  '      # live test actually ran and passed; a skipped or excluded test file exits 0 otherwise.',
  '      # It runs after every install and build step. The backend and Vite servers started earlier',
  '      # keep running, so this narrows the window before the E2E launch rather than closing it.',
  '      - name: Verify live browser sandbox, CSP and CORS',
  '        run: |',
  '          npx vitest run test/unit/browser-security.test.ts --reporter=default --reporter=json --outputFile.json="${RUNNER_TEMP}/live-browser-results.json"',
  '          node e2e/support/assert-live-results.mjs "${RUNNER_TEMP}/live-browser-results.json"',
  '        working-directory: gitnexus-web',
  '        env:',
  "          RUN_LIVE_BROWSER_TESTS: '1'",
  "          PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH: ''",
  '          CHROME_BIN: ${{ env.CHROME_BIN }}',
  "          CHROME_PATH: ''",
  "          CHROMIUM_PATH: ''",
  '          GITNEXUS_EXPECTED_CHROME_VERSION: ${{ env.GITNEXUS_EXPECTED_CHROME_VERSION }}',
  '',
  '      - name: Run E2E tests',
];

const EXPECTED_E2E_TEST_STEP = [
  '      - name: Run E2E tests',
  '        run: npx playwright test',
  '        working-directory: gitnexus-web',
  '        env:',
  "          E2E: '1'",
  "          PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH: ''",
  '          CHROME_BIN: ${{ env.CHROME_BIN }}',
  "          CHROME_PATH: ''",
  "          CHROMIUM_PATH: ''",
  '          GITNEXUS_EXPECTED_CHROME_VERSION: ${{ env.GITNEXUS_EXPECTED_CHROME_VERSION }}',
  '',
  '      - name: Upload test results',
];

const EXPECTED_CI_E2E_CALLER = [
  '  e2e:',
  '    uses: ./.github/workflows/ci-e2e.yml',
  '    permissions:',
  '      contents: read',
  '',
  '  scope-parity:',
];

const REVIEWED_FILE_SHA256: Record<string, string> = {
  '.github/workflows/ci-e2e.yml':
    '83b39622b7610f6d53286e17a20ca88552d603433afbfa99b45511b7ceaab889',
  '.github/actions/setup-gitnexus-web/action.yml':
    '3845c12ad70b565aa3efd70c7bb27c019bc3a8048b189d907c0761ff71f49e2f',
  'gitnexus-web/e2e/support/assert-live-results.mjs':
    'daaf858ec7878654ec24225605d0c525f5ef764ea57e7ef755e36191b05a17f5',
};

describe('CI pin parity with the resolver', () => {
  const workflow = fs.readFileSync(path.join(REPO_ROOT, '.github/workflows/ci-e2e.yml'), 'utf8');
  const workflowLines = workflow.replace(/\r\n/g, '\n').split('\n');

  function exactBlock(expected: string[]): string[] {
    const starts = workflowLines.flatMap((line, i) => (line === expected[0] ? [i] : []));
    expect(starts, `block start must appear exactly once: ${expected[0]}`).toHaveLength(1);
    return workflowLines.slice(starts[0], starts[0] + expected.length);
  }

  function jobOf(lineIndex: number): string | undefined {
    for (let i = lineIndex; i >= 0; i--) {
      const match = workflowLines[i].match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
      if (match) return match[1];
    }
    return undefined;
  }

  it('downloads the same Chrome for Testing build the resolver pins', () => {
    expect(workflow).toContain(`CFT_VERSION="${PINNED_CFT_VERSION}"`);
    const urlTemplate = workflow.match(/CFT_URL="([^"]+)"/)?.[1];
    expect(urlTemplate?.replace('${CFT_VERSION}', PINNED_CFT_VERSION)).toBe(
      OFFICIAL_CFT_ARTIFACTS.downloads.linux64.url,
    );
  });

  // Exact-text contracts: any edit to these blocks, however it is spelled, must come with a
  // reviewed update to the expected text here. Each step block runs through the next step's
  // first line so nothing (a key, or a comment followed by a key) can be appended to it.
  it('keeps the pinned download, integrity checks, and live sandbox step exactly as reviewed', () => {
    expect(exactBlock(EXPECTED_CFT_INSTALL_STEP)).toEqual(EXPECTED_CFT_INSTALL_STEP);
    expect(exactBlock(EXPECTED_LIVE_CHECK_STEP)).toEqual(EXPECTED_LIVE_CHECK_STEP);
  });

  it('runs the E2E tests against the pinned executable exactly as reviewed', () => {
    expect(exactBlock(EXPECTED_E2E_TEST_STEP)).toEqual(EXPECTED_E2E_TEST_STEP);
  });

  it('runs the e2e job unconditionally after a web, workflow, or setup-action change', () => {
    expect(exactBlock(EXPECTED_E2E_JOB_HEADER)).toEqual(EXPECTED_E2E_JOB_HEADER);
    expect(exactBlock(EXPECTED_PATH_FILTER)).toEqual(EXPECTED_PATH_FILTER);
  });

  it('does not persist the checkout token into later steps', () => {
    const checkouts = workflowLines.flatMap((line, i) =>
      line.includes('uses: actions/checkout@') ? [i] : [],
    );
    expect(checkouts).toHaveLength(2);
    for (const i of checkouts) {
      expect(workflowLines.slice(i + 1, i + 3).map((l) => l.trim())).toEqual([
        'with:',
        'persist-credentials: false',
      ]);
    }
  });

  it('defines only the reviewed jobs, with the security steps inside the e2e job', () => {
    const jobsAt = workflowLines.indexOf('jobs:');
    const jobKeys = workflowLines
      .slice(jobsAt + 1)
      .flatMap((line) => line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/)?.[1] ?? []);
    expect(jobKeys).toEqual(['check-changes', 'e2e']);
    for (const start of [
      EXPECTED_CFT_INSTALL_STEP[0],
      EXPECTED_LIVE_CHECK_STEP[0],
      EXPECTED_E2E_TEST_STEP[0],
    ]) {
      expect(jobOf(workflowLines.indexOf(start))).toBe('e2e');
    }
  });

  it('pins the full reviewed text of the E2E workflow and its setup action', () => {
    for (const [rel, expected] of Object.entries(REVIEWED_FILE_SHA256)) {
      const actual = createHash('sha256')
        .update(fs.readFileSync(path.join(REPO_ROOT, rel)))
        .digest('hex');
      expect(actual, `${rel} changed: review the whole file, then update its hash here`).toBe(
        expected,
      );
    }
  });

  it('keeps the CI entry point calling the E2E workflow unconditionally', () => {
    const ciLines = fs
      .readFileSync(path.join(REPO_ROOT, '.github/workflows/ci.yml'), 'utf8')
      .split('\n');
    const starts = ciLines.flatMap((line, i) => (line === EXPECTED_CI_E2E_CALLER[0] ? [i] : []));
    expect(starts).toHaveLength(1);
    expect(ciLines.slice(starts[0], starts[0] + EXPECTED_CI_E2E_CALLER.length)).toEqual(
      EXPECTED_CI_E2E_CALLER,
    );
  });

  it('writes GITHUB_ENV only from the reviewed lines', () => {
    expect(
      workflowLines.filter((line) => line.includes('GITHUB_ENV')).map((l) => l.trim()),
    ).toEqual([
      'run: echo "GITNEXUS_HOME=${RUNNER_TEMP}/gitnexus-home" >> "$GITHUB_ENV"',
      'echo "CHROME_BIN=${DEST_DIR}/chrome-linux64/chrome" >> "$GITHUB_ENV"',
      'echo "GITNEXUS_EXPECTED_CHROME_VERSION=${CFT_VERSION}" >> "$GITHUB_ENV"',
    ]);
  });
});

describe('Live results check used by the CI live step', () => {
  const checker = path.join(WEB_ROOT, 'e2e/support/assert-live-results.mjs');
  const PIN_SUITE = 'CI pin parity with the resolver';
  const LIVE_SUITE = 'Live browser launch and boundaries';
  const REQUIRED: Array<[string, string]> = [
    [PIN_SUITE, 'pins the full reviewed text of the E2E workflow and its setup action'],
    [PIN_SUITE, 'keeps the CI entry point calling the E2E workflow unconditionally'],
    [LIVE_SUITE, 'arms the live tests whenever CI pins an exact browser build'],
    [LIVE_SUITE, 'runs renderers of the configured browser inside the kernel sandbox'],
    [LIVE_SUITE, 'detects unsandboxed renderers when the sandbox is turned off'],
    [LIVE_SUITE, 'enforces CSP and CORS with the configured context'],
  ];
  const testFile = path.join(WEB_ROOT, 'test/unit/browser-security.test.ts');
  let reportDir: string;

  beforeEach(() => {
    reportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitnexus-live-results-'));
  });

  afterEach(() => {
    fs.rmSync(reportDir, { recursive: true, force: true });
  });

  function passingReport(name = testFile) {
    return {
      success: true,
      numFailedTests: 0,
      testResults: [
        {
          name,
          assertionResults: [
            { ancestorTitles: ['Some other suite'], title: 'unrelated', status: 'passed' },
            ...REQUIRED.map(([suite, title]) => ({
              ancestorTitles: [suite],
              title,
              status: 'passed',
            })),
          ],
        },
      ],
    };
  }

  function check(report: unknown) {
    const file = path.join(reportDir, 'report.json');
    fs.writeFileSync(file, typeof report === 'string' ? report : JSON.stringify(report));
    return spawnSync(process.execPath, [checker, file], { cwd: WEB_ROOT, encoding: 'utf8' });
  }

  function withoutTitle(title: string) {
    const report = passingReport();
    report.testResults[0].assertionResults = report.testResults[0].assertionResults.filter(
      (a) => a.title !== title,
    );
    return report;
  }

  it('names tests that exist in this file', () => {
    const source = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
    for (const suite of [PIN_SUITE, LIVE_SUITE]) expect(source).toContain(`describe('${suite}'`);
    for (const [, title] of REQUIRED) {
      expect(title).toMatch(/^[a-zA-Z0-9 ]+$/);
      expect(source).toMatch(new RegExp(`\\bit(?:\\.runIf\\(shouldRunLive\\))?\\(\\s*'${title}'`));
    }
  });

  it('accepts a run in which every required test passed', () => {
    expect(check(passingReport()).status).toBe(0);
  });

  it('rejects each required test that was skipped, as in a run without a pinned browser', () => {
    for (const [, title] of REQUIRED) {
      const report = passingReport();
      const target = report.testResults[0].assertionResults.find((a) => a.title === title);
      if (!target) throw new Error(`fixture lacks ${title}`);
      target.status = 'skipped';
      const result = check(report);
      expect(result.status, title).toBe(1);
      expect(result.stderr).toContain(`"${title}" did not pass (status: skipped)`);
    }
  });

  it('rejects a run missing any required test, as when the config filters it out', () => {
    for (const [suite, title] of REQUIRED) {
      const result = check(withoutTitle(title));
      expect(result.status, title).toBe(1);
      expect(result.stderr).toContain(`expected one "${suite} > ${title}", found 0`);
    }
  });

  it('rejects a run in which the test file was excluded', () => {
    const result = check({ ...passingReport(), testResults: [] });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('expected exactly one result');
  });

  it('rejects a same-named test file anywhere other than the reviewed path', () => {
    for (const name of [
      path.join(WEB_ROOT, 'test/decoy/test/unit/browser-security.test.ts'),
      path.join(os.tmpdir(), 'elsewhere/test/unit/browser-security.test.ts'),
    ]) {
      expect(check(passingReport(name)).status).toBe(1);
    }
  });

  it('rejects a missing, renamed, or relocated live test', () => {
    const report = passingReport();
    report.testResults[0].assertionResults[3].ancestorTitles = ['Another suite'];
    expect(check(report).status).toBe(1);
  });

  it('rejects a duplicated required test', () => {
    const report = passingReport();
    report.testResults[0].assertionResults.push({ ...report.testResults[0].assertionResults[3] });
    expect(check(report).status).toBe(1);
  });

  it('rejects a run that failed or did not succeed', () => {
    expect(check({ ...passingReport(), numFailedTests: 1 }).status).toBe(1);
    expect(check({ ...passingReport(), success: false }).status).toBe(1);
  });

  it('rejects an unreadable report and a missing argument', () => {
    expect(check('{not json').status).toBe(1);
    expect(spawnSync(process.execPath, [checker], { cwd: WEB_ROOT, encoding: 'utf8' }).status).toBe(
      2,
    );
  });

  it('says why a report could not be read', () => {
    const missing = spawnSync(process.execPath, [checker, path.join(reportDir, 'absent.json')], {
      cwd: WEB_ROOT,
      encoding: 'utf8',
    });
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain('ENOENT');
    expect(missing.stderr).toContain('absent.json');

    const malformed = check('{not json');
    expect(malformed.stderr).toMatch(/SyntaxError: .*JSON/);
  });
});

describe('Process tree sandbox validation', () => {
  const cleanProcessSnapshot = [
    ' 1000     1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --gitnexus-sec-id=test-session-123',
    ' 1001  1000 /Applications/Google Chrome.app/Contents/Frameworks/Helpers/Google Chrome Helper --type=zygote',
    ' 1002  1001 /Applications/Google Chrome.app/Contents/Frameworks/Helpers/Google Chrome Helper (Renderer) --type=renderer --seatbelt-client=83',
    ' 1003  1000 /Applications/Google Chrome.app/Contents/Frameworks/Helpers/Google Chrome Helper --type=utility --utility-sub-type=network.mojom.NetworkService',
    ' 2000     1 /usr/bin/unrelated --type=renderer --no-sandbox',
  ];

  it('walks the tree recursively and ignores unrelated processes', () => {
    const result = validateProcessTreeSandbox(cleanProcessSnapshot, 'test-session-123');
    expect(result.browserPid).toBe('1000');
    expect(result.childCount).toBe(3);
    expect(result.rendererCount).toBe(1);
    expect(result.rendererPids).toEqual(['1002']);
    expect(result.allPids).toEqual(['1000', '1001', '1003', '1002']);
  });

  it('fails when the root browser carries any disallowed flag', () => {
    for (const flag of LITERAL_DISALLOWED_PROCESS_FLAGS) {
      const mutant = [
        ` 1000     1 /path/chrome ${flag} --gitnexus-sec-id=test-session-123`,
        ' 1001  1000 /path/chrome-helper --type=renderer',
      ];
      expect(() => validateProcessTreeSandbox(mutant, 'test-session-123')).toThrow(
        /Insecure flag detected: process \(PID 1000\)/,
      );
    }
  });

  it('fails when a grandchild renderer carries --no-sandbox', () => {
    const mutant = [
      ' 1000     1 /path/chrome --gitnexus-sec-id=test-session-123',
      ' 1001  1000 /path/chrome --type=zygote',
      ' 1002  1001 /path/chrome-helper --type=renderer --no-sandbox',
    ];
    expect(() => validateProcessTreeSandbox(mutant, 'test-session-123')).toThrow(
      /Insecure flag detected: process \(PID 1002\) contains forbidden --no-sandbox/,
    );
  });

  it('fails when a process disables a single site isolation feature', () => {
    const mutant = [
      ' 1000     1 /path/chrome --gitnexus-sec-id=test-session-123 --disable-features=Translate,site-per-process',
      ' 1001  1000 /path/chrome-helper --type=renderer',
    ];
    expect(() => validateProcessTreeSandbox(mutant, 'test-session-123')).toThrow(
      /contains forbidden --disable-features=site-per-process/,
    );
  });

  it('fails closed when the process table is empty', () => {
    expect(() => validateProcessTreeSandbox([], 'test-session-123')).toThrow(
      /Process table read failure: process table snapshot is empty/,
    );
  });

  it('matches the identifier token exactly, not by prefix or suffix', () => {
    const snapshots = [
      [' 1000 1 /path/chrome --random-token=run-1', ' 1001 1000 /path/helper --type=renderer'],
      [' 1000 1 /path/chrome --gitnexus-sec-id=run-1x', ' 1001 1000 /path/helper --type=renderer'],
      [' 1000 1 /path/chrome x--gitnexus-sec-id=run-1', ' 1001 1000 /path/helper --type=renderer'],
    ];
    for (const snapshot of snapshots) {
      expect(() => validateProcessTreeSandbox(snapshot, 'run-1')).toThrow(
        /Target browser process not found for identifier "run-1"/,
      );
    }
  });

  it('fails closed when more than one process carries the identifier', () => {
    const spoofed = [
      ' 900 1 /tmp/decoy --gitnexus-sec-id=test-session-123',
      ' 901 900 /tmp/decoy-child --type=renderer',
      ' 1000 1 /path/chrome --no-sandbox --gitnexus-sec-id=test-session-123',
      ' 1001 1000 /path/helper --type=renderer --no-sandbox',
    ];
    expect(() => collectProcessTree(spoofed, 'test-session-123')).toThrow(
      /Ambiguous browser process: 2 processes carry identifier "test-session-123" \(PIDs 900, 1000\)/,
    );
  });

  it('fails closed when the browser has no child processes', () => {
    const vacuous = [' 1000 1 /path/chrome --gitnexus-sec-id=test-session-123'];
    expect(() => validateProcessTreeSandbox(vacuous, 'test-session-123')).toThrow(
      /Vacuous check: no child processes found for browser PID 1000/,
    );
  });
});

describe('macOS Seatbelt kernel sandbox check', () => {
  it('maps sandbox_check output to a sandbox state', () => {
    expect(checkProcessSeatbeltSandboxed(1234, () => '1\n')).toBe(true);
    expect(checkProcessSeatbeltSandboxed(1234, () => '0\n')).toBe(false);
  });

  it('runs only the absolute system python3 in isolated mode', () => {
    let capturedBin = '';
    let capturedArgs: string[] = [];
    checkProcessSeatbeltSandboxed(1234, (bin, args) => {
      capturedBin = bin;
      capturedArgs = args;
      return '1\n';
    });
    expect(SYSTEM_PYTHON3).toBe('/usr/bin/python3');
    expect(capturedBin).toBe('/usr/bin/python3');
    expect(capturedArgs.slice(0, 2)).toEqual(['-I', '-c']);
  });

  it('fails closed when the system python3 cannot run, with no PATH fallback', () => {
    const calls: string[] = [];
    expect(() =>
      checkProcessSeatbeltSandboxed(1234, (bin) => {
        calls.push(bin);
        throw new Error('ENOENT');
      }),
    ).toThrow(/sandbox_check failed for PID 1234/);
    expect(calls).toEqual(['/usr/bin/python3']);
  });

  it('fails closed on unexpected output', () => {
    expect(() => checkProcessSeatbeltSandboxed(1234, () => 'maybe\n')).toThrow(
      /Unexpected sandbox_check output/,
    );
  });

  it('rejects invalid PIDs', () => {
    expect(() => checkProcessSeatbeltSandboxed(-1)).toThrow(/Invalid PID/);
    expect(() => checkProcessSeatbeltSandboxed('abc')).toThrow(/Invalid PID/);
  });

  it.runIf(process.platform === 'darwin')('reports the test runner itself as unsandboxed', () => {
    expect(checkProcessSeatbeltSandboxed(process.pid)).toBe(false);
  });
});

describe('Linux kernel sandbox check', () => {
  function procReader(
    files: Record<string, string>,
    links: Record<string, string>,
  ): LinuxProcReader {
    return {
      readFile: (p) => {
        if (!(p in files)) throw new Error(`ENOENT ${p}`);
        return files[p];
      },
      readlink: (p) => {
        if (!(p in links)) throw new Error(`ENOENT ${p}`);
        return links[p];
      },
    };
  }

  const browserLinks = { '/proc/10/ns/user': 'user:[1]', '/proc/10/ns/pid': 'pid:[1]' };
  const unfilteredBrowser = { '/proc/10/status': 'Name:\tchrome\nSeccomp:\t0\n' };
  const ownNamespaces = {
    ...browserLinks,
    '/proc/20/ns/user': 'user:[2]',
    '/proc/20/ns/pid': 'pid:[2]',
  };

  it('reports a seccomp-filtered renderer in its own namespaces as sandboxed', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        {
          ...unfilteredBrowser,
          '/proc/20/status': 'Name:\tchrome\nSeccomp:\t2\nSeccomp_filters:\t3\n',
        },
        ownNamespaces,
      ),
    );
    expect(state).toEqual({
      seccompMode: 2,
      browserSeccompMode: 0,
      seccompFilters: 3,
      browserSeccompFilters: undefined,
      rendererAddedSeccompFilter: true,
      separateUserNamespace: true,
      separatePidNamespace: true,
      sandboxed: true,
    });
  });

  it('accepts the setuid sandbox shape: own PID namespace, shared user namespace', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        { ...unfilteredBrowser, '/proc/20/status': 'Seccomp:\t2\n' },
        { ...browserLinks, '/proc/20/ns/user': 'user:[1]', '/proc/20/ns/pid': 'pid:[2]' },
      ),
    );
    expect(state.separateUserNamespace).toBe(false);
    expect(state.separatePidNamespace).toBe(true);
    expect(state.sandboxed).toBe(true);
  });

  it('accepts the namespace sandbox shape: own user namespace, shared PID namespace', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        { ...unfilteredBrowser, '/proc/20/status': 'Seccomp:\t2\n' },
        { ...browserLinks, '/proc/20/ns/user': 'user:[2]', '/proc/20/ns/pid': 'pid:[1]' },
      ),
    );
    expect(state.sandboxed).toBe(true);
  });

  it('reports a renderer without a seccomp filter as unsandboxed', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader({ ...unfilteredBrowser, '/proc/20/status': 'Seccomp:\t0\n' }, ownNamespaces),
    );
    expect(state.sandboxed).toBe(false);
  });

  it('reports a renderer in seccomp strict mode as unsandboxed', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader({ ...unfilteredBrowser, '/proc/20/status': 'Seccomp:\t1\n' }, ownNamespaces),
    );
    expect(state.rendererAddedSeccompFilter).toBe(false);
    expect(state.sandboxed).toBe(false);
  });

  it('does not count a seccomp filter inherited from the browser', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        {
          '/proc/10/status': 'Seccomp:\t2\nSeccomp_filters:\t1\n',
          '/proc/20/status': 'Seccomp:\t2\nSeccomp_filters:\t1\n',
        },
        ownNamespaces,
      ),
    );
    expect(state.rendererAddedSeccompFilter).toBe(false);
    expect(state.sandboxed).toBe(false);
  });

  it('counts a filter the renderer adds on top of an inherited one', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        {
          '/proc/10/status': 'Seccomp:\t2\nSeccomp_filters:\t1\n',
          '/proc/20/status': 'Seccomp:\t2\nSeccomp_filters:\t2\n',
        },
        ownNamespaces,
      ),
    );
    expect(state.sandboxed).toBe(true);
  });

  it('fails closed when the browser is filtered and filter counts are unavailable', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        { '/proc/10/status': 'Seccomp:\t2\n', '/proc/20/status': 'Seccomp:\t2\n' },
        ownNamespaces,
      ),
    );
    expect(state.sandboxed).toBe(false);
  });

  it('reports a renderer sharing the browser namespaces as unsandboxed', () => {
    const state = readLinuxSandboxState(
      20,
      10,
      procReader(
        { ...unfilteredBrowser, '/proc/20/status': 'Seccomp:\t2\n' },
        { ...browserLinks, '/proc/20/ns/user': 'user:[1]', '/proc/20/ns/pid': 'pid:[1]' },
      ),
    );
    expect(state.sandboxed).toBe(false);
  });

  it('fails closed when /proc cannot be read or lacks a Seccomp line', () => {
    expect(() => readLinuxSandboxState(20, 10, procReader({}, browserLinks))).toThrow(/ENOENT/);
    expect(() =>
      readLinuxSandboxState(
        20,
        10,
        procReader({ ...unfilteredBrowser, '/proc/20/status': 'Name:\tchrome\n' }, {}),
      ),
    ).toThrow(/Cannot read Seccomp mode for PID 20/);
    expect(() =>
      readLinuxSandboxState(
        20,
        10,
        procReader(
          { '/proc/10/status': 'Name:\tchrome\n', '/proc/20/status': 'Seccomp:\t2\n' },
          {},
        ),
      ),
    ).toThrow(/Cannot read Seccomp mode for PID 10/);
  });
});

describe('Global setup post-launch verification', () => {
  function fakeResolution(): SecureBrowserResolution {
    return {
      executablePath: '/opt/chrome',
      version: '156.0.8078.80',
      source: 'env',
      args: ['--enable-webgl'],
      chromiumSandbox: true,
    };
  }

  function fakeLaunch(reportedVersion: string) {
    const state = { closed: false, options: undefined as unknown };
    const launch = async (options: unknown) => {
      state.options = options;
      return {
        version: () => reportedVersion,
        close: async () => {
          state.closed = true;
        },
      };
    };
    return { launch, state };
  }

  it('launches the resolved executable with the sandbox on and accepts a patched browser', async () => {
    const { launch, state } = fakeLaunch('156.0.8078.80');
    await createGlobalSetup({ resolve: fakeResolution, launch, platform: 'linux' })();
    expect(state.options).toEqual({
      executablePath: '/opt/chrome',
      args: ['--enable-webgl'],
      chromiumSandbox: true,
      headless: true,
    });
    expect(state.closed).toBe(true);
  });

  it('rejects a launched browser that reports a version below the floor', async () => {
    const { launch, state } = fakeLaunch('145.0.7632.6');
    await expect(
      createGlobalSetup({ resolve: fakeResolution, launch, platform: 'linux' })(),
    ).rejects.toThrow(/below minimum secure baseline/);
    expect(state.closed).toBe(true);
  });

  it('applies the Windows floor on Windows', async () => {
    const { launch } = fakeLaunch('156.0.8078.73');
    await expect(
      createGlobalSetup({ resolve: fakeResolution, launch, platform: 'win32' })(),
    ).rejects.toThrow(/below minimum secure baseline 156.0.8078.74/);
  });

  it('rejects a launched browser that differs from the required exact pin', async () => {
    const { launch } = fakeLaunch('156.0.8078.81');
    await expect(
      createGlobalSetup({
        resolve: fakeResolution,
        launch,
        platform: 'linux',
        expectedExactVersion: '156.0.8078.80',
      })(),
    ).rejects.toThrow(/does not match the required pinned version/);
  });
});

describe('Default global setup entry point', () => {
  let stubDir = '';
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitnexus-global-setup-'));
    for (const name of [...BROWSER_ENV_VARS, 'GITNEXUS_EXPECTED_CHROME_VERSION']) {
      savedEnv[name] = process.env[name];
      delete process.env[name];
    }
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(stubDir, { recursive: true, force: true });
    vi.doUnmock('@playwright/test');
    vi.resetModules();
  });

  async function importDefaultWithLaunchedVersion(reportedVersion: string) {
    const launched: unknown[] = [];
    vi.resetModules();
    vi.doMock('@playwright/test', () => ({
      chromium: {
        launch: async (options: unknown) => {
          launched.push(options);
          return { version: () => reportedVersion, close: async () => {} };
        },
      },
    }));
    const { default: setup } = await import('../../e2e/support/global-setup');
    return { setup, launched };
  }

  it('maps the CI exact pin and the platform into the setup dependencies', () => {
    const pinned = defaultGlobalSetupDeps(
      { GITNEXUS_EXPECTED_CHROME_VERSION: '156.0.8078.80' },
      'win32',
    );
    expect(pinned.platform).toBe('win32');
    expect(pinned.expectedExactVersion).toBe('156.0.8078.80');
    expect(
      defaultGlobalSetupDeps({ GITNEXUS_EXPECTED_CHROME_VERSION: '' }, 'linux')
        .expectedExactVersion,
    ).toBeUndefined();
  });

  it.skipIf(process.platform === 'win32')(
    'resolves the browser from the environment it was given',
    () => {
      const stub = writeStubBrowser(stubDir, 'Google Chrome 156.0.8078.80');
      const resolution = defaultGlobalSetupDeps({ CHROME_BIN: stub }, 'linux').resolve();
      expect(resolution.executablePath).toBe(stub);
      expect(resolution.source).toBe('env');
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a launched browser that differs from the pin in GITNEXUS_EXPECTED_CHROME_VERSION',
    async () => {
      process.env.CHROME_BIN = writeStubBrowser(stubDir, 'Google Chrome 156.0.8078.80');
      process.env.GITNEXUS_EXPECTED_CHROME_VERSION = '156.0.8078.80';
      const { setup, launched } = await importDefaultWithLaunchedVersion('156.0.8078.81');
      await expect(setup()).rejects.toThrow(
        /156.0.8078.81 does not match the required pinned version 156.0.8078.80/,
      );
      expect(launched).toEqual([
        expect.objectContaining({ executablePath: process.env.CHROME_BIN, chromiumSandbox: true }),
      ]);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'applies the floor of the platform it runs on',
    async () => {
      process.env.CHROME_BIN = writeStubBrowser(stubDir, 'Google Chrome 156.0.8078.80');
      const original = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
      try {
        const { setup } = await importDefaultWithLaunchedVersion('156.0.8078.73');
        await expect(setup()).rejects.toThrow(/below minimum secure baseline 156.0.8078.74/);
      } finally {
        if (original) Object.defineProperty(process, 'platform', original);
      }
    },
  );
});

describe('Playwright config entry point', () => {
  let stubDir = '';
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitnexus-browser-stub-'));
    for (const name of [...BROWSER_ENV_VARS, 'GITNEXUS_EXPECTED_CHROME_VERSION']) {
      savedEnv[name] = process.env[name];
      delete process.env[name];
    }
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(stubDir, { recursive: true, force: true });
    vi.resetModules();
  });

  it.skipIf(process.platform === 'win32')(
    'builds a sandboxed, CSP-enforcing config around the resolved executable',
    async () => {
      const stub = writeStubBrowser(stubDir, 'Google Chrome 156.0.8078.80');
      process.env.CHROME_BIN = stub;
      vi.resetModules();
      const { default: config } = await import('../../playwright.config');

      expect(config.globalSetup).toBe('./e2e/support/global-setup.ts');
      expect(config.use?.bypassCSP).toBe(false);
      expect(config.use?.launchOptions?.executablePath).toBe(stub);
      expect(config.use?.launchOptions?.chromiumSandbox).toBe(true);
      expect(config.use?.launchOptions?.args).toContain('--enable-webgl');
      expect(config.use?.launchOptions?.args).not.toContain('--no-sandbox');
    },
  );

  it.skipIf(process.platform === 'win32')(
    'loads through the real Playwright loader and refuses an unpatched executable',
    () => {
      const playwrightCli = path.join(WEB_ROOT, 'node_modules/.bin/playwright');
      const run = (versionLine: string) =>
        spawnSync(playwrightCli, ['test', '--list'], {
          cwd: WEB_ROOT,
          env: {
            ...envWithoutBrowserOverrides(),
            CHROME_BIN: writeStubBrowser(stubDir, versionLine),
          },
          encoding: 'utf8',
          timeout: 60_000,
        });

      const unpatched = run('Google Chrome 145.0.7632.6');
      expect(unpatched.status).not.toBe(0);
      expect(`${unpatched.stdout}${unpatched.stderr}`).toMatch(/below minimum secure baseline/);

      const patched = run('Google Chrome 156.0.8078.80');
      expect(`${patched.stdout}${patched.stderr}`).not.toMatch(/ReferenceError/);
      expect(patched.status).toBe(0);
    },
    90_000,
  );
});

describe('Live browser launch and boundaries', () => {
  const shouldRunLive =
    process.env.RUN_LIVE_BROWSER_TESTS === '1' || process.env.RUN_LIVE_BROWSER_TESTS === 'true';

  async function loadConfig() {
    const { default: config } = await import('../../playwright.config');
    const launchOptions = config.use?.launchOptions;
    if (!launchOptions?.executablePath) {
      throw new Error('Playwright config resolved no executable');
    }
    return { config, launchOptions };
  }

  function snapshotProcessTable(): string[] {
    return execSync('ps -ww -eo pid,ppid,command').toString().split('\n');
  }

  function assertRendererSandbox(browserPid: string, rendererPid: string, expected: boolean) {
    if (process.platform === 'darwin') {
      expect(checkProcessSeatbeltSandboxed(rendererPid)).toBe(expected);
    } else if (process.platform === 'linux') {
      expect(readLinuxSandboxState(rendererPid, browserPid).sandboxed).toBe(expected);
    } else {
      throw new Error(`No kernel sandbox check implemented for ${process.platform}`);
    }
  }

  it('arms the live tests whenever CI pins an exact browser build', () => {
    if (process.env.GITNEXUS_EXPECTED_CHROME_VERSION) {
      expect(shouldRunLive).toBe(true);
    }
  });

  it.runIf(shouldRunLive)(
    'runs renderers of the configured browser inside the kernel sandbox',
    async () => {
      const { chromium } = await import('@playwright/test');
      const { launchOptions } = await loadConfig();
      const runId = `gn-sec-live-${process.pid}-${Date.now()}`;

      const browser = await chromium.launch({
        ...launchOptions,
        args: [...(launchOptions.args ?? []), `--gitnexus-sec-id=${runId}`],
        headless: true,
      });

      try {
        await globalSetup();
        verifyLiveBrowserVersion(
          browser,
          process.platform,
          process.env.GITNEXUS_EXPECTED_CHROME_VERSION || undefined,
        );

        const contextA = await browser.newContext();
        const contextB = await browser.newContext();
        const pageA = await contextA.newPage();
        const pageB = await contextB.newPage();
        await pageA.goto('data:text/html,<h1>GitNexus context A</h1>');
        await pageB.goto('data:text/html,<h1>GitNexus context B</h1>');

        const validation = validateProcessTreeSandbox(snapshotProcessTable(), runId);
        expect(validation.rendererPids.length).toBeGreaterThan(0);
        for (const rendererPid of validation.rendererPids) {
          assertRendererSandbox(validation.browserPid, rendererPid, true);
        }

        // Smoke check of a browser invariant: no repository setting can change it.
        await contextA.addCookies([
          { name: 'session_token', value: 'secret_123', domain: 'localhost', path: '/' },
        ]);
        expect((await contextA.cookies()).some((c) => c.name === 'session_token')).toBe(true);
        expect((await contextB.cookies()).some((c) => c.name === 'session_token')).toBe(false);

        await contextA.close();
        await contextB.close();
      } finally {
        await browser.close();
      }
    },
    60_000,
  );

  it.runIf(shouldRunLive)(
    'detects unsandboxed renderers when the sandbox is turned off',
    async () => {
      const { chromium } = await import('@playwright/test');
      const { launchOptions } = await loadConfig();
      const runId = `gn-sec-neg-${process.pid}-${Date.now()}`;

      const browser = await chromium.launch({
        ...launchOptions,
        chromiumSandbox: false,
        args: [...(launchOptions.args ?? []), `--gitnexus-sec-id=${runId}`],
        headless: true,
      });

      try {
        const page = await (await browser.newContext()).newPage();
        await page.goto('data:text/html,<h1>GitNexus negative control</h1>');

        const table = snapshotProcessTable();
        expect(() => validateProcessTreeSandbox(table, runId)).toThrow(/--no-sandbox/);

        const tree = collectProcessTree(table, runId);
        const rendererPids = tree.descendantPids.filter((pid) =>
          (tree.commandLineByPid.get(pid) ?? '').split(/\s+/).includes('--type=renderer'),
        );
        expect(rendererPids.length).toBeGreaterThan(0);
        for (const rendererPid of rendererPids) {
          assertRendererSandbox(tree.browserPid, rendererPid, false);
        }
      } finally {
        await browser.close();
      }
    },
    60_000,
  );

  it.runIf(shouldRunLive)(
    'enforces CSP and CORS with the configured context',
    async () => {
      const { chromium } = await import('@playwright/test');
      const { config, launchOptions } = await loadConfig();

      const serverB = http.createServer((req, res) => {
        if (req.url === '/secret') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ secret: 'origin-b-secret-data' }));
        } else if (req.url === '/public') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          });
          res.end(JSON.stringify({ ok: true }));
        } else if (req.url === '/landing') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<h1>Landing on origin B</h1>');
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => serverB.listen(0, 'localhost', () => resolve()));
      const addrB = serverB.address();
      const portB = typeof addrB === 'object' && addrB ? addrB.port : 0;

      const inlineScript =
        '<script>window.__inlineScriptExecuted = true;</script><h1>Origin A</h1>';
      const serverA = http.createServer((req, res) => {
        if (req.url === '/redirect') {
          res.writeHead(302, { Location: `http://localhost:${portB}/landing` });
          res.end();
        } else if (req.url === '/csp') {
          res.writeHead(200, {
            'Content-Type': 'text/html',
            'Content-Security-Policy': "script-src 'self'",
          });
          res.end(inlineScript);
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(inlineScript);
        }
      });
      await new Promise<void>((resolve) => serverA.listen(0, '127.0.0.1', () => resolve()));
      const addrA = serverA.address();
      const portA = typeof addrA === 'object' && addrA ? addrA.port : 0;
      const originA = `http://127.0.0.1:${portA}`;

      const browser = await chromium.launch({ ...launchOptions, headless: true });

      try {
        const context = await browser.newContext({ bypassCSP: config.use?.bypassCSP });
        const page = await context.newPage();
        const inlineRan = () =>
          page.evaluate(
            () =>
              (window as unknown as { __inlineScriptExecuted?: boolean }).__inlineScriptExecuted ===
              true,
          );

        await page.goto(`${originA}/plain`);
        expect(await inlineRan()).toBe(true);
        await page.goto(`${originA}/csp`);
        expect(await inlineRan()).toBe(false);

        await page.goto(`${originA}/plain`);
        const fetchStatus = (url: string) =>
          page.evaluate(async (target) => {
            try {
              const response = await fetch(target);
              return `ok:${response.status}`;
            } catch {
              return 'blocked';
            }
          }, url);
        expect(await fetchStatus(`http://localhost:${portB}/public`)).toBe('ok:200');
        expect(await fetchStatus(`http://localhost:${portB}/secret`)).toBe('blocked');

        // Smoke check of a browser invariant: storage stays per-origin across a redirect.
        await page.evaluate(() => window.localStorage.setItem('origin_a_secret', 'token123'));
        await page.goto(`${originA}/redirect`);
        expect(page.url()).toBe(`http://localhost:${portB}/landing`);
        expect(
          await page.evaluate(() => window.localStorage.getItem('origin_a_secret')),
        ).toBeNull();

        await context.close();
      } finally {
        await browser.close();
        serverA.close();
        serverB.close();
      }
    },
    60_000,
  );
});
