import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

/**
 * Chromium Security Baseline Configuration and Enforcement
 *
 * Google Security Advisory:
 * https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html
 *
 * Desktop Chromium releases prior to 156.0.8078.73 (Linux/macOS) and 156.0.8078.74 (Windows)
 * are vulnerable to four Critical Chrome CNA security records:
 *   - CNA-118306 (Potential code execution outside sandbox)
 *   - CNA-118331
 *   - CNA-118348
 *   - CNA-118344
 *
 * Any browser used for testing must meet or exceed this minimum secure baseline.
 * Bundled controller fallbacks (e.g. Playwright default Chromium bundles mapping to
 * older unpatched revisions) must fail closed.
 */
export const MIN_CHROMIUM_SECURITY_VERSION_POSIX = '156.0.8078.73';
export const MIN_CHROMIUM_SECURITY_VERSION_WIN32 = '156.0.8078.74';
export const MIN_CHROMIUM_SECURITY_VERSION = MIN_CHROMIUM_SECURITY_VERSION_POSIX;

export function getMinimumSecurityBaseline(platform: NodeJS.Platform = process.platform): string {
  return platform === 'win32'
    ? MIN_CHROMIUM_SECURITY_VERSION_WIN32
    : MIN_CHROMIUM_SECURITY_VERSION_POSIX;
}

/**
 * Official Google Chrome for Testing (CfT) Stable channel pinned release:
 * Source: https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json
 */
export const PINNED_CFT_VERSION = '156.0.8078.80';
export const PINNED_CFT_REVISION = '1706539';

export const CRITICAL_CHROME_CNA_RECORDS = ['118306', '118331', '118348', '118344'] as const;

export const GOOGLE_SECURITY_ADVISORY_URL =
  'https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html';

/**
 * Official Chrome for Testing (CfT) download URLs and GCS object metadata.
 * Note: gcsEtagMd5 is Google Cloud Storage object metadata, not a publisher signature.
 */
export const OFFICIAL_CFT_ARTIFACTS = {
  version: PINNED_CFT_VERSION,
  revision: PINNED_CFT_REVISION,
  downloads: {
    linux64: {
      url: 'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.80/linux64/chrome-linux64.zip',
      gcsEtagMd5: '6a158ba7e01da016f1988bae0643d9e5',
      executableSubpath: 'chrome-linux64/chrome',
    },
    'mac-arm64': {
      url: 'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.80/mac-arm64/chrome-mac-arm64.zip',
      gcsEtagMd5: '3b89133432e118660a79f59d3141cc09',
      executableSubpath:
        'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    },
    'mac-x64': {
      url: 'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.80/mac-x64/chrome-mac-x64.zip',
      gcsEtagMd5: '9e69bf864a6c37c0073d016a05987f31',
      executableSubpath:
        'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    },
    win64: {
      url: 'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.80/win64/chrome-win64.zip',
      gcsEtagMd5: 'd795d32dfa4506e67f6eda8b8b9c54d8',
      executableSubpath: 'chrome-win64\\chrome.exe',
    },
  },
} as const;

/**
 * Dangerous security flags that disable origin isolation, sandboxing, or CSP.
 * These are strictly disallowed in all test execution environments.
 */
export const DISALLOWED_SECURITY_FLAGS = [
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
] as const;

/**
 * Insecure flags that disable sandboxing or isolation in running process trees.
 * Note: --user-data-dir is forbidden in user customArgs to prevent pointing to
 * shared/unisolated profiles, but is legitimately passed by Playwright to point
 * to its own isolated ephemeral temp profile.
 */
export const DISALLOWED_PROCESS_FLAGS = [
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
] as const;

/**
 * Base launch args required for headless WebGL rendering (Sigma.js graph view).
 */
export const REQUIRED_BASE_LAUNCH_ARGS = [
  '--use-gl=angle',
  '--use-angle=swiftshader',
  '--enable-webgl',
  '--enable-unsafe-swiftshader',
] as const;

export interface SecureBrowserResolution {
  executablePath: string;
  version: string;
  source: 'option' | 'env' | 'cft' | 'system';
  args: string[];
  chromiumSandbox: boolean;
}

export interface ResolveOptions {
  customExecutablePath?: string;
  customArgs?: string[];
  env?: Record<string, string | undefined>;
  platform?: NodeJS.Platform;
  fsExists?: (path: string) => boolean;
  execCommand?: (bin: string, args: string[]) => string;
}

/**
 * Parse a four-part Chromium semver string (e.g. "156.0.8078.80") into numeric components.
 */
export function parseVersionParts(version: string): [number, number, number, number] {
  const parts = version
    .trim()
    .split('.')
    .map((p) => {
      const n = Number(p);
      if (!Number.isInteger(n) || n < 0) {
        throw new Error(`Invalid version component "${p}" in version "${version}"`);
      }
      return n;
    });

  if (parts.length < 3 || parts.length > 4) {
    throw new Error(
      `Chromium version must have 3 or 4 components, got ${parts.length} in "${version}"`,
    );
  }

  return [parts[0], parts[1], parts[2], parts[3] ?? 0];
}

/**
 * Compare two Chromium version strings.
 * Returns -1 if v1 < v2, 0 if v1 === v2, 1 if v1 > v2.
 */
export function compareChromiumVersions(v1: string, v2: string): number {
  const p1 = parseVersionParts(v1);
  const p2 = parseVersionParts(v2);

  for (let i = 0; i < 4; i++) {
    if (p1[i] < p2[i]) return -1;
    if (p1[i] > p2[i]) return 1;
  }
  return 0;
}

/**
 * Verify whether a Chromium version meets or exceeds the security baseline.
 */
export function isSecureChromiumVersion(
  version: string,
  baselineOrPlatform: string | NodeJS.Platform = MIN_CHROMIUM_SECURITY_VERSION,
): boolean {
  const baseline =
    baselineOrPlatform === 'win32' ||
    baselineOrPlatform === 'linux' ||
    baselineOrPlatform === 'darwin'
      ? getMinimumSecurityBaseline(baselineOrPlatform)
      : baselineOrPlatform;
  return compareChromiumVersions(version, baseline) >= 0;
}

/**
 * Extract Chromium version from `--version` command line output.
 * Matches standard output from Google Chrome, Chromium, Chrome for Testing, HeadlessChrome.
 * Fails closed if the output does not explicitly identify a recognized Chromium binary.
 */
export function parseChromiumVersion(output: string): string {
  const trimmed = output.trim();
  const match = trimmed.match(
    /(?:Google Chrome(?: for Testing)?|Chromium|HeadlessChrome)[ /]([0-9]+(?:\.[0-9]+){2,3})/,
  );

  if (match && match[1]) {
    return match[1];
  }

  throw new Error(
    `Refusing browser executable: cannot parse Chromium version from output: "${trimmed}". Only verified Chromium distributions are permitted.`,
  );
}

/**
 * Probe a browser binary by executing `--version` and parsing the output.
 */
export function probeBrowserVersion(
  executablePath: string,
  execCommand: (bin: string, args: string[]) => string = defaultExecCommand,
): string {
  let output: string;
  try {
    output = execCommand(executablePath, ['--version']);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Refusing browser executable at "${executablePath}": execution failed (${msg}). Stale or unexecutable binaries are rejected.`,
    );
  }

  return parseChromiumVersion(output);
}

/**
 * Verify live launched browser version from Playwright Browser object.
 */
export function verifyLiveBrowserVersion(
  browser: { version(): string },
  baselineOrPlatform?: string | NodeJS.Platform,
): string {
  const ver = browser.version();
  if (!isSecureChromiumVersion(ver, baselineOrPlatform)) {
    const targetBaseline =
      typeof baselineOrPlatform === 'string' &&
      !['win32', 'linux', 'darwin'].includes(baselineOrPlatform)
        ? baselineOrPlatform
        : getMinimumSecurityBaseline(
            typeof baselineOrPlatform === 'string'
              ? (baselineOrPlatform as NodeJS.Platform)
              : undefined,
          );
    throw new Error(
      `Live launched browser version ${ver} is below minimum secure baseline ${targetBaseline}.`,
    );
  }
  return ver;
}

function defaultExecCommand(bin: string, args: string[]): string {
  return execFileSync(bin, args, {
    encoding: 'utf8',
    timeout: 10_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * Sanitize launch arguments:
 * - Rejects any dangerous security-bypassing flags (throws).
 * - Preserves required base rendering args without duplicates.
 */
export function sanitizeLaunchArgs(customArgs: string[] = []): string[] {
  for (const arg of customArgs) {
    const isDisallowed = (DISALLOWED_SECURITY_FLAGS as readonly string[]).some(
      (flag) => arg === flag || arg.startsWith(`${flag}=`) || arg.startsWith(`${flag} `),
    );
    if (isDisallowed) {
      throw new Error(
        `Insecure launch argument rejected: "${arg}" violates Chromium security baseline. Insecure overrides are forbidden.`,
      );
    }
  }

  const sanitized = new Set<string>(REQUIRED_BASE_LAUNCH_ARGS);
  for (const arg of customArgs) {
    sanitized.add(arg);
  }

  return Array.from(sanitized);
}

export interface ProcessTreeValidationResult {
  browserPid: string;
  childCount: number;
  rendererCount: number;
  rendererPids: string[];
  allPids: string[];
}

/**
 * Validates a live process table snapshot to verify:
 * 1. The target browser process exists (matched via exact token `--gitnexus-sec-id=<id>`).
 * 2. Child/renderer processes exist via recursive tree walk (non-vacuous check).
 * 3. None of the processes in the tree contain forbidden security flags.
 * 4. Fails closed if the process list is empty (read failure) or child count is 0.
 */
export function validateProcessTreeSandbox(
  processTableLines: string[],
  identifier: string,
): ProcessTreeValidationResult {
  if (!processTableLines || processTableLines.length === 0) {
    throw new Error('Process table read failure: process table snapshot is empty');
  }

  // Parse lines into process table records
  const processes: Array<{ pid: string; ppid: string; line: string }> = [];
  for (const rawLine of processTableLines) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 3) {
      processes.push({
        pid: parts[0],
        ppid: parts[1],
        line,
      });
    }
  }

  // Match root browser process via exact token --gitnexus-sec-id=<identifier>
  const expectedToken = `--gitnexus-sec-id=${identifier}`;
  const browserProc = processes.find((p) => {
    const idx = p.line.indexOf(expectedToken);
    if (idx === -1) return false;
    const after = p.line.slice(idx + expectedToken.length);
    return after.length === 0 || /^\s/.test(after);
  });

  if (!browserProc) {
    throw new Error(`Target browser process not found for identifier "${identifier}"`);
  }

  const browserPid = browserProc.pid;

  // Build parent -> children map for recursive tree traversal
  const childrenMap = new Map<string, string[]>();
  for (const p of processes) {
    const existing = childrenMap.get(p.ppid) || [];
    existing.push(p.pid);
    childrenMap.set(p.ppid, existing);
  }

  // Recursive walk to find all descendants (handling Linux zygote -> renderer hierarchy)
  const descendantPids = new Set<string>();
  const queue = [browserPid];
  while (queue.length > 0) {
    const curr = queue.shift();
    if (!curr) continue;
    const kids = childrenMap.get(curr) || [];
    for (const kid of kids) {
      if (!descendantPids.has(kid)) {
        descendantPids.add(kid);
        queue.push(kid);
      }
    }
  }

  if (descendantPids.size === 0) {
    throw new Error(`Vacuous check: no child processes found for browser PID ${browserPid}`);
  }

  const allPids = [browserPid, ...Array.from(descendantPids)];
  const procByPid = new Map(processes.map((p) => [p.pid, p]));

  let rendererCount = 0;
  const rendererPids: string[] = [];

  // Check every process in the tree against all disallowed security flags
  for (const pid of allPids) {
    const proc = procByPid.get(pid);
    if (!proc) continue;

    for (const disallowed of DISALLOWED_PROCESS_FLAGS) {
      if (
        proc.line.includes(disallowed) ||
        proc.line.includes(`${disallowed}=`) ||
        proc.line.includes(`${disallowed} `)
      ) {
        throw new Error(
          `Insecure flag detected: process (PID ${pid}) contains forbidden ${disallowed}`,
        );
      }
    }

    if (proc.line.includes('--type=renderer')) {
      rendererCount++;
      rendererPids.push(pid);
    }
  }

  return {
    browserPid,
    childCount: descendantPids.size,
    rendererCount,
    rendererPids,
    allPids,
  };
}

/**
 * Query macOS kernel Seatbelt sandbox state for a specific process ID using
 * system `sandbox_check(pid, NULL, SANDBOX_FILTER_NONE)`.
 *
 * Implemented using Python 3 `-I` (isolated mode) stdlib ctypes loading macOS libSystem.
 */
export function checkProcessSeatbeltSandboxed(
  pid: number | string,
  execCommand?: (bin: string, args: string[]) => string,
): boolean {
  const numericPid = Number(pid);
  if (!Number.isInteger(numericPid) || numericPid <= 0) {
    throw new Error(`Invalid PID "${pid}" for sandbox_check`);
  }

  const script = `import ctypes; lib = ctypes.CDLL(None); print(lib.sandbox_check(${numericPid}, None, 0))`;
  let output: string;
  try {
    if (execCommand) {
      output = execCommand('/usr/bin/python3', ['-I', '-c', script]).trim();
    } else {
      try {
        output = execFileSync('/usr/bin/python3', ['-I', '-c', script], {
          encoding: 'utf8',
          timeout: 5000,
          stdio: ['ignore', 'pipe', 'pipe'],
        }).trim();
      } catch {
        output = execFileSync('python3', ['-I', '-c', script], {
          encoding: 'utf8',
          timeout: 5000,
          stdio: ['ignore', 'pipe', 'pipe'],
        }).trim();
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`sandbox_check failed for PID ${numericPid}: ${msg}`);
  }

  if (output === '1') return true;
  if (output === '0') return false;

  throw new Error(`Unexpected sandbox_check output for PID ${numericPid}: "${output}"`);
}

/**
 * Get system candidate paths for Chromium/Chrome based on operating system.
 * Avoids path planting by ensuring base directory variables are non-empty.
 */
export function getSystemCandidatePaths(
  platform: NodeJS.Platform,
  env: Record<string, string | undefined> = process.env,
): string[] {
  const home = (env.HOME ?? '').trim();
  const localAppData = (env.LOCALAPPDATA ?? '').trim();
  const programFiles = (env['ProgramFiles'] ?? 'C:\\Program Files').trim();
  const programFilesX86 = (env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)').trim();

  const candidates: string[] = [];

  if (platform === 'darwin') {
    candidates.push(
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta',
    );
    if (home) {
      candidates.push(
        path.join(home, 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome'),
      );
    }
  } else if (platform === 'linux') {
    candidates.push(
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
      '/snap/bin/chromium',
    );
  } else if (platform === 'win32') {
    if (programFiles) {
      candidates.push(path.join(programFiles, 'Google\\Chrome\\Application\\chrome.exe'));
    }
    if (programFilesX86) {
      candidates.push(path.join(programFilesX86, 'Google\\Chrome\\Application\\chrome.exe'));
    }
    if (localAppData) {
      candidates.push(path.join(localAppData, 'Google\\Chrome\\Application\\chrome.exe'));
    }
  }

  return candidates;
}

/**
 * Resolve secure browser launch options, enforcing:
 * 1. Explicit verified executable (option, environment variable, pinned CfT, or validated system Chrome).
 * 2. Actual probed version >= security baseline (156.0.8078.73 on POSIX, 156.0.8078.74 on Win32).
 * 3. Enforced sandboxing (chromiumSandbox: true; no --no-sandbox flag).
 * 4. Origin restrictions and profile isolation.
 */
export function resolveSecureBrowserLaunchOptions(
  options: ResolveOptions = {},
): SecureBrowserResolution {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const fsExists = options.fsExists ?? fs.existsSync;
  const execCommand = options.execCommand ?? defaultExecCommand;
  const sanitizedArgs = sanitizeLaunchArgs(options.customArgs);
  const baseline = getMinimumSecurityBaseline(platform);

  const rejectionReasons: string[] = [];

  // 1. Explicit path from options
  if (options.customExecutablePath) {
    const candidate = path.resolve(options.customExecutablePath);
    if (!fsExists(candidate)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": executable file not found. Stale cache and unverified fallbacks are rejected.`,
      );
    }
    const version = probeBrowserVersion(candidate, execCommand);
    if (!isSecureChromiumVersion(version, baseline)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": version ${version} is below minimum secure baseline ${baseline} ` +
          `(vulnerable to Critical Chrome CNA records: ${CRITICAL_CHROME_CNA_RECORDS.join(', ')}). ` +
          `See ${GOOGLE_SECURITY_ADVISORY_URL}. Stale cache or bundled fallback must fail closed.`,
      );
    }
    return {
      executablePath: candidate,
      version,
      source: 'option',
      args: sanitizedArgs,
      chromiumSandbox: true,
    };
  }

  // 2. Explicit environment variable candidate
  const envCandidate =
    env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ||
    env.CHROME_BIN ||
    env.CHROME_PATH ||
    env.CHROMIUM_PATH;

  if (envCandidate) {
    const candidate = path.resolve(envCandidate);
    if (!fsExists(candidate)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": executable file not found. Stale cache and unverified fallbacks are rejected.`,
      );
    }
    const version = probeBrowserVersion(candidate, execCommand);
    if (!isSecureChromiumVersion(version, baseline)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": version ${version} is below minimum secure baseline ${baseline} ` +
          `(vulnerable to Critical Chrome CNA records: ${CRITICAL_CHROME_CNA_RECORDS.join(', ')}). ` +
          `See ${GOOGLE_SECURITY_ADVISORY_URL}. Stale cache or bundled fallback must fail closed.`,
      );
    }
    return {
      executablePath: candidate,
      version,
      source: 'env',
      args: sanitizedArgs,
      chromiumSandbox: true,
    };
  }

  // 3. Pinned local Chrome for Testing candidates (anchored to repository directory, not CWD)
  const localCftCandidates: string[] = [
    path.resolve(
      MODULE_DIR,
      '../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.linux64.executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-arm64'].executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-x64'].executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.win64.executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.linux64.executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-arm64'].executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-x64'].executableSubpath,
    ),
    path.resolve(
      MODULE_DIR,
      '../../..',
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.win64.executableSubpath,
    ),
  ];

  for (const candidate of localCftCandidates) {
    if (fsExists(candidate)) {
      try {
        const version = probeBrowserVersion(candidate, execCommand);
        if (isSecureChromiumVersion(version, baseline)) {
          return {
            executablePath: candidate,
            version,
            source: 'cft',
            args: sanitizedArgs,
            chromiumSandbox: true,
          };
        } else {
          rejectionReasons.push(`[cft ${candidate}]: version ${version} < ${baseline}`);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        rejectionReasons.push(`[cft ${candidate}]: ${msg}`);
      }
    }
  }

  // 4. System-installed candidates
  const systemCandidates = getSystemCandidatePaths(platform, env);
  for (const candidate of systemCandidates) {
    if (fsExists(candidate)) {
      try {
        const version = probeBrowserVersion(candidate, execCommand);
        if (isSecureChromiumVersion(version, baseline)) {
          return {
            executablePath: candidate,
            version,
            source: 'system',
            args: sanitizedArgs,
            chromiumSandbox: true,
          };
        } else {
          rejectionReasons.push(`[system ${candidate}]: version ${version} < ${baseline}`);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        rejectionReasons.push(`[system ${candidate}]: ${msg}`);
      }
    } else {
      rejectionReasons.push(`[system ${candidate}]: file not found`);
    }
  }

  // 5. Fail closed if no secure browser could be verified
  const diagnosticSummary =
    rejectionReasons.length > 0
      ? `\nDiagnostic scan results:\n  - ${rejectionReasons.join('\n  - ')}`
      : '';

  throw new Error(
    `No secure Chromium browser executable resolved (minimum baseline: ${baseline}). ` +
      `Bundled Playwright chromium fallback is disallowed because bundled versions (<${baseline}) ` +
      `are vulnerable to Critical Chrome CNA records: ${CRITICAL_CHROME_CNA_RECORDS.join(', ')}. ` +
      `Please provide an explicit patched executable via CHROME_BIN / PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ` +
      `or install Google Chrome >= ${baseline}.${diagnosticSummary}`,
  );
}
