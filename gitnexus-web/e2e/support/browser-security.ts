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
 * The advisory lists fixes for four Critical Chrome CNA records (118306, 118331, 118348,
 * 118344) in desktop 156.0.8078.73 (Linux/macOS) and 156.0.8078.74 (Windows). Exact
 * introduction bounds per record are not established, so every earlier build is refused
 * rather than assumed safe. Playwright's bundled Chromium (145.x for 1.58.2) is below
 * this floor and must never be used as a fallback.
 *
 * Version policy: local runs accept any probed version at or above the platform floor;
 * CI pins the exact Chrome for Testing build (PINNED_CFT_VERSION) and additionally
 * requires the live browser to report exactly that version (GITNEXUS_EXPECTED_CHROME_VERSION).
 *
 * Playwright 1.58.2 itself launches Chromium with ThirdPartyStoragePartitioning and
 * HttpsUpgrades disabled (playwright-core chromiumSwitches.js). Those defaults predate this
 * baseline and are not changed by it; origin checks here cover CSP and CORS only.
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
 * Official Chrome for Testing (CfT) download URLs and archive layouts for the pinned build.
 * Archive integrity is checked in CI (.github/workflows/ci-e2e.yml) against recorded GCS
 * object metadata; that is storage metadata, not a publisher signature.
 */
const CFT_BUCKET = `https://storage.googleapis.com/chrome-for-testing-public/${PINNED_CFT_VERSION}`;

export const OFFICIAL_CFT_ARTIFACTS = {
  version: PINNED_CFT_VERSION,
  revision: PINNED_CFT_REVISION,
  downloads: {
    linux64: {
      url: `${CFT_BUCKET}/linux64/chrome-linux64.zip`,
      executableSubpath: 'chrome-linux64/chrome',
    },
    'mac-arm64': {
      url: `${CFT_BUCKET}/mac-arm64/chrome-mac-arm64.zip`,
      executableSubpath:
        'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    },
    'mac-x64': {
      url: `${CFT_BUCKET}/mac-x64/chrome-mac-x64.zip`,
      executableSubpath:
        'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    },
    win64: {
      url: `${CFT_BUCKET}/win64/chrome-win64.zip`,
      executableSubpath: 'chrome-win64\\chrome.exe',
    },
  },
} as const;

/**
 * Switches rejected in custom launch args: they disable or bypass sandboxing, site
 * isolation, web security, certificate checks, or local file isolation, or they replace
 * the sandboxed child executables. This is a best-effort deny list of known switches, not
 * an allow list; no production caller passes custom args today.
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
  '--remote-debugging-address',
  '--remote-debugging-port',
  '--renderer-cmd-prefix',
  '--browser-subprocess-path',
  '--disable-site-isolation-for-policy',
  '--no-sandbox-and-elevated',
] as const;

/**
 * Features that must never appear in a `--disable-features=` list, whether alone or combined
 * with others. `SitePerProcess` is the feature name; `site-per-process` is the switch name,
 * kept because it is a common mistaken spelling.
 */
export const DISALLOWED_DISABLED_FEATURES = [
  'SitePerProcess',
  'IsolateOrigins',
  'IsolateSandboxedIframes',
  'site-per-process',
] as const;

function normalizeFeatureEntry(entry: string): string {
  return entry
    .trim()
    .replace(/^["']+|["']+$/g, '')
    .replace(/^\*/, '')
    .split(/[<:]/)[0]
    .trim()
    .toLowerCase();
}

/**
 * Chromium accepts `--name` and `-name` (and `/name` on Windows), and switch names
 * case-insensitively on Windows, so matching is done on a normalized `--lowercase` name.
 * Feature-list entries are compared without a `*` prefix or a `<Trial` / `:params` suffix.
 */
export function findDisallowedFlag(
  arg: string,
  disallowed: readonly string[],
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  const trimmed = arg.trim().replace(/^["']+|["']+$/g, '');
  const isSwitch = trimmed.startsWith('-') || (platform === 'win32' && trimmed.startsWith('/'));
  if (!isSwitch) return undefined;
  const eq = trimmed.indexOf('=');
  const rawName = eq === -1 ? trimmed : trimmed.slice(0, eq);
  const name = `--${rawName.replace(/^[-/]+/, '').toLowerCase()}`;
  if (disallowed.some((flag) => flag.toLowerCase() === name)) return name;
  if (name === '--disable-features' && eq !== -1) {
    const features = trimmed
      .slice(eq + 1)
      .split(',')
      .map(normalizeFeatureEntry);
    for (const feature of DISALLOWED_DISABLED_FEATURES) {
      if (features.includes(feature.toLowerCase())) return `--disable-features=${feature}`;
    }
  }
  return undefined;
}

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
      if (!/^\d+$/.test(p)) {
        throw new Error(`Invalid version component "${p}" in version "${version}"`);
      }
      return Number(p);
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
    /^(?:Google Chrome(?: for Testing)?|Chromium|HeadlessChrome)[ /]([0-9]+(?:\.[0-9]+){2,3})(?=\s|$)/,
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
  baselineOrPlatform: string | NodeJS.Platform = process.platform,
  expectedExactVersion?: string,
): string {
  const ver = browser.version();
  if (expectedExactVersion && ver !== expectedExactVersion) {
    throw new Error(
      `Live launched browser version ${ver} does not match the required pinned version ${expectedExactVersion}.`,
    );
  }
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
    if (findDisallowedFlag(arg, DISALLOWED_SECURITY_FLAGS)) {
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

export interface ProcessTreeSnapshot {
  browserPid: string;
  descendantPids: string[];
  commandLineByPid: Map<string, string>;
}

/**
 * Locate the browser process tagged with the exact token `--gitnexus-sec-id=<id>` in a
 * `ps -eo pid,ppid,command` snapshot and collect every descendant (renderers on Linux sit
 * under the zygote, so the walk is recursive). Fails closed on an empty snapshot or when
 * the tagged process is absent.
 */
export function collectProcessTree(
  processTableLines: string[],
  identifier: string,
): ProcessTreeSnapshot {
  if (!processTableLines || processTableLines.length === 0) {
    throw new Error('Process table read failure: process table snapshot is empty');
  }

  const processes: Array<{ pid: string; ppid: string; line: string }> = [];
  for (const rawLine of processTableLines) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 3) {
      processes.push({ pid: parts[0], ppid: parts[1], line });
    }
  }

  const expectedToken = `--gitnexus-sec-id=${identifier}`;
  const tagged = processes.filter((p) => p.line.split(/\s+/).includes(expectedToken));
  if (tagged.length === 0) {
    throw new Error(`Target browser process not found for identifier "${identifier}"`);
  }
  if (tagged.length > 1) {
    throw new Error(
      `Ambiguous browser process: ${tagged.length} processes carry identifier "${identifier}" (PIDs ${tagged.map((p) => p.pid).join(', ')})`,
    );
  }
  const browserProc = tagged[0];

  const childrenMap = new Map<string, string[]>();
  for (const p of processes) {
    const existing = childrenMap.get(p.ppid) || [];
    existing.push(p.pid);
    childrenMap.set(p.ppid, existing);
  }

  const descendantPids = new Set<string>();
  const queue = [browserProc.pid];
  while (queue.length > 0) {
    const curr = queue.shift();
    if (!curr) continue;
    for (const kid of childrenMap.get(curr) || []) {
      if (!descendantPids.has(kid) && kid !== browserProc.pid) {
        descendantPids.add(kid);
        queue.push(kid);
      }
    }
  }

  return {
    browserPid: browserProc.pid,
    descendantPids: Array.from(descendantPids),
    commandLineByPid: new Map(processes.map((p) => [p.pid, p.line])),
  };
}

/**
 * Validate the tagged browser's process tree: it must have descendants, and no process in
 * the tree may carry a disallowed flag.
 */
export function validateProcessTreeSandbox(
  processTableLines: string[],
  identifier: string,
): ProcessTreeValidationResult {
  const tree = collectProcessTree(processTableLines, identifier);
  const { browserPid } = tree;

  if (tree.descendantPids.length === 0) {
    throw new Error(`Vacuous check: no child processes found for browser PID ${browserPid}`);
  }

  const allPids = [browserPid, ...tree.descendantPids];
  const rendererPids: string[] = [];

  for (const pid of allPids) {
    const line = tree.commandLineByPid.get(pid);
    if (!line) continue;
    const tokens = line.split(/\s+/);

    for (const token of tokens) {
      const disallowed = findDisallowedFlag(token, DISALLOWED_PROCESS_FLAGS);
      if (disallowed) {
        throw new Error(
          `Insecure flag detected: process (PID ${pid}) contains forbidden ${disallowed}`,
        );
      }
    }

    if (tokens.includes('--type=renderer')) {
      rendererPids.push(pid);
    }
  }

  return {
    browserPid,
    childCount: tree.descendantPids.length,
    rendererCount: rendererPids.length,
    rendererPids,
    allPids,
  };
}

/**
 * Absolute path, so a planted `python3` earlier on PATH is never chosen. On macOS this is
 * the xcrun shim, which still selects the developer toolchain from `DEVELOPER_DIR` or
 * `xcode-select`; `-I` does not change that. The PID is validated as an integer first.
 */
export const SYSTEM_PYTHON3 = '/usr/bin/python3';

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
  const run = execCommand ?? defaultExecCommand;
  let output: string;
  try {
    output = run(SYSTEM_PYTHON3, ['-I', '-c', script]).trim();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`sandbox_check failed for PID ${numericPid}: ${msg}`);
  }

  if (output === '1') return true;
  if (output === '0') return false;

  throw new Error(`Unexpected sandbox_check output for PID ${numericPid}: "${output}"`);
}

export interface LinuxProcReader {
  readFile(path: string): string;
  readlink(path: string): string;
}

const defaultLinuxProcReader: LinuxProcReader = {
  readFile: (p) => fs.readFileSync(p, 'utf8'),
  readlink: (p) => fs.readlinkSync(p),
};

export interface LinuxSandboxState {
  seccompMode: number;
  browserSeccompMode: number;
  seccompFilters?: number;
  browserSeccompFilters?: number;
  rendererAddedSeccompFilter: boolean;
  separateUserNamespace: boolean;
  separatePidNamespace: boolean;
  sandboxed: boolean;
}

function readStatusNumber(status: string, field: string): number | undefined {
  const line = status.split('\n').find((l) => l.startsWith(`${field}:`));
  if (line === undefined) return undefined;
  const value = line.slice(field.length + 1).trim();
  if (!/^\d+$/.test(value)) return undefined;
  return Number(value);
}

/**
 * Read the Linux kernel sandbox state of a renderer relative to its browser process.
 * Chromium's Linux sandbox applies its own seccomp-bpf filter to renderers and moves them
 * into their own PID namespace (setuid sandbox) or user+PID namespaces (namespace sandbox).
 * A `Seccomp: 2` inherited from the browser (as under a container's default profile) proves
 * nothing, so the renderer must be filtered where the browser is not, or carry more
 * filters than the browser. Fails closed when /proc cannot be read.
 */
export function readLinuxSandboxState(
  rendererPid: number | string,
  browserPid: number | string,
  reader: LinuxProcReader = defaultLinuxProcReader,
): LinuxSandboxState {
  const pid = Number(rendererPid);
  const parent = Number(browserPid);
  if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(parent) || parent <= 0) {
    throw new Error(`Invalid PID pair "${rendererPid}"/"${browserPid}" for Linux sandbox check`);
  }

  const readMode = (target: number) => {
    const status = reader.readFile(`/proc/${target}/status`);
    const mode = readStatusNumber(status, 'Seccomp');
    if (mode === undefined) {
      throw new Error(`Cannot read Seccomp mode for PID ${target} from /proc/${target}/status`);
    }
    return { mode, filters: readStatusNumber(status, 'Seccomp_filters') };
  };
  const renderer = readMode(pid);
  const browser = readMode(parent);

  const rendererAddedSeccompFilter =
    renderer.mode === 2 &&
    (browser.mode === 0 ||
      (renderer.filters !== undefined &&
        browser.filters !== undefined &&
        renderer.filters > browser.filters));

  const ns = (target: number, kind: 'user' | 'pid') =>
    reader.readlink(`/proc/${target}/ns/${kind}`);
  const separateUserNamespace = ns(pid, 'user') !== ns(parent, 'user');
  const separatePidNamespace = ns(pid, 'pid') !== ns(parent, 'pid');

  return {
    seccompMode: renderer.mode,
    browserSeccompMode: browser.mode,
    seccompFilters: renderer.filters,
    browserSeccompFilters: browser.filters,
    rendererAddedSeccompFilter,
    separateUserNamespace,
    separatePidNamespace,
    sandboxed: rendererAddedSeccompFilter && (separateUserNamespace || separatePidNamespace),
  };
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
 * 3. chromiumSandbox: true on every branch, so Playwright never adds --no-sandbox.
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
          `(the advisory lists fixes for Critical Chrome CNA records ${CRITICAL_CHROME_CNA_RECORDS.join(', ')} at this floor). ` +
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
          `(the advisory lists fixes for Critical Chrome CNA records ${CRITICAL_CHROME_CNA_RECORDS.join(', ')} at this floor). ` +
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

  // 3. Local Chrome for Testing candidates (anchored to the repository, not CWD). `cft` means
  // the binary reports exactly PINNED_CFT_VERSION; nothing here verifies archive integrity.
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
        if (compareChromiumVersions(version, PINNED_CFT_VERSION) === 0) {
          return {
            executablePath: candidate,
            version,
            source: 'cft',
            args: sanitizedArgs,
            chromiumSandbox: true,
          };
        } else {
          rejectionReasons.push(
            `[cft ${candidate}]: version ${version} does not match pinned CfT ${PINNED_CFT_VERSION}`,
          );
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
      `Bundled Playwright chromium fallback is disallowed because bundled versions are below ${baseline}, ` +
      `where the advisory lists fixes for Critical Chrome CNA records ${CRITICAL_CHROME_CNA_RECORDS.join(', ')}. ` +
      `Please provide an explicit patched executable via CHROME_BIN / PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ` +
      `or install Google Chrome >= ${baseline}.${diagnosticSummary}`,
  );
}
