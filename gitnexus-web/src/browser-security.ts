import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Chromium Security Baseline Configuration and Enforcement
 *
 * Google Security Advisory:
 * https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html
 *
 * Desktop Chromium releases prior to 156.0.8078.73 are vulnerable to four
 * Critical Chrome CNA security records:
 *   - CNA-118306 (Potential code execution outside sandbox)
 *   - CNA-118331
 *   - CNA-118348
 *   - CNA-118344
 *
 * Any browser used for testing must meet or exceed this minimum secure baseline.
 * Bundled controller fallbacks (e.g. Playwright default Chromium bundles mapping to
 * older unpatched revisions) must fail closed.
 */
export const MIN_CHROMIUM_SECURITY_VERSION = '156.0.8078.73';

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
 * Published Google Cloud Storage metadata and official etag/MD5 hashes for
 * Chrome for Testing 156.0.8078.80 artifacts.
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
  source: 'env' | 'cft' | 'system';
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
  baseline: string = MIN_CHROMIUM_SECURITY_VERSION,
): boolean {
  return compareChromiumVersions(version, baseline) >= 0;
}

/**
 * Extract Chromium version from `--version` command line output.
 * Matches standard output from Google Chrome, Chromium, Chrome for Testing, HeadlessChrome.
 */
export function parseChromiumVersion(output: string): string {
  const trimmed = output.trim();
  // Standard formats:
  // "Google Chrome 156.0.8078.80"
  // "Chromium 156.0.8078.73"
  // "Google Chrome for Testing 156.0.8078.80"
  // "Chrome/156.0.8078.80"
  const match = trimmed.match(
    /(?:Google Chrome(?: for Testing)?|Chromium|HeadlessChrome)[ /]([0-9]+(?:\.[0-9]+){2,3})/,
  );

  if (match && match[1]) {
    return match[1];
  }

  // Fallback: four dotted integers anywhere in the output
  const fallback = trimmed.match(/\b([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b/);
  if (fallback && fallback[1]) {
    return fallback[1];
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

function defaultExecCommand(bin: string, args: string[]): string {
  return execFileSync(bin, args, {
    encoding: 'utf8',
    timeout: 10_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * Sanitize launch arguments:
 * - Strips any dangerous security-bypassing flags (e.g. `--no-sandbox`, `--disable-web-security`).
 * - Preserves required base rendering args without duplicates.
 */
export function sanitizeLaunchArgs(customArgs: string[] = []): string[] {
  const sanitized = new Set<string>(REQUIRED_BASE_LAUNCH_ARGS);

  for (const arg of customArgs) {
    const isDisallowed = (DISALLOWED_SECURITY_FLAGS as readonly string[]).some(
      (flag) => arg === flag || arg.startsWith(`${flag}=`),
    );
    if (!isDisallowed) {
      sanitized.add(arg);
    }
  }

  return Array.from(sanitized);
}

/**
 * Get system candidate paths for Chromium/Chrome based on operating system.
 */
export function getSystemCandidatePaths(
  platform: NodeJS.Platform,
  env: Record<string, string | undefined> = process.env,
): string[] {
  const home = env.HOME ?? '';
  const localAppData = env.LOCALAPPDATA ?? '';
  const programFiles = env['ProgramFiles'] ?? 'C:\\Program Files';
  const programFilesX86 = env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';

  if (platform === 'darwin') {
    return [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta',
      path.join(home, 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome'),
    ];
  }

  if (platform === 'linux') {
    return [
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
      '/snap/bin/chromium',
    ];
  }

  if (platform === 'win32') {
    return [
      path.join(programFiles, 'Google\\Chrome\\Application\\chrome.exe'),
      path.join(programFilesX86, 'Google\\Chrome\\Application\\chrome.exe'),
      path.join(localAppData, 'Google\\Chrome\\Application\\chrome.exe'),
    ];
  }

  return [];
}

/**
 * Resolve secure browser launch options, enforcing:
 * 1. Explicit verified executable (environment variable, pinned CfT, or validated system Chrome).
 * 2. Actual probed version >= 156.0.8078.73 (fails closed on older or unverified binaries).
 * 3. Enforced sandboxing (chromiumSandbox: true; no --no-sandbox flag).
 * 4. Origin restrictions and profile isolation (no --disable-web-security or --disable-site-isolation-trials).
 */
export function resolveSecureBrowserLaunchOptions(
  options: ResolveOptions = {},
): SecureBrowserResolution {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const fsExists = options.fsExists ?? fs.existsSync;
  const execCommand = options.execCommand ?? defaultExecCommand;
  const sanitizedArgs = sanitizeLaunchArgs(options.customArgs);

  // 1. Explicit path from options
  if (options.customExecutablePath) {
    const candidate = path.resolve(options.customExecutablePath);
    if (!fsExists(candidate)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": executable file not found. Stale cache and unverified fallbacks are rejected.`,
      );
    }
    const version = probeBrowserVersion(candidate, execCommand);
    if (!isSecureChromiumVersion(version)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": version ${version} is below minimum secure baseline ${MIN_CHROMIUM_SECURITY_VERSION} ` +
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
    if (!isSecureChromiumVersion(version)) {
      throw new Error(
        `Refusing browser executable at "${candidate}": version ${version} is below minimum secure baseline ${MIN_CHROMIUM_SECURITY_VERSION} ` +
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

  // 3. Pinned local Chrome for Testing candidates (if downloaded to .browsers)
  const localCftCandidates: string[] = [
    path.resolve(
      process.cwd(),
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.linux64.executableSubpath,
    ),
    path.resolve(
      process.cwd(),
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-arm64'].executableSubpath,
    ),
    path.resolve(
      process.cwd(),
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-x64'].executableSubpath,
    ),
    path.resolve(
      process.cwd(),
      '.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.win64.executableSubpath,
    ),
    path.resolve(
      __dirname,
      '../.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.linux64.executableSubpath,
    ),
    path.resolve(
      __dirname,
      '../.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-arm64'].executableSubpath,
    ),
    path.resolve(
      __dirname,
      '../.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads['mac-x64'].executableSubpath,
    ),
    path.resolve(
      __dirname,
      '../.browsers',
      OFFICIAL_CFT_ARTIFACTS.downloads.win64.executableSubpath,
    ),
  ];

  for (const candidate of localCftCandidates) {
    if (fsExists(candidate)) {
      try {
        const version = probeBrowserVersion(candidate, execCommand);
        if (isSecureChromiumVersion(version)) {
          return {
            executablePath: candidate,
            version,
            source: 'cft',
            args: sanitizedArgs,
            chromiumSandbox: true,
          };
        }
      } catch {
        // Continue searching other candidates
      }
    }
  }

  // 4. System-installed candidates
  const systemCandidates = getSystemCandidatePaths(platform, env);
  for (const candidate of systemCandidates) {
    if (fsExists(candidate)) {
      try {
        const version = probeBrowserVersion(candidate, execCommand);
        if (isSecureChromiumVersion(version)) {
          return {
            executablePath: candidate,
            version,
            source: 'system',
            args: sanitizedArgs,
            chromiumSandbox: true,
          };
        }
      } catch {
        // Continue searching other candidates
      }
    }
  }

  // 5. Fail closed if no secure browser could be verified
  throw new Error(
    `No secure Chromium browser executable resolved (minimum baseline: ${MIN_CHROMIUM_SECURITY_VERSION}). ` +
      `Bundled Playwright chromium fallback is disallowed because bundled versions (<156.0.8078.73) ` +
      `are vulnerable to Critical Chrome CNA records: ${CRITICAL_CHROME_CNA_RECORDS.join(', ')}. ` +
      `Please provide an explicit patched executable via CHROME_BIN / PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ` +
      `or install Google Chrome >= ${MIN_CHROMIUM_SECURITY_VERSION}.`,
  );
}
