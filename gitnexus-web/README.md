# gitnexus-web

React/Vite thin client for the GitNexus CLI. All queries go through the
`gitnexus serve` HTTP API.

## Development

```bash
npm run dev          # Vite dev server on port 5173
npm test             # vitest unit tests
npx tsc -b --noEmit  # type check
```

## End-to-end tests

Requires Node 22, as CI uses. Playwright starts no servers. From the repo root, run each step in its own
terminal, the way CI does in `.github/workflows/ci-e2e.yml`. Set the same
`GITNEXUS_HOME` in the step 1 and 2 terminals so your own index isn't touched:

```bash
# 1. Install, build the backend, and index the fixture repo
export GITNEXUS_HOME=/tmp/gitnexus-e2e-home
(cd gitnexus-shared && npm ci)
(cd gitnexus && npm ci && npm run build)
(cd gitnexus-web && npm ci)
repo=/tmp/gitnexus-e2e-repo
rm -rf "$repo" && mkdir -p "$repo"
cp -R gitnexus/test/fixtures/mini-repo/src "$repo/src"
echo '{"name":"e2e-mini-repo","version":"0.0.0","private":true}' > "$repo/package.json"
node gitnexus/dist/cli/index.js analyze "$repo" --skip-git --skip-agents-md --name e2e-mini-repo

# 2. Backend on :4747
export GITNEXUS_HOME=/tmp/gitnexus-e2e-home
node gitnexus/dist/cli/index.js serve

# 3. Frontend on :5173
cd gitnexus-web && npm run dev

# 4. Tests
cd gitnexus-web && E2E=1 npm run test:e2e
```

Without `E2E=1`, specs that need the backend skip when it's unreachable;
`onboarding.spec.ts` still needs the Vite server.

### Browser

`playwright.config.ts` resolves the browser when it loads, so every Playwright
command, including `--list`, fails closed until one resolves. Playwright's
bundled Chromium is never used. The resolver takes the first match:

1. **An env var:** the first non-empty one of `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`,
   `CHROME_BIN`, `CHROME_PATH`, `CHROMIUM_PATH`. It must be Google Chrome,
   Chrome for Testing, or Chromium (Edge and Brave are rejected), at or above
   the security floor: `156.0.8078.73`, or `156.0.8078.74` on Windows. A set
   path that is missing or too old fails; it doesn't fall through.
2. **The pinned Chrome for Testing build** (`PINNED_CFT_VERSION` in
   `e2e/support/browser-security.ts`), unzipped into `.browsers/` at the repo
   root or in `gitnexus-web/`. It must report exactly the pinned version.
3. **An installed Google Chrome** (or Chromium on Linux) in its standard
   location, at or above the floor.

If your installed Chrome is current, you need no setup. Otherwise, from
`gitnexus-web/`:

```bash
platform=mac-arm64   # linux64 | mac-x64 | win64
version=$(sed -n "s/^export const PINNED_CFT_VERSION = '\([^']*\)';/\1/p" e2e/support/browser-security.ts)
curl -fsSL -o /tmp/chrome.zip \
  "https://storage.googleapis.com/chrome-for-testing-public/$version/$platform/chrome-$platform.zip"
unzip -q /tmp/chrome.zip -d .browsers/
```

No checksum is checked locally; CI verifies the linux64 SHA256 in
`.github/workflows/ci-e2e.yml`.

To enforce the exact pin as CI does, set
`GITNEXUS_EXPECTED_CHROME_VERSION=$version` on the `test:e2e` command line, and
global setup rejects any other version. Don't export it: `npm test` then
expects `RUN_LIVE_BROWSER_TESTS=1`.

### Live sandbox, CSP, and CORS checks

`npm test` skips these, and a skip exits 0, so it isn't a pass. To run them on
Linux or macOS, from `gitnexus-web/`:

```bash
RUN_LIVE_BROWSER_TESTS=1 npx vitest run test/unit/browser-security.test.ts
```
