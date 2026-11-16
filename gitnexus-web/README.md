# gitnexus-web

React/Vite thin client for the GitNexus CLI. All queries go through the
`gitnexus serve` HTTP API.

## Development

```bash
npm run dev        # Vite dev server on port 5173
npm test           # vitest unit tests
npx tsc -b --noEmit
```

## End-to-end tests

```bash
npm run test:e2e
```

### Browser setup (required)

The e2e suite runs against a pinned Chrome for Testing build
(`156.0.8078.80`, pinned in `e2e/support/browser-security.ts`). The resolver
fails closed on a fresh machine unless you do one of:

1. **Point `CHROME_BIN` at any installed Chromium-based browser** whose version
   matches the pinned build, or
2. **Unzip the pinned build into `.browsers/`** (repo root or
   `gitnexus-web/.browsers/`), so the binary lands at one of the eight
   candidate paths:

   ```
   .browsers/chrome-linux64/chrome
   .browsers/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing
   .browsers/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing
   .browsers/chrome-win64/chrome.exe
   ```

   (each also valid under `gitnexus-web/` instead of the repo root).

Example download:

```bash
version=156.0.8078.80
curl -L -o /tmp/chrome.zip \
  "https://storage.googleapis.com/chrome-for-testing-public/$version/mac-arm64/chrome-mac-arm64.zip"
unzip /tmp/chrome.zip -d .browsers/
```
