// Exit status alone can't show the live tests ran: they skip without a pinned browser, and a
// vitest config change can exclude or filter tests while the run still exits 0. The workflow pin
// tests are required here too, so the e2e job runs them whatever tests the config selects. This
// can't see a config or setup file that makes a selected test pass falsely; review gates that.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const TEST_FILE = 'test/unit/browser-security.test.ts';
const REQUIRED_PASSED = [
  [
    'CI pin parity with the resolver',
    'pins the full reviewed text of the E2E workflow and its setup action',
  ],
  [
    'CI pin parity with the resolver',
    'keeps the CI entry point calling the E2E workflow unconditionally',
  ],
  [
    'Live browser launch and boundaries',
    'arms the live tests whenever CI pins an exact browser build',
  ],
  [
    'Live browser launch and boundaries',
    'runs renderers of the configured browser inside the kernel sandbox',
  ],
  [
    'Live browser launch and boundaries',
    'detects unsandboxed renderers when the sandbox is turned off',
  ],
  ['Live browser launch and boundaries', 'enforces CSP and CORS with the configured context'],
];

const normalize = (p) => p.replace(/\\/g, '/');

function problemsIn(report, expectedFile) {
  const problems = [];
  if (report?.success !== true) problems.push('vitest run did not report success');
  if (report?.numFailedTests !== 0) problems.push('vitest reported failed tests');
  const files = (Array.isArray(report?.testResults) ? report.testResults : []).filter(
    (file) => typeof file?.name === 'string' && normalize(file.name) === expectedFile,
  );
  if (files.length !== 1) {
    problems.push(`expected exactly one result for ${expectedFile}, found ${files.length}`);
    return problems;
  }
  const assertions = Array.isArray(files[0].assertionResults) ? files[0].assertionResults : [];
  for (const [suite, title] of REQUIRED_PASSED) {
    const matches = assertions.filter(
      (a) =>
        a?.title === title &&
        Array.isArray(a.ancestorTitles) &&
        a.ancestorTitles.length === 1 &&
        a.ancestorTitles[0] === suite,
    );
    if (matches.length !== 1) {
      problems.push(`expected one "${suite} > ${title}", found ${matches.length}`);
    } else if (matches[0].status !== 'passed') {
      problems.push(`"${title}" did not pass (status: ${matches[0].status})`);
    }
  }
  return problems;
}

const reportPath = process.argv[2];
if (!reportPath) {
  console.error(
    'usage: node assert-live-results.mjs <vitest-json-report>  (run from gitnexus-web)',
  );
  process.exit(2);
}

let problems;
try {
  problems = problemsIn(
    JSON.parse(readFileSync(reportPath, 'utf8')),
    normalize(resolve(process.cwd(), TEST_FILE)),
  );
} catch (error) {
  const detail = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  problems = [`cannot read vitest JSON report ${reportPath}: ${detail}`];
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`::error::Live browser checks: ${problem}`);
  process.exit(1);
}
console.log(`Live browser checks: all ${REQUIRED_PASSED.length} required tests passed`);
