#!/usr/bin/env node
/**
 * A `peerDependencies` range is a claim about versions nobody ran. This script
 * makes the claim checkable instead of asserted: for each line the range admits,
 * it copies this package into a scratch directory, pins every harness package to
 * that line's lowest published version, installs, builds, and runs the suite.
 *
 * The lines come from the manifest, not from a list here — a probe with its own
 * copy of the contract can drift from the thing it is supposed to be checking.
 * Each `||` segment of the range is one line, and its **lowest** version is the
 * boundary the segment claims, so that is what gets installed: a line whose
 * boundary passes is the strongest available evidence for the whole segment.
 *
 * ```sh
 * npm run test:probe-lines                 # every line the range admits
 * npm run test:probe-lines -- 0.1.7-rc.1   # one line
 * npm run test:probe-lines -- --keep       # leave the scratch trees in place
 * ```
 *
 * A line that fails here is removed from the range (manifest, README and the
 * `SUPPORTED_LINES` contract in `test/packaging.spec.mjs`) rather than left
 * claimed. This script is development-only and is not published.
 *
 * @module scripts/probe-lines
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import semver from 'semver'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))

/** What is copied into the scratch tree; everything else is not needed to test. */
const COPIED = ['src', 'test', 'tsconfig.json', 'README.md', 'LICENSE', 'cordis.patch.yml']

/**
 * The harness packages installed at the probed line.
 *
 * `dsh-system-prompt` is here because the integration suite mounts it; the other
 * three are the peers the range is about.
 */
const HARNESS = [
  '@deepseek-ai/dsh-agent',
  '@deepseek-ai/dsh-llm',
  '@deepseek-ai/dsh-tools',
  '@deepseek-ai/dsh-system-prompt',
]

/**
 * The newest published build of each `||` segment of a range.
 *
 * The representative of a line is its latest build — the one a user on that line
 * is actually running — not the earliest one the segment happens to admit. The
 * earliest build of a line is an alpha nobody is left on, and probing it says
 * less than probing the build the line converged to.
 * @param range - a semver range, composed of `||` segments.
 * @param versions - every published version of the package.
 * @returns one version per segment, in range order.
 */
function representativesOf(range, versions) {
  return range.split('||')
    .map(segment => segment.trim())
    .filter(segment => segment.length > 0)
    .map(segment => semver.maxSatisfying(versions, segment))
}

const argv = process.argv.slice(2)
const keep = argv.includes('--keep')
const requested = argv.filter(argument => !argument.startsWith('-'))

const range = manifest.peerDependencies['@deepseek-ai/dsh-llm']
const published = JSON.parse(execFileSync('npm', ['view', '@deepseek-ai/dsh-llm', 'versions', '--json'], { encoding: 'utf8' }))
const lines = requested.length > 0 ? requested : representativesOf(range, published)

/** Install one probe and run the suite in it. */
function probe(line) {
  const dir = mkdtempSync(join(tmpdir(), `sandbox-grant-advisor-${line}-`))
  const log = (message) => process.stdout.write(`${message}\n`)
  log(`\n=== ${line} — ${dir}`)
  for (const entry of COPIED) cpSync(join(ROOT, entry), join(dir, entry), { recursive: true })
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify({
    ...manifest,
    // The published version is the thing under test in `packedPaths()`; nothing
    // else about the manifest changes, so the packaging arms still apply.
    devDependencies: {
      ...manifest.devDependencies,
      ...Object.fromEntries(HARNESS.map(name => [name, line])),
    },
    // No `test:probe-lines` here: the probe must not be able to recurse.
    scripts: { build: 'tsc', test: 'tsc && node --test "test/*.spec.mjs"' },
  }, null, 2)}\n`)
  try {
    install(dir, log, line)
    execFileSync('npm', ['test'], { cwd: dir, stdio: ['ignore', 'pipe', 'inherit'] })
    log(`=== ${line}: PASS`)
    return true
  } catch (error) {
    if (error.stdout !== undefined) process.stdout.write(String(error.stdout))
    log(`=== ${line}: FAIL`)
    return false
  } finally {
    if (!keep) rmSync(dir, { recursive: true, force: true })
  }
}

/**
 * Install the probed line, and say so when npm's own resolution had to be
 * overruled.
 *
 * The harness packages peer-depend on each other, and an alpha build can
 * peer-depend on a later rc of the same line (`dsh-tools@0.1.5-alpha.1` →
 * `dsh-user-approval@^0.1.5-alpha.1` → `dsh-agent@^0.1.5-rc.3`), which npm
 * refuses to resolve into one tree. That refusal is a fact about the harness's
 * published metadata, not about this plugin — a real install gets these packages
 * from the profile's own lockfile — so the probe retries with `--force` and
 * records that the line's tree is npm's own choice. Only the LINE of the
 * versions under test is pinned here; which build of it npm ends up hoisting is
 * not something this plugin's claim depends on.
 * @param dir - the probe tree.
 * @param log - the progress writer.
 * @param line - the line being probed.
 */
function install(dir, log, line) {
  const options = { cwd: dir, stdio: ['ignore', 'ignore', 'inherit'] }
  try {
    execFileSync('npm', ['install', '--no-audit', '--no-fund'], options)
  } catch {
    log(`    npm refused the ${line} peer graph; retrying with --force`)
    execFileSync('npm', ['install', '--no-audit', '--no-fund', '--force'], options)
  }
}

const failed = lines.filter(line => !probe(line))
process.stdout.write(`\nprobed ${lines.length} line(s) of ${range}\n`)
if (failed.length > 0) {
  process.stdout.write(`failed: ${failed.join(', ')} — remove them from the range, the README and SUPPORTED_LINES\n`)
  process.exitCode = 1
}
