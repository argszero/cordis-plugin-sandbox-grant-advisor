/**
 * The `tools/` guard: the instruments the third producer was measured with, and
 * the two claims that were wrong in the thread they came from.
 *
 * `tools/` is a published surface with no runtime behind it — nothing in `lib/`
 * imports it and no advisory executes it — which is exactly the shape that drifts.
 * Three defects had been reported against the *description* of this directory, all
 * by the person who wrote the scripts:
 *
 * - a closure size ("25 packages") that had been written without tallying the
 *   closure, and was wrong;
 * - "each script's header repeats its own invocation", which is true of three of
 *   the six and false of the other three — the reporter's own correction named
 *   one, and the same test names the other two; and
 * - the hook itself: the version posted in the thread switches on eight arms, while
 *   the version its author ran has twenty, so twelve arms his own rows report had no
 *   file here that could run them. `0.26.0` ships the twenty-arm file, which is why
 *   the arm table is checked against the script rather than against the thread.
 *
 * So the tables here are checked against the artifacts rather than against
 * themselves: the file list, the arm list and the knob list are each read out of
 * the scripts, and every number a reader could copy is either derived from a
 * script or absent. The one figure that must not appear in prose is the
 * materialiser's package count, which that script prints itself.
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { advisoryText } from '../lib/advice.js'
import { classifyNativeInitDeath } from '../lib/signature.js'
import { foreground, NATIVE_DEATH } from './foreground.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const TOOLS = join(ROOT, 'tools')
const README = readFileSync(join(TOOLS, 'README.md'), 'utf8')

/** Every script in `tools/`, sorted: the directory is the list, not the README. */
const FILES = readdirSync(TOOLS).filter(name => name.endsWith('.mjs')).sort()

/** One script's text, read by name rather than through a table of readers. */
function tool(name) {
  return readFileSync(join(TOOLS, name), 'utf8')
}

/**
 * Split a script into the provenance block this repository prepends and the text
 * it was prepended to. The block is delimited by the rule line it opens with, so
 * the split cannot silently walk off the end of a file that lost one.
 */
function splitProvenance(text) {
  const lines = text.split('\n')
  const rule = lines[0]
  assert.match(rule, /^\/\/ -+$/, 'a script must open with the provenance rule line')
  const close = lines.indexOf(rule, 1)
  assert.notEqual(close, -1, 'the provenance block must be closed by the rule line that opened it')
  return { block: lines.slice(0, close + 1).join('\n'), rest: lines.slice(close + 1).join('\n') }
}

/** A script's OWN comment header: the run of comments (and blanks) before its first code line. */
function ownHeader(text) {
  const collected = []
  for (const line of text.split('\n')) {
    if (line.startsWith('//') || line.trim() === '') collected.push(line)
    else break
  }
  return collected.join('\n')
}

/**
 * Whether a file's own header carries its invocation, computed rather than
 * declared: an invocation is a comment line that runs the packaged executable or
 * a plain node binary. The provenance block is excluded first, so this repository
 * cannot accidentally answer its own question.
 */
function carriesInvocation(text) {
  return /^\/\/\s+\S.*(?:--expose-internals|<node\.exe>)/m.test(ownHeader(splitProvenance(text).rest))
}

/** The rows of the README's `## <title>` section that are table rows with content. */
function rows(title) {
  const start = README.indexOf(`\n## ${title}\n`)
  assert.notEqual(start, -1, `tools/README.md must have a "## ${title}" section`)
  const after = README.indexOf('\n## ', start + 1)
  const body = README.slice(start + 1, after === -1 ? README.length : after)
  const parsed = []
  for (const line of body.split('\n')) {
    if (!line.startsWith('|')) continue
    const cells = line.split('|').slice(1, -1).map(cell => cell.trim())
    if (!cells.length || cells.every(cell => cell === '')) continue
    if (cells.every(cell => /^:?-{2,}:?$/.test(cell))) continue
    if (['file', 'arm', 'variable'].includes(cells[0])) continue
    parsed.push(cells)
  }
  return parsed
}

/** The single backticked token a table row is keyed by, unquoted. */
function key(cells, table) {
  assert.match(cells[0], /^`[^`]+`$/, `every ${table} row must start with one backticked name, saw ${cells[0]}`)
  return cells[0].slice(1, -1)
}

/** The arms `hook.mjs` switches on. */
function hookArms() {
  return [...tool('hook.mjs').matchAll(/case "([^"]+)":/g)].map(match => match[1])
}

/** The variants `dacl-patch-hook.mjs` documents, which is where it names them. */
function patchArms() {
  return [...tool('dacl-patch-hook.mjs').matchAll(/variant "([a-z]+)"/g)].map(match => match[1])
}

/** Every environment variable the scripts read, whatever the README lists. */
function knobs() {
  const found = new Set()
  for (const name of FILES) {
    for (const match of tool(name).matchAll(/\b(?:SBX_[A-Z_]+|SBXRUNNER|KOFFI_URL)\b/g)) found.add(match[0])
  }
  return [...found].sort()
}

test('the guard has something to guard', () => {
  assert.equal(FILES.length, 6, `expected the six scripts the reporter offered, saw ${FILES.join(', ')}`)
  assert.ok(FILES.includes('materialise-runner.mjs'), 'the materialiser must be here: it is the one script the others cannot replace')
  assert.ok(rows('The files').length === FILES.length, 'the file table must have one row per script')
  assert.ok(hookArms().length >= 5, `expected hook.mjs to switch on its arms, saw ${hookArms().join(', ')}`)
  assert.equal(patchArms().length, 2, `expected the two documented variants, saw ${patchArms().join(', ')}`)
  assert.ok(knobs().length >= 4, `expected the scripts to read environment variables, saw ${knobs().join(', ')}`)
})

test('the file table and the directory list the same scripts, both ways', () => {
  const listed = rows('The files').map(cells => key(cells, 'file'))
  assert.deepEqual([...listed].sort(), FILES, 'a tool that is not in the table is a tool nobody can find, and a row with no file is a promise the directory does not keep')
})

test('every script carries the same provenance lines, and the origin its row names', () => {
  for (const name of FILES) {
    const { block } = splitProvenance(tool(name))
    assert.match(block, /Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread\./, `${name} does not keep the author line verbatim`)
    assert.match(block, /The body underneath this block is unedited\. tools\/README\.md says what each arm is for/, `${name} does not keep the unedited-and-here-is-where-it-is-explained line`)
    assert.match(block, /by that script itself rather than written down anywhere\./, `${name} does not carry the rule that keeps the closure size out of prose`)
  }
  const row = new Map(rows('The files').map(cells => [key(cells, 'file'), cells]))
  for (const name of FILES) {
    const { block } = splitProvenance(tool(name))
    const origin = block.match(/issuecomment-(\d+)/)
    assert.ok(origin, `${name}'s provenance names no origin comment`)
    assert.ok(row.get(name)[1].includes(origin[1]), `the README gives ${name} origin ${row.get(name)[1]}, while the file itself names ${origin[0]}`)
  }
})

test('the "own header" column matches what the scripts actually carry', () => {
  // The blanket sentence this column replaces — "each script's header repeats its
  // own invocation" — was offered in the thread and then corrected for one file.
  // Computed, the correction covers three: the two bootstraps and the two-axis
  // hook all defer, and only the three that drive the packaged executable
  // themselves carry their own command line.
  const row = new Map(rows('The files').map(cells => [key(cells, 'file'), cells]))
  const carrying = FILES.filter(name => carriesInvocation(tool(name)))
  assert.equal(carrying.length, 3, `expected three scripts to carry their own invocation, saw ${carrying.join(', ')}`)
  for (const name of FILES) {
    const cell = row.get(name)[3]
    assert.ok(cell, `${name}'s row has no "own header" cell`)
    const claims = `${cell.startsWith('carries its invocation')}`
    assert.equal(claims, `${carrying.includes(name)}`, `the README says "${cell}" of ${name}, and the file says otherwise`)
  }
})

test('the arm table and the arms the hooks implement are the same set, both ways', () => {
  const listed = rows('The arms').map(cells => key(cells, 'arm')).sort()
  assert.deepEqual(listed, [...hookArms(), ...patchArms()].sort(), 'an arm the README documents but no hook implements is a row a reader cannot run, and an arm the hook implements but the README omits is one they will not find')
})

test('every knob the scripts read is documented', () => {
  const listed = rows('The knobs').map(cells => key(cells, 'knob'))
  for (const name of knobs()) {
    assert.ok(listed.includes(name), `${name} is read by a script and never named in the README`)
  }
})

test('the closure size is printed by the materialiser and stated nowhere in prose', () => {
  const materialiser = tool('materialise-runner.mjs')
  assert.ok(materialiser.includes('packages copied ('), 'the materialiser must print its own count — the README points at that line instead of carrying a number')
  assert.ok(README.includes('packages copied ('), 'the README must name the materialiser output line the count is read from')
  assert.ok(!/\b\d+\s+packages\b/i.test(README), 'the README states a package count, which is a property of one build and was wrong the last time it was written down')
  // …and the mechanisms the README says resolve the closure are the ones the
  // script has. A description of how a tool works that names a mechanism the tool
  // does not use is the same defect as a stale number, one level up.
  for (const mechanism of ['pj.dependencies', 'pj.peerDependencies', 'scanSpecs']) {
    assert.ok(materialiser.includes(mechanism), `the README says the closure is resolved this way, and the script has no ${mechanism}`)
  }
})

test('every script parses', () => {
  // `--check` parses without executing: these scripts load koffi from an installed
  // desktop build, so importing one is not available on a test host — but a file
  // that is not a program at all is a defect the reviewer of a copy can catch, and
  // a truncated paste is the way it happens.
  for (const name of FILES) {
    execFileSync(process.execPath, ['--check', join(TOOLS, name)], { stdio: 'pipe' })
  }
})

test('the advisory points at the repository, and so do the two copies of it that ship', () => {
  // The offer these scripts came with was to link the comment; a comment is where
  // a reader has to scroll, and a repository directory is where they can run
  // something. All three carriers are asserted, because the README and the bundle
  // patch are published prose that a mounting operator reads before any advisory
  // fires, and a pointer that reaches only the rendered text is one they never see.
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH))
  assert.ok(failure, 'the fixture must classify as the native-init death, or the advisory below is not the one being checked')
  const rendered = advisoryText(failure, { mode: 'workspace-write' })
  assert.match(rendered, /`tools\/`/, 'the rendered advisory does not point at tools/')
  assert.match(rendered, /`tools\/README\.md`/, 'the rendered advisory does not say where in tools/ to read')
  for (const file of ['README.md', 'cordis.patch.yml']) {
    const text = readFileSync(join(ROOT, file), 'utf8')
    assert.ok(text.includes('tools/README.md'), `${file} does not point at tools/README.md`)
    assert.ok(/instruments/i.test(text), `${file} does not say what tools/ holds`)
  }
})
