/**
 * The temp-root family, unit and end to end.
 *
 * Four properties need the real pipeline, and they are this family's whole reason
 * for existing:
 *
 * 1. **It is read from a thrown error's own message.** Both producers *throw* the
 *    sentence, and the runner's copy reaches the session inside another error's
 *    detail — so an arm that only ever inspects a successful result would never
 *    see it. The counterpart is asserted too: a command whose own output quotes
 *    the sentence is an ordinary success and must be left alone.
 * 2. **It has two producers of one sentence**, distinguished from the line itself:
 *    the session-scoped provider (no child ever existed) and the runner (marked
 *    with `windows-acl-run: `, exit 127, reclassified into a
 *    `SandboxUnavailableError`). Both spellings are built here as the producers
 *    really write them.
 * 3. **It is diagnosed twice by design.** The standing condition is reported
 *    pre-flight, on the first tracked call, and the refusal's own report follows
 *    if it happens — two seats, not one, so that the more informative text is not
 *    made unreachable in exactly the sessions that were warned.
 * 4. **The pre-flight half predicts, and its prediction is the backend's own
 *    computation** of two directories rather than a string test. The suite
 *    exercises that on the *real* filesystem: the policy stand-in is pointed at a
 *    directory that genuinely contains this host's `os.tmpdir()`, so the
 *    containment in the advice is the same `realpathSync.native` comparison the
 *    backend performs, computed on real paths.
 *
 * **The platform fact.** The pre-flight half is Windows-only by construction (the
 * invariant belongs to the Windows ACL backend's two capabilities), and this
 * suite runs on the maintainer's macOS host. The plugin reads `process.platform`,
 * not a config knob — a knob would be a backdoor into a shipped decision — so the
 * arms that need Windows stub the process-level fact and restore it, exactly as
 * the workspace-denial suite does. The failure half needs no stub: its input is
 * the producer's sentence, which no other platform can produce.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'

import { TEMP_ROOT_DISCUSSIONS, advisoryText, tempRootPreflightAdvisory } from '../lib/advice.js'
import { RUNNER_SIGNATURE, TEMP_ROOT_ASSERTION, classifyTempRootRefusal, failureLine } from '../lib/signature.js'
import { containsDirectory, tempRootInsideWorkspace } from '../lib/temp-root.js'
import { call, contexts, failingTool, logLines, logText, okTool, sandboxPolicy, who, world } from './harness.mjs'

/** The workspace and the temp root `#9175` printed, verbatim. */
const WORKSPACE = 'C:\\Users\\yanggaihao'
const TEMP = 'C:\\Users\\yanggaihao\\AppData\\Local\\Temp'

/** The sentence the provider throws, exactly as `path-boundary.ts` formats it. */
const REFUSAL = `${TEMP_ROOT_ASSERTION}: workspace=${WORKSPACE}; temp=${TEMP}`

/** The same sentence as the runner writes it, behind its own marker. */
const RUNNER_LINE = `${RUNNER_SIGNATURE} ${REFUSAL}`

/**
 * The message the runner carrier actually reaches a session as.
 *
 * Built from `SandboxUnavailableError`'s own text
 * (`packages/sandbox/sandbox/src/index.ts`): the seam reclassifies exit 127 with
 * the `windows-acl-run: ` signature as a runner failure and appends the runner's
 * stderr line behind `Runner failure: `, so the sentence arrives wrapped in
 * another error rather than as the message itself. That is why the recognition is
 * anchored on the sentence and not on the whole message.
 */
const RUNNER_ARRIVAL = 'sandbox mode "workspace-write" is requested but no sandbox backend is usable on this'
  + ' host; refusing to run the command unconfined. Install bubblewrap or run a Landlock-enforcing kernel'
  + ` (Linux), ensure sandbox-exec is usable (macOS), or ensure the ACL restricted-token runner can start`
  + ` (Windows) — otherwise switch the consumer to danger-full-access. Runner failure: ${RUNNER_LINE}`

/** The one mode whose private temp capability makes the invariant matter. */
const CONFINING = 'workspace-write'

/** The real host's platform descriptor, restored after every stubbed arm. */
const REAL_PLATFORM = Object.getOwnPropertyDescriptor(process, 'platform')

/**
 * Run one arm with the host reporting Windows.
 * @param body - the arm to run.
 * @returns whatever the arm returned.
 */
async function onWindows(body) {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true, enumerable: true })
  try {
    return await body()
  } finally {
    Object.defineProperty(process, 'platform', REAL_PLATFORM)
  }
}

/**
 * A directory that really does contain this host's temp root.
 *
 * The pre-flight arm needs a workspace the containment test answers YES for on a
 * machine that is not Windows, and the honest way to get one is to point at a real
 * ancestor of the real temp directory rather than at a string that looks like one:
 * `realpathSync.native` has to resolve both operands, so a fabricated path could
 * only ever exercise the fail-closed branch.
 */
const ANCESTOR_OF_TEMP = dirname(tmpdir())

test('the refusal is recognized from the producer\'s own sentence, with both operands kept', () => {
  const failure = classifyTempRootRefusal(REFUSAL)
  assert.ok(failure, 'the sentence with its two operands is the recognition')
  assert.equal(failure.family, 'temp-root-inside-workspace')
  assert.equal(failure.carrier, 'pre-spawn')
  assert.equal(failure.workspaceRoot, WORKSPACE)
  assert.equal(failure.tempRoot, TEMP)
  // The operands are the producer's, not a re-derivation: the message is the only
  // input, so a different pair comes back as a different pair.
  const other = classifyTempRootRefusal(`${TEMP_ROOT_ASSERTION}: workspace=D:\\ws; temp=D:\\ws\\tmp`)
  assert.ok(other)
  assert.equal(other.workspaceRoot, 'D:\\ws')
  assert.equal(other.tempRoot, 'D:\\ws\\tmp')
})

test('the second producer is told apart from the first by its own marker, on the line it sits on', () => {
  // The runner's copy does not arrive as the message: it arrives as the
  // `Runner failure: ` detail of the error the seam raises around it, where the
  // sentence is preceded on its own line by the runner's marker. The carrier is
  // therefore read off that line rather than off the message's beginning, and the
  // difference is not cosmetic — it is *when* the refusal happened.
  const failure = classifyTempRootRefusal(RUNNER_ARRIVAL)
  assert.ok(failure, 'the sentence is found inside the wrapping error')
  assert.equal(failure.carrier, 'runner')
  assert.equal(failure.workspaceRoot, WORKSPACE)
  assert.equal(failure.tempRoot, TEMP)
  // Bare, with no marker anywhere, is the provider: the same sentence is what both
  // producers throw, and only one of them prefixes it.
  assert.equal(classifyTempRootRefusal(REFUSAL)?.carrier, 'pre-spawn')
  assert.equal(failureLine({ ...failure, carrier: 'pre-spawn' }), REFUSAL)
  assert.equal(failureLine(failure), RUNNER_LINE)
})

test('everything that merely mentions the assertion is refused, not guessed at', () => {
  for (const message of [
    // The sentence alone, as a document or a log line would carry it: no operands,
    // so nothing to place and nothing to quote back.
    `The backend asserts: ${TEMP_ROOT_ASSERTION}`,
    // The sibling assertion in the same module — and this is the one that matters,
    // because it is a different failure wearing almost the same words. It rejects
    // an overlap between the private temp DIRECTORY and the writable directories,
    // in either direction; this family is the temp ROOT against the workspace, one
    // direction only. Advice written for one is wrong for the other.
    'AclSandbox private temp directory must be disjoint from writable directories: writable=D:\\ws; temp=D:\\t',
    // The same invariant with operands that are nothing but whitespace — what a
    // truncated or emptied-out log line carries. The pattern matches it, so the
    // emptiness guard is what has to refuse it.
    `${TEMP_ROOT_ASSERTION}: workspace=   ; temp=   `,
    // The other family's failure text, and an empty message.
    'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
    'PTY shell exited during startup',
    '[exit code: -1073741502]',
    '',
  ]) {
    assert.equal(classifyTempRootRefusal(message), undefined, `must refuse: ${JSON.stringify(message)}`)
  }
})

test('containment is the backend\'s canonical comparison, not a string prefix', () => {
  // On real paths, so the resolution both sides perform is really performed: the
  // temp directory is inside its own parent and not the other way round.
  assert.equal(containsDirectory(dirname(tmpdir()), tmpdir()), true)
  assert.equal(containsDirectory(tmpdir(), dirname(tmpdir())), false)
  // A directory contains itself.
  assert.equal(containsDirectory(tmpdir(), tmpdir()), true)
  // A sibling whose NAME begins with the root's own name does not, and the two
  // real directories make that a measurement rather than a spelling: this is the
  // shape a naive `startsWith` gets wrong, and the resolution both sides perform
  // is what gets it right.
  const parent = mkdtempSync(join(tmpdir(), 'sg-root-'))
  const sibling = `${parent}-sibling`
  const child = join(parent, 'child')
  mkdirSync(sibling)
  mkdirSync(child)
  try {
    assert.equal(containsDirectory(parent, sibling), false)
    assert.equal(containsDirectory(sibling, parent), false)
    assert.equal(containsDirectory(parent, child), true, 'and a real child is still contained')
  } finally {
    rmSync(parent, { recursive: true, force: true })
    rmSync(sibling, { recursive: true, force: true })
  }
  // A path that does not resolve is not "not contained" — it is a comparison that
  // could not be made, and the call throws so the caller's fail-closed branch (not
  // a silent `false`) is what answers.
  assert.throws(() => containsDirectory(tmpdir(), `${tmpdir()}-sibling`))
})

test('the standing predicate is gated on the host and on the one mode that has the capability', () => {
  const containing = { workspaceRoot: dirname(tmpdir()), tempRoot: tmpdir() }
  // The invariant belongs to the Windows ACL backend's two capabilities, so no
  // other host can be in the condition however the paths fall.
  assert.equal(tempRootInsideWorkspace({ ...containing, platform: 'darwin', mode: CONFINING }), false)
  assert.equal(tempRootInsideWorkspace({ ...containing, platform: 'linux', mode: CONFINING }), false)
  // Only `workspace-write` materializes a private temp capability: `read-only`
  // grants nothing to keep disjoint, and `danger-full-access` never spawns
  // through the sandbox at all.
  assert.equal(tempRootInsideWorkspace({ ...containing, platform: 'win32', mode: 'read-only' }), false)
  assert.equal(tempRootInsideWorkspace({ ...containing, platform: 'win32', mode: 'danger-full-access' }), false)
  assert.equal(tempRootInsideWorkspace({ ...containing, platform: 'win32', mode: CONFINING }), true)
  // And a path that does not resolve answers "no violation": a prediction that
  // cannot be computed must stay silent rather than guess.
  assert.equal(
    tempRootInsideWorkspace({ platform: 'win32', mode: CONFINING, workspaceRoot: dirname(tmpdir()), tempRoot: `${tmpdir()}/does-not-exist-${String(process.pid)}` }),
    false,
  )
})

test('the refusal advisory prints the producer\'s pair, names the carrier, and hands nothing to the shell', () => {
  const failure = classifyTempRootRefusal(REFUSAL)
  assert.ok(failure)
  const text = advisoryText(failure, { tool: 'bash' })
  assert.match(text, /Sandbox command execution is unavailable/)
  // Both operands the producer printed, quoted rather than re-derived.
  assert.match(text, new RegExp(WORKSPACE.replaceAll('\\', '\\\\')))
  assert.match(text, /AppData\\Local\\Temp/)
  assert.match(text, /workspace-write/, 'the mode the rule applies to is named')
  // The mechanism, and the reason a permissions fix is the wrong reach.
  assert.match(text, /capability-disjointness/)
  assert.match(text, /realpathSync\.native/)
  assert.match(text, /not an ACL problem and no `icacls` grant fixes it/)
  // The remedy is the environment, addressed to the user, because nothing inside
  // the session can carry it out — and there is no grant command anywhere in it.
  assert.match(text, /%TMP%/)
  assert.match(text, /GetTempPathW/)
  assert.match(text, /set TMP=C:\\dsh-temp/)
  assert.doesNotMatch(text, /icacls .*\/grant/, 'no grant-repair advice belongs in this family')
  assert.doesNotMatch(text, /If you own it/)
  // The two modes that do not meet the rule, and the session's own reach.
  assert.match(text, /`read-only` session is unaffected/)
  assert.match(text, /`danger-full-access` does not hit it either/)
  assert.match(text, /file read\/write tools keep working/)
  assert.match(text, new RegExp(TEMP_ROOT_DISCUSSIONS))
  // With an href the thread line moves, and the discussion id becomes the link.
  const linked = advisoryText(failure, { tool: 'bash', href: 'https://example.invalid/d/9175' })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/d\/9175/)
  assert.doesNotMatch(linked, /tracked upstream \(discussion/)
})

test('the two carriers are named as themselves, because a fix has to satisfy both', () => {
  const provider = classifyTempRootRefusal(REFUSAL)
  const runner = classifyTempRootRefusal(RUNNER_ARRIVAL)
  assert.ok(provider)
  assert.ok(runner)
  const fromProvider = advisoryText(provider, {})
  const fromRunner = advisoryText(runner, {})
  assert.match(fromProvider, /the PROVIDER, before any child existed/)
  assert.match(fromProvider, /nothing ran/)
  assert.doesNotMatch(fromProvider, /the RUNNER, whose line is written/)
  assert.match(fromRunner, /the RUNNER, whose line is written to stderr behind the `windows-acl-run: `/)
  assert.match(fromRunner, /exit 127/)
  assert.match(fromRunner, /`SandboxUnavailableError`/)
  assert.doesNotMatch(fromRunner, /the PROVIDER, before any child existed/)
  // Both texts say the same sentence has two producers, which is the fact a
  // maintainer needs and a session cannot see from the outside.
  for (const text of [fromProvider, fromRunner]) assert.match(text, /One sentence, two producers/)
})

test('the pre-flight report states the facts it computed, and how it is falsified', () => {
  const text = tempRootPreflightAdvisory(WORKSPACE, TEMP)
  assert.match(text, /Standing condition, before anything has failed/)
  // The three facts, so the claim can be audited rather than taken on faith.
  assert.match(text, /host        win32/)
  assert.match(text, /mode        workspace-write/)
  assert.match(text, /workspace   C:\\Users\\yanggaihao/)
  assert.match(text, /temp root   C:\\Users\\yanggaihao\\AppData\\Local\\Temp/)
  // The one verification available when no command can be run.
  assert.match(text, /falsifiable in one step/)
  assert.match(text, /if a command does run in this session/)
  // It shares the mechanism, the remedy and the boundaries with the failure
  // advisory, and says the refusal's own report is still coming.
  assert.match(text, /capability-disjointness/)
  assert.match(text, /%TMP%/)
  assert.match(text, /`read-only` session is unaffected/)
  assert.match(text, /a second advisory/)
  assert.doesNotMatch(text, /icacls .*\/grant/)
  assert.match(text, new RegExp(TEMP_ROOT_DISCUSSIONS))
  assert.match(tempRootPreflightAdvisory(WORKSPACE, TEMP, 'https://example.invalid/d/9175'), /tracked upstream: https:/)
})

test('the refusal arrives as a notice beside the failing call, from either producer', async () => {
  for (const [message, carrier] of [[REFUSAL, 'session-scoped provider'], [RUNNER_ARRIVAL, 'windows-acl runner']]) {
    const { ctx, logged } = await world(undefined, [failingTool('bash', message)])
    const result = await call(ctx, 'bash', { command: 'echo test' })
    assert.equal(result.isError, true, 'the producer throws, so the call really is an error')
    assert.equal(contexts(result).length, 1, 'the diagnosis rides the failing result')
    const notice = contexts(result)[0]
    assert.equal(notice.role, 'user')
    assert.equal(notice.source.kind, 'sandbox-grant-advisor')
    assert.equal(notice.source.form, 'notice')
    assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the row stays one line')
    assert.match(notice.source.summary, /sandbox temp root lies inside the workspace/)
    const body = notice.content.map(block => block.text).join('\n')
    assert.match(body, /Sandbox command execution is unavailable/)
    assert.match(body, /not an ACL problem/)
    // The host-side account carries both operands and the carrier.
    const host = logLines(logged, 'sandbox-grant-advisor: ')
    assert.equal(host.length, 1)
    assert.match(host[0], new RegExp(carrier))
    assert.match(host[0], /C:\\Users\\yanggaihao/)
    assert.match(host[0], /AppData/)
    assert.match(host[0], new RegExp(TEMP_ROOT_DISCUSSIONS))
  }
})

test('the advisory is delivered once per agent, and a quoted sentence is not this family', async () => {
  const { ctx } = await world(undefined, [failingTool('bash', REFUSAL), okTool('read', 'no match here')])
  assert.equal(contexts(await call(ctx, 'bash', { command: 'echo test' })).length, 1)
  assert.equal(contexts(await call(ctx, 'bash', { command: 'echo test' })).length, 0, 'the environment is explained once')
  // A command whose own OUTPUT contains the sentence is an ordinary success: the
  // family is read from a thrown error's message, and the rendered content of a
  // finished run is exactly where a transcript would carry it.
  const quoted = await world(undefined, [okTool('bash', REFUSAL)])
  const success = await call(quoted.ctx, 'bash', {})
  assert.equal(success.isError, false)
  assert.equal(contexts(success).length, 0, 'a printed sentence is not a refusal')
  assert.equal(logText(quoted.logged), '', 'and not a withheld decision either')
})

test('an agent already in the standing condition is told before its first command fails', async () => {
  await onWindows(async () => {
    const policy = sandboxPolicy(CONFINING, { workspaceRoot: ANCESTOR_OF_TEMP })
    const { ctx, logged } = await world(undefined, [okTool('read', 'x')], { policy })
    // A file read, not a command: the condition is a relationship between two
    // directories, so it is discoverable before anything is asked to run.
    const first = await call(ctx, 'read', {})
    assert.equal(first.isError, false)
    assert.equal(contexts(first).length, 1, 'the report rides the first tool result of any kind')
    const notice = contexts(first)[0]
    assert.match(notice.source.summary, /commands will be refused/)
    const body = notice.content.map(block => block.text).join('\n')
    assert.match(body, /Standing condition, before anything has failed/)
    assert.match(body, new RegExp(ANCESTOR_OF_TEMP.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')))
    // The host line accounts for it, and the verdict is memoized: the second call
    // does not ask the policy resolver again.
    assert.equal(logLines(logged, 'pre-flight advisory delivered').length, 1)
    assert.equal(contexts(await call(ctx, 'read', {})).length, 0)
    assert.equal(policy.calls.length, 2, 'one resolution per fact, on the first call only')
    assert.equal(policy.calls[0].session, who('s1').session)
  })
})

test('the pre-flight report is not sent when the mode has no such capability, nor off Windows', async () => {
  await onWindows(async () => {
    // `read-only` materializes no private temp capability, so the invariant is
    // never reached — the same directories, a different mode, no condition.
    const { ctx, logged } = await world(
      undefined,
      [okTool('read', 'x')],
      { policy: sandboxPolicy('read-only', { workspaceRoot: ANCESTOR_OF_TEMP }) },
    )
    assert.equal(contexts(await call(ctx, 'read', {})).length, 0)
    assert.equal(logText(logged), '', 'a decided clear is not a withheld decision')
  })
  // And this arm is the real host: the question does not arise off Windows, so the
  // platform fact is read before any policy lookup.
  assert.notEqual(process.platform, 'win32', 'this half is only meaningful off Windows')
  const policy = sandboxPolicy(CONFINING, { workspaceRoot: ANCESTOR_OF_TEMP })
  const { ctx, logged } = await world(undefined, [okTool('read', 'x')], { policy })
  assert.equal(contexts(await call(ctx, 'read', {})).length, 0)
  assert.equal(logText(logged), '')
  assert.equal(policy.calls.length, 0, 'no host pays for a family it cannot have')
})

test('a Windows host that cannot answer says so once, instead of passing as clear', async () => {
  await onWindows(async () => {
    // No root in the answer: the containment claim is a statement about two
    // strings, and without the second there is nothing to test. Silence would read
    // as "this session is fine", which this plugin cannot claim.
    const { ctx, logged } = await world(
      undefined,
      [okTool('read', 'x')],
      { policy: sandboxPolicy(CONFINING, { resolve: () => ({ mode: CONFINING }) }) },
    )
    for (let attempt = 0; attempt < 3; attempt += 1) assert.equal(contexts(await call(ctx, 'read', {})).length, 0)
    const notes = logLines(logged, 'could not be checked')
    assert.equal(notes.length, 1, 'the decision is recorded once, not once per call')
    assert.match(notes[0], /without a usable workspace root/)
    assert.match(notes[0], new RegExp(TEMP_ROOT_DISCUSSIONS))
    assert.equal(logLines(logged, 'pre-flight advisory delivered').length, 0, 'and nothing was delivered')
  })
})

test('the pre-flight seat and the refusal seat are separate, so a warned session still gets the proof', async () => {
  await onWindows(async () => {
    const { ctx } = await world(
      undefined,
      [failingTool('bash', REFUSAL), okTool('read', 'x')],
      { policy: sandboxPolicy(CONFINING, { workspaceRoot: ANCESTOR_OF_TEMP }) },
    )
    const agent = who('both3')
    // The failure is asked first, so this call carries the producer's own line
    // rather than the prediction — which is the point of the order.
    const refused = await call(ctx, 'bash', { command: 'echo test' }, agent)
    assert.equal(contexts(refused).length, 1)
    const refusal = contexts(refused)[0].content.map(block => block.text).join('\n')
    assert.match(refusal, /Sandbox command execution is unavailable/)
    assert.doesNotMatch(refusal, /Standing condition/)
    // The standing seat was left untouched by that call, so the next one still
    // reports the condition — the two are not one flag.
    const read = await call(ctx, 'read', {}, agent)
    assert.equal(contexts(read).length, 1)
    const preflight = contexts(read)[0].content.map(block => block.text).join('\n')
    assert.match(preflight, /Standing condition, before anything has failed/)
    assert.doesNotMatch(preflight, /What was reported/)
    // And each is delivered once: a third call is quiet.
    assert.equal(contexts(await call(ctx, 'read', {}, agent)).length, 0)
  })
})

test('a tool the operator excluded gets neither half, because that is asked-for silence', async () => {
  await onWindows(async () => {
    const policy = sandboxPolicy(CONFINING, { workspaceRoot: ANCESTOR_OF_TEMP })
    const { ctx, logged } = await world({ exclude: ['bash', 'read'] }, [okTool('read', 'x')], { policy })
    assert.equal(contexts(await call(ctx, 'read', {})).length, 0)
    assert.equal(logText(logged), '')
    assert.equal(policy.calls.length, 0, 'an untracked call is transparent, pre-flight included')
  })
})

test('a resolver that throws during the standing check is disclosed, not swallowed', async () => {
  await onWindows(async () => {
    const { ctx, logged } = await world(
      undefined,
      [okTool('read', 'x')],
      { policy: sandboxPolicy(CONFINING, { resolve: () => { throw new Error('policy exploded') } }) },
    )
    const result = await call(ctx, 'read', {})
    assert.equal(result.isError, false, 'a broken advisor is not a broken call')
    assert.equal(contexts(result).length, 0)
    assert.match(logText(logged), /could not be checked/)
    assert.match(logText(logged), /policy exploded/)
  })
})
