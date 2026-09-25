/**
 * The native-init death, end to end: the `native-init` family driven through the
 * real tool waterfalls on the shared harness.
 *
 * This is the only family whose input is a **successful** result, so the
 * properties that need the real pipeline here are different from the other two
 * suites':
 *
 * 1. **The diagnosis attaches to a call the pipeline calls a success.** A
 *    `tools/post-execute` listener that only looked at `isError` results — which
 *    is what this plugin shipped before `0.6.0` — cannot see this failure at all,
 *    so the arm that matters is the one where `result.isError === false` and the
 *    notice still rides `additionalContexts`.
 * 2. **The sandbox mode is still the gate.** Both producers of the code need the
 *    restricted token to happen, so a non-confining mode must withhold and say so.
 *
 * The values are built by `test/foreground.mjs` from the reports' own numbers
 * (`#7876`, `#7877`): `-1073741502` and the MSYS2 stderr line.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  call,
  contexts,
  failingTool,
  foreground,
  logLines,
  logText,
  MSYS2_STDERR,
  NATIVE_DEATH,
  okTool,
  REPORTED,
  runs,
  sandboxPolicy,
  shellTool,
  text,
  who,
  world,
} from './harness.mjs'

/** A confining mode: the one both reports' failing arms used. */
const CONFINING = 'workspace-write'

/** One shell call that died in the loader, with the policy it ran under. */
async function deathWorld(config, options = {}) {
  const policy = options.policy ?? sandboxPolicy(options.mode ?? CONFINING, options.policyOptions ?? {})
  const built = await world(config, [shellTool('pwsh', options.value ?? foreground(NATIVE_DEATH))], { policy })
  return { ...built, policy }
}

test('a confining mode turns a "successful" call that never started into the diagnosis beside it', async () => {
  const { ctx, logged, policy } = await deathWorld()
  const result = await call(ctx, 'pwsh', { command: 'D:\\Git\\bin\\bash.exe -c "echo bash-ok"' })
  // The producer's own framing, asserted first: this is a success. The whole
  // reason this family was invisible before 0.6.0 is that the pipeline says so.
  assert.equal(result.isError, false)
  assert.match(text(result), /\[exit code: -1073741502\]/, 'the shell tool still reports the code to the model')

  const attached = contexts(result)
  assert.equal(attached.length, 1, 'exactly one context rides the result')
  const notice = attached[0]
  assert.equal(notice.role, 'user')
  assert.equal(notice.source.kind, 'sandbox-grant-advisor', 'the producer declares its own source kind')
  assert.equal(notice.source.form, 'notice')
  assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the notice row stays one line')
  assert.match(notice.source.summary, /never started/)
  assert.match(notice.source.summary, /workspace-write/, 'the transcript row names the mode, which is the finding')
  const body = notice.content.map(block => block.text).join('\n')
  assert.match(body, /STATUS_DLL_INIT_FAILED/)
  assert.match(body, /`workspace-write`/)
  assert.match(body, /Do not retry this call/)
  assert.match(body, /couldn\'t create signal pipe, Win32 error 5/)

  // The gate asked the real resolver, for this agent's own session.
  assert.equal(policy.calls.length, 1, 'one resolution per recognized failure')
  assert.equal(policy.calls[0].session, who('s1').session, 'resolved for the failing agent\'s session')

  // The host-side account exists too, and quotes the code as it was reported.
  const host = logLines(logged, 'sandbox-grant-advisor: sandboxed command reported exit')
  assert.equal(host.length, 1)
  assert.match(host[0], /-1073741502/)
  assert.match(host[0], /0xC0000142/)
  assert.match(host[0], /"workspace-write"/)
})

test('the advisory is delivered once per agent, not once per dead command', async () => {
  const { ctx, logged } = await deathWorld()
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'bash -c echo' })).length, 1)
  for (const command of ['sh -c echo', 'git status', 'ls | wc -l']) {
    const again = await call(ctx, 'pwsh', { command })
    assert.equal(again.isError, false)
    assert.equal(contexts(again).length, 0, 'the environment is explained once; repetition is noise')
  }
  assert.equal(runs('pwsh'), 4, 'the tool body really ran every time — the plugin enriched, never blocked')
  assert.equal(logLines(logged, 'sandboxed command reported exit').length, 1, 'the host line is not repeated either')
})

test('a second agent gets its own advisory', async () => {
  const { ctx } = await deathWorld()
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' }, who('p1'))).length, 1)
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' }, who('p2'))).length, 1)
})

test('the mode is read per call, and a non-confining one is not this family\'s story', async () => {
  const mode = { now: CONFINING }
  const calls = []
  const policy = sandboxPolicy(CONFINING, {
    calls,
    resolve: request => { calls.push(request); return { mode: mode.now } },
  })
  const { ctx, logged } = await world(undefined, [shellTool('pwsh', foreground(NATIVE_DEATH))], { policy })
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' }, who('m1'))).length, 1)
  // The same code under `danger-full-access`: the harness does not spawn the
  // command through the ACL runner there, so this is a different story (a broken
  // program) and asserting the sandbox would be a confident wrong cause.
  mode.now = 'danger-full-access'
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await call(ctx, 'pwsh', { command: 'x' }, who('m2'))
    assert.equal(result.isError, false)
    assert.equal(contexts(result).length, 0, 'no advisory where the mode is not confining')
  }
  const withheld = logLines(logged, 'no advisory sent')
  assert.equal(withheld.length, 1, 'the decision is recorded once, not once per retry')
  assert.match(withheld[0], /native-init/)
  assert.match(withheld[0], /danger-full-access/)
  assert.equal(logLines(logged, 'advisory delivered to the model').length, 1, 'only the confining call was advised')
})

test('an unmountable policy service withholds rather than guessing at the mode', async () => {
  const { ctx, logged } = await world(undefined, [shellTool('pwsh', foreground(NATIVE_DEATH))])
  const result = await call(ctx, 'pwsh', { command: 'bash -c echo' })
  assert.equal(result.isError, false)
  assert.equal(contexts(result).length, 0)
  const withheld = logLines(logged, 'no advisory sent')
  assert.equal(withheld.length, 1)
  assert.match(withheld[0], /no `sandboxPolicy` service is mounted/)
})

test('only the shipped foreground projection with the loader status is recognized', async () => {
  // Recognition is structural, so nothing a command *prints* can reach it: the
  // value has to be the shell projection with that integer in it.
  const quotedText = okTool('read_file', `main.log: [exit code: ${String(NATIVE_DEATH)}] — see #7877`)
  const background = shellTool('pwsh_bg', { kind: 'background', exitCode: NATIVE_DEATH })
  const { ctx, logged } = await world(undefined, [quotedText, background], { policy: sandboxPolicy(CONFINING) })

  const read = await call(ctx, 'read_file', { path: 'main.log' })
  assert.equal(read.isError, false)
  assert.match(text(read), /-1073741502/, 'the text really does contain the code')
  assert.equal(contexts(read).length, 0, 'a line of text is not a loader status')

  const running = await call(ctx, 'pwsh_bg', { command: 'sleep 1' })
  assert.equal(contexts(running).length, 0, 'a background handle is a different value shape')
  assert.equal(logText(logged), '', 'neither is a recognized failure, so nothing is logged either')
})

test('an exit code the producer does not call an error is left alone', async () => {
  // The neighbouring statuses and ordinary failures are other stories. The most
  // important of them is exit 127: that one the sandbox backend *does* own, and
  // it already arrives as an error result with its own diagnosis.
  for (const exitCode of [0, 1, 127, -1073740791, -1073741515]) {
    const { ctx, logged } = await world(undefined, [shellTool('pwsh', foreground(exitCode))], {
      policy: sandboxPolicy(CONFINING),
    })
    const result = await call(ctx, 'pwsh', { command: 'echo hi' })
    assert.equal(result.isError, false)
    assert.equal(contexts(result).length, 0, `must not advise for exit ${String(exitCode)}`)
    assert.equal(logText(logged), '')
  }
})

test('the MSYS2 producer keeps its own stderr, and the Electron one carries none', async () => {
  // The two producers are visibly different in this one respect, and the plugin
  // must not confuse the value with its stderr: the same code with output is
  // still the same class of failure.
  const withOutput = await deathWorld(undefined, { value: foreground(NATIVE_DEATH, MSYS2_STDERR) })
  const noOutput = await deathWorld(undefined, { value: foreground(NATIVE_DEATH) })
  const one = contexts(await call(withOutput.ctx, 'pwsh', { command: 'bash -c echo' }))
  const two = contexts(await call(noOutput.ctx, 'pwsh', { command: 'bash -c echo' }))
  assert.equal(one.length, 1)
  assert.equal(two.length, 1)
  assert.match(one[0].content.map(block => block.text).join('\n'), /signal pipe/)
  assert.equal(
    one[0].content.map(block => block.text).join('\n'),
    two[0].content.map(block => block.text).join('\n'),
    'the advisory is about the code and the mode, not about the stderr that happens to be present',
  )
})

test('the blocking half does not extend to the native-init family', async () => {
  // The remedy is a user-side launch fix, or a rewrite the model makes by calling
  // a different command — which has a different call key and is therefore never
  // the call being refused. Refusing calls could only pad a session that is
  // already unable to do the thing being refused.
  const { ctx } = await deathWorld({ enforceAfter: 1, maxDenials: 2 })
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const result = await call(ctx, 'pwsh', { command: 'bash -c echo' })
    assert.match(text(result), /\[exit code: -1073741502\]/, 'the tool really ran and really reported the code')
    assert.doesNotMatch(text(result), /Blocked by sandbox-grant-advisor/)
  }
  assert.equal(runs('pwsh'), 4)
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'bash -c echo' })).length, 0)
})

test('an agent that hits two families is told about both, each in its own words', async () => {
  const built = await world(undefined, [
    shellTool('pwsh', foreground(NATIVE_DEATH)),
    failingTool('bash', REPORTED),
  ], { policy: sandboxPolicy(CONFINING) })
  const agent = who('both1')
  const native = await call(built.ctx, 'pwsh', { command: 'bash -c echo' }, agent)
  const acl = await call(built.ctx, 'bash', { command: 'ls' }, agent)
  assert.equal(contexts(native).length, 1, 'the family whose input is a success is still first-class')
  assert.equal(contexts(acl).length, 1)
  assert.match(contexts(native)[0].content.map(block => block.text).join('\n'), /STATUS_DLL_INIT_FAILED/)
  assert.match(contexts(acl)[0].content.map(block => block.text).join('\n'), /WRITE_OWNER/)
  assert.equal(logLines(built.logged, 'sandboxed command reported exit').length, 1)
  assert.equal(logLines(built.logged, 'workspace ACL provisioning failed').length, 1)
  // The second call of each family is still quiet.
  assert.equal(contexts(await call(built.ctx, 'pwsh', { command: 'sh -c echo' }, agent)).length, 0)
  assert.equal(contexts(await call(built.ctx, 'bash', { command: 'pwd' }, agent)).length, 0)
})

test('the watching lists narrow this family too, without pretending it was withheld', async () => {
  const excluded = await world({ exclude: ['pwsh'] }, [shellTool('pwsh', foreground(NATIVE_DEATH))], {
    policy: sandboxPolicy(CONFINING),
  })
  assert.equal(contexts(await call(excluded.ctx, 'pwsh', { command: 'x' })).length, 0)
  assert.equal(logText(excluded.logged), '', 'an excluded tool is not a withheld diagnosis — the operator asked for silence')

  const wrongInclude = await world({ include: ['bash'] }, [shellTool('pwsh', foreground(NATIVE_DEATH))], {
    policy: sandboxPolicy(CONFINING),
  })
  assert.equal(contexts(await call(wrongInclude.ctx, 'pwsh', { command: 'x' })).length, 0)
  assert.equal(logText(wrongInclude.logged), '')
})

test('a configured href replaces the thread line in this family as well', async () => {
  const { ctx } = await world({ href: 'https://example.invalid/t/11' }, [shellTool('pwsh', foreground(NATIVE_DEATH))], {
    policy: sandboxPolicy('read-only'),
  })
  const body = contexts(await call(ctx, 'pwsh', { command: 'x' }))[0].content.map(block => block.text).join('\n')
  assert.match(body, /tracked upstream: https:\/\/example\.invalid\/t\/11/)
  // Only the thread *line* moves: the two producers keep their own references,
  // because a reader who wants the measurements needs the thread, not the line.
  assert.doesNotMatch(body, /tracked upstream \(discussions/)
  assert.match(body, /\(#7877\)/)
  assert.match(body, /\(#7876\)/)
})
