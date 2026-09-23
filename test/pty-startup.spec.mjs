/**
 * The persistent-shell failure, end to end: the `pty-startup` family driven
 * through the real tool waterfalls on the shared harness.
 *
 * Two properties are load-bearing here and neither can be seen in a unit arm:
 *
 * 1. **The gate reads the sandbox policy the failing call actually ran under.**
 *    The advisory's whole content is the mode, so the suite asserts which
 *    *session* the plugin resolved for, not merely that it resolved.
 * 2. **Withholding is visible.** The transcript shows a bare error whether the
 *    plugin decided the sandbox is irrelevant or could not tell at all, so the
 *    host log has to carry the difference — once.
 *
 * The failure text is the producer's, taken from `dsh-terminal-bash`'s
 * `session.ts` / `index.ts` (`waitReason === 'session_exit'`), because that text
 * is the plugin's entire input on every platform.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  call,
  contexts,
  failingTool,
  logLines,
  logText,
  okTool,
  PTY_EXIT,
  REPORTED,
  runs,
  sandboxPolicy,
  text,
  who,
  whoWithoutSession,
  world,
} from './harness.mjs'

/** A confining mode: the one the report's failing arm used. */
const CONFINING = 'workspace-write'

/** One failing persistent-shell call, with the policy the call ran under. */
async function shellWorld(config, options = {}) {
  const policy = options.policy ?? sandboxPolicy(options.mode ?? CONFINING)
  const built = await world(config, [failingTool('pwsh', PTY_EXIT)], { policy })
  return { ...built, policy }
}

test('a confining mode turns the bare startup failure into the diagnosis beside it', async () => {
  const { ctx, logged, policy } = await shellWorld()
  const result = await call(ctx, 'pwsh', { command: 'echo test' })
  assert.equal(result.isError, true)
  assert.equal(text(result), `Error: ${PTY_EXIT}`, 'the original failure is preserved, not replaced')
  const attached = contexts(result)
  assert.equal(attached.length, 1, 'exactly one context rides the failure')
  const notice = attached[0]
  assert.equal(notice.role, 'user')
  assert.equal(notice.source.kind, 'sandbox-grant-advisor', 'the producer declares its own source kind')
  assert.equal(notice.source.form, 'notice')
  assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the notice row stays one line')
  assert.match(notice.source.summary, /workspace-write/, 'the transcript row names the mode, which is the finding')
  const body = notice.content.map(block => block.text).join('\n')
  assert.match(body, /PTY shell exited during startup/)
  assert.match(body, /`workspace-write`/)
  assert.match(body, /Do NOT retry/)

  // The gate asked the real resolver, for this agent's own session — not for the
  // deployment default, which is the answer a mode-less resolve() would give.
  assert.equal(policy.calls.length, 1, 'one resolution per recognized failure')
  assert.equal(policy.calls[0].session, who('s1').session, 'resolved for the failing agent\'s session')

  // The host-side account exists too, and names the mode.
  const host = logLines(logged, 'sandbox-grant-advisor: persistent shell exited during startup')
  assert.equal(host.length, 1)
  assert.match(host[0], /"workspace-write"/)
})

test('the persistent-shell advisory is delivered once per agent, not once per failed command', async () => {
  const { ctx, logged } = await shellWorld()
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'echo test' })).length, 1)
  for (const command of ['dir', 'whoami', 'git status']) {
    const again = await call(ctx, 'pwsh', { command })
    assert.equal(again.isError, true)
    assert.equal(contexts(again).length, 0, 'the environment is explained once; repetition is noise')
  }
  assert.equal(logLines(logged, 'persistent shell exited during startup').length, 1, 'the host-side line is not repeated either')
})

test('a second agent gets its own advisory', async () => {
  const { ctx } = await shellWorld()
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' }, who('p1'))).length, 1)
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' }, who('p2'))).length, 1)
})

test('the mode is read per call, so a mode the user changes is what gets quoted', async () => {
  // The plugin must not cache the first answer: the mode is part of the
  // diagnosis, and a session can log a new one (`sandbox/mode`).
  const mode = { now: CONFINING }
  const calls = []
  const policy = sandboxPolicy(CONFINING, { calls, resolve: request => { calls.push(request); return { mode: mode.now } } })
  const { ctx } = await world(undefined, [failingTool('pwsh', PTY_EXIT)], { policy })
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' }, who('m1'))).length, 1)
  mode.now = 'read-only'
  const second = await call(ctx, 'pwsh', { command: 'x' }, who('m2'))
  assert.equal(contexts(second).length, 1)
  assert.match(contexts(second)[0].content.map(block => block.text).join('\n'), /`read-only`/)
  assert.equal(calls.length, 2, 'each recognized failure resolves again')
})

test('under danger-full-access the failure is NOT this plugin\'s story, and the silence is disclosed', async () => {
  // The reporter's own control: the same shell works under danger-full-access.
  // A shell that still fails to start there is a broken or missing shell, and
  // sending the model to change presets would be a confident wrong cause.
  const { ctx, logged } = await shellWorld(undefined, { mode: 'danger-full-access' })
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await call(ctx, 'pwsh', { command: 'echo test' })
    assert.equal(result.isError, true)
    assert.equal(text(result), `Error: ${PTY_EXIT}`)
    assert.equal(contexts(result).length, 0, 'no advisory where the mode is not confining')
  }
  const withheld = logLines(logged, 'no advisory sent')
  assert.equal(withheld.length, 1, 'the decision is recorded once, not once per retry')
  assert.match(withheld[0], /danger-full-access/)
  assert.equal(logLines(logged, 'advisory delivered to the model').length, 0)
})

test('an unmountable policy service withholds rather than guessing at the mode', async () => {
  // `ctx.get('sandboxPolicy')` is optional lookup: a composition may not mount
  // the service, and this plugin must degrade to silence rather than fail.
  const { ctx, logged } = await world(undefined, [failingTool('pwsh', PTY_EXIT)])
  const result = await call(ctx, 'pwsh', { command: 'echo test' })
  assert.equal(result.isError, true)
  assert.equal(contexts(result).length, 0)
  const withheld = logLines(logged, 'no advisory sent')
  assert.equal(withheld.length, 1)
  assert.match(withheld[0], /no `sandboxPolicy` service is mounted/)
})

test('a resolver that lies, throws, or answers for another shape is not believed', async () => {
  const lying = sandboxPolicy(CONFINING, { resolve: () => ({ sandboxMode: CONFINING }) })
  const fromLying = await world(undefined, [failingTool('pwsh', PTY_EXIT)], { policy: lying })
  assert.equal(contexts(await call(fromLying.ctx, 'pwsh', { command: 'x' })).length, 0)
  assert.equal(logLines(fromLying.logged, 'without a recognizable mode').length, 1)

  const scalar = sandboxPolicy(CONFINING, { resolve: () => CONFINING })
  const fromScalar = await world(undefined, [failingTool('pwsh', PTY_EXIT)], { policy: scalar })
  assert.equal(contexts(await call(fromScalar.ctx, 'pwsh', { command: 'x' })).length, 0)
  assert.equal(logLines(fromScalar.logged, 'without a recognizable mode').length, 1)

  const throwing = sandboxPolicy(CONFINING, { resolve: () => { throw new Error('session not registered') } })
  const fromThrowing = await world(undefined, [failingTool('pwsh', PTY_EXIT)], { policy: throwing })
  const refused = await call(fromThrowing.ctx, 'pwsh', { command: 'x' })
  assert.equal(refused.isError, true, 'a throwing resolver must not break the call')
  assert.equal(contexts(refused).length, 0)
  assert.equal(logLines(fromThrowing.logged, 'resolve` threw (Error: session not registered)').length, 1)

  // An agent with no session is the fourth way to fail closed — and the resolver
  // must not be consulted with an empty request, which would answer with the
  // deployment default instead of this session's mode.
  const calls = []
  const unconsulted = sandboxPolicy(CONFINING, { calls })
  const noSession = await world(undefined, [failingTool('pwsh', PTY_EXIT)], { policy: unconsulted })
  assert.equal(contexts(await call(noSession.ctx, 'pwsh', { command: 'x' }, whoWithoutSession('n1'))).length, 0)
  assert.equal(calls.length, 0, 'fail closed means not asking, not asking the wrong question')
  assert.equal(logLines(noSession.logged, 'the agent exposes no session').length, 1)
})

test('the diagnosis comes from the failure the layer recorded, not from a quoted line', async () => {
  // The failure the layer recorded is unrelated (`grep` found nothing and the
  // call was marked failed); a later listener rewrites the *rendered* content
  // into the producer's sentence. The PTY family reads `error.message` — the
  // rendered content is where a command's own output lives, and a quoted
  // sentence must not make a working session think its shell is dead.
  const { ctx, logged } = await world(undefined, [failingTool('pwsh', 'grep: no match (exit 1)')], {
    policy: sandboxPolicy(CONFINING),
  })
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    if (exec.name !== 'pwsh') return next()
    const downstream = await next()
    if (downstream.kind !== 'accept') return downstream
    return { ...downstream, content: [{ type: 'text', text: `Error: ${PTY_EXIT}` }] }
  })
  const result = await call(ctx, 'pwsh', { command: 'grep -c PTY terminal.log' })
  assert.equal(result.isError, true)
  assert.equal(text(result), `Error: ${PTY_EXIT}`, 'the content really does quote the sentence')
  assert.equal(contexts(result).length, 0, 'a quote is not a diagnosis')
  assert.equal(logText(logged), '')
})

test('a SUCCESS whose output quotes the startup failure is never advised', async () => {
  // Reading a log that happens to contain the line must not trigger advice: the
  // gate is the result's error state, not the presence of the text.
  const quoted = okTool('read_file', `terminal.log: ${PTY_EXIT}`)
  const { ctx, logged } = await world(undefined, [quoted], { policy: sandboxPolicy(CONFINING) })
  const result = await call(ctx, 'read_file', { path: 'terminal.log' })
  assert.equal(result.isError, false)
  assert.equal(contexts(result).length, 0)
  assert.equal(logText(logged), '')
})

test('the blocking half does not extend to the persistent-shell family', async () => {
  // The ACL remedy is a command the user can run while the session continues;
  // the PTY remedy is a preset swap between sessions. Refusing calls could only
  // pad a session that is already unable to do the thing being refused.
  const { ctx } = await shellWorld({ enforceAfter: 1, maxDenials: 2 })
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const result = await call(ctx, 'pwsh', { command: 'echo test' })
    assert.equal(result.isError, true)
    assert.match(text(result), /PTY shell exited during startup/, 'the tool really ran and really failed')
    assert.doesNotMatch(text(result), /Blocked by sandbox-grant-advisor/)
  }
  assert.equal(runs('pwsh'), 4)
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'echo test' })).length, 0, 'still one advisory, not one per call')
})

test('an agent that hits both families is told about both', async () => {
  // One "already advised" flag per agent would silently swallow the second
  // diagnosis; the state is kept per family for exactly this reason.
  const built = await world(undefined, [failingTool('pwsh', PTY_EXIT), failingTool('bash', REPORTED)], {
    policy: sandboxPolicy(CONFINING),
  })
  const agent = who('both1')
  const shell = await call(built.ctx, 'pwsh', { command: 'echo test' }, agent)
  const acl = await call(built.ctx, 'bash', { command: 'ls' }, agent)
  assert.equal(contexts(shell).length, 1)
  assert.equal(contexts(acl).length, 1)
  assert.match(contexts(shell)[0].content.map(block => block.text).join('\n'), /PTY shell exited during startup/)
  assert.match(contexts(acl)[0].content.map(block => block.text).join('\n'), /WRITE_OWNER/)
  // Each family's host line fired, in its own words — and neither fired twice.
  assert.equal(logLines(built.logged, 'workspace ACL provisioning failed').length, 1)
  assert.equal(logLines(built.logged, 'persistent shell exited during startup').length, 1)
  // The second call of each family is still quiet.
  assert.equal(contexts(await call(built.ctx, 'pwsh', { command: 'dir' }, agent)).length, 0)
  assert.equal(contexts(await call(built.ctx, 'bash', { command: 'pwd' }, agent)).length, 0)
})

test('the watching lists narrow this family too, without pretending it was withheld', async () => {
  const { ctx, logged } = await world({ exclude: ['pwsh'] }, [failingTool('pwsh', PTY_EXIT)], {
    policy: sandboxPolicy(CONFINING),
  })
  assert.equal(contexts(await call(ctx, 'pwsh', { command: 'x' })).length, 0)
  assert.equal(logText(logged), '', 'an excluded tool is not a withheld diagnosis: the operator asked for silence')

  const included = await world({ include: ['bash'] }, [failingTool('pwsh', PTY_EXIT)], {
    policy: sandboxPolicy(CONFINING),
  })
  assert.equal(contexts(await call(included.ctx, 'pwsh', { command: 'x' })).length, 0)
  assert.equal(logText(included.logged), '')
})

test('a configured href replaces the thread line in this family as well', async () => {
  const { ctx } = await world({ href: 'https://example.invalid/t/9' }, [failingTool('pwsh', PTY_EXIT)], {
    policy: sandboxPolicy('read-only'),
  })
  const body = contexts(await call(ctx, 'pwsh', { command: 'x' }))[0].content.map(block => block.text).join('\n')
  assert.match(body, /tracked upstream: https:\/\/example\.invalid\/t\/9/)
  assert.doesNotMatch(body, /#7638/)
})
