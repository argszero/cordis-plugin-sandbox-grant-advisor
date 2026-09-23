/**
 * The reported ACL failure, end to end: mount the plugin on the shared harness
 * (`./harness.mjs` — a real cordis context, the real `dsh-tools` ToolRuntime,
 * and the real tool waterfalls) and drive calls through the actual
 * `tools/pre-execute` / `tools/post-execute` seams.
 *
 * This suite owns the `acl-provisioning` family, in every form: recognition
 * through the seam, once-per-agent delivery, the error gate, the watching
 * lists, config validation, and both arms of the optional fail-fast half.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import * as plugin from '../lib/index.js'
import {
  call,
  contexts,
  failingTool,
  flakyTool,
  logText,
  okTool,
  REPORTED,
  runs,
  signal,
  text,
  who,
  world,
} from './harness.mjs'

test('exposes the documented plugin surface', () => {
  assert.equal(plugin.name, 'sandbox-grant-advisor')
  assert.equal(typeof plugin.apply, 'function')
  assert.deepEqual(plugin.inject, ['tools'])
  assert.equal(plugin.SOURCE_KIND, 'sandbox-grant-advisor')
  assert.equal(plugin.DEFAULT_ENFORCE_AFTER, 0)
  assert.equal(plugin.DEFAULT_MAX_DENIALS, 2)
})

test('the reported failure is settled with the diagnosis beside it', async () => {
  const { ctx, logged } = await world(undefined, [failingTool('bash', REPORTED)])
  const result = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(result.isError, true)
  assert.equal(text(result), `Error: ${REPORTED}`, 'the original failure is preserved, not replaced')
  const attached = contexts(result)
  assert.equal(attached.length, 1, 'exactly one context rides the failure')
  const notice = attached[0]
  assert.equal(notice.role, 'user')
  assert.equal(notice.source.kind, 'sandbox-grant-advisor', 'the producer declares its own source kind')
  assert.equal(notice.source.form, 'notice')
  assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the notice row stays one line')
  assert.equal(typeof notice.id, 'string')
  const body = notice.content.map(block => block.text).join('\n')
  assert.match(body, /WRITE_OWNER/)
  assert.match(body, /SetNamedSecurityInfoW failed \(Win32 5\): grantWrite\(D:\\ws\)/)
  assert.match(body, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)F"/)
  // A host-side account exists too, so the transcript is not the only record.
  assert.equal(
    logText(logged).split('\n').filter(line => line.includes('sandbox-grant-advisor: workspace ACL provisioning failed')).length,
    1,
  )
})

test('the advisory is delivered once per agent, not once per failed command', async () => {
  const { ctx, logged } = await world(undefined, [failingTool('bash', REPORTED)])
  const first = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(contexts(first).length, 1)
  for (const command of ['pwd', 'whoami', 'git status']) {
    const again = await call(ctx, 'bash', { command })
    assert.equal(again.isError, true)
    assert.equal(contexts(again).length, 0, 'the environment is explained once; repetition is noise')
  }
  assert.equal(logged.length, 1, 'the host-side line is not repeated either')
})

test('a second agent gets its own advisory', async () => {
  const { ctx } = await world(undefined, [failingTool('bash', REPORTED)])
  assert.equal(contexts(await call(ctx, 'bash', { command: 'ls' }, who('a1'))).length, 1)
  assert.equal(contexts(await call(ctx, 'bash', { command: 'ls' }, who('a2'))).length, 1)
})

test('a direct execute() with no agent is never advised', async () => {
  const { ctx } = await world(undefined, [failingTool('bash', REPORTED)])
  const result = await ctx.tools.execute({ name: 'bash', arguments: { command: 'ls' }, signal: signal() })
  assert.equal(result.isError, true)
  assert.equal(contexts(result).length, 0, 'no agent means no session to explain anything to')
})

test('an unrelated failure is left exactly as it was', async () => {
  const { ctx, logged } = await world(undefined, [failingTool('edit', 'old_string and new_string must differ')])
  const result = await call(ctx, 'edit', { old_string: 'a', new_string: 'a' })
  assert.equal(result.isError, true)
  assert.equal(contexts(result).length, 0)
  assert.match(text(result), /must differ/)
  assert.equal(logged.length, 0)
})

test('a SUCCESS whose output quotes the signature is not a provisioning failure', async () => {
  // Reading a log file that happens to contain the line must not trigger advice:
  // the gate is the result's error state, not the presence of the text.
  const { ctx, logged } = await world(undefined, [okTool('read_file', `deploy.log: ${REPORTED}`)])
  const result = await call(ctx, 'read_file', { path: 'deploy.log' })
  assert.equal(result.isError, false)
  assert.equal(contexts(result).length, 0)
  assert.equal(logged.length, 0)
})

test('include and exclude lists narrow what is watched', async () => {
  const { ctx } = await world({ exclude: ['bash'] }, [failingTool('bash', REPORTED)])
  assert.equal(contexts(await call(ctx, 'bash', { command: 'ls' })).length, 0)

  const included = await world({ include: ['pwsh*'] }, [failingTool('bash', REPORTED), failingTool('pwsh', REPORTED)])
  assert.equal(contexts(await call(included.ctx, 'bash', { command: 'ls' })).length, 0)
  assert.equal(contexts(await call(included.ctx, 'pwsh', { command: 'ls' })).length, 1)
})

test('invalid configuration fails loud instead of silently disabling the half', () => {
  const ctxStub = { logger: { warn() {} } }
  for (const bad of [{ enforceAfter: -1 }, { enforceAfter: 1.5 }, { enforceAfter: 'x' }, { maxDenials: 0 }]) {
    assert.throws(() => { plugin.apply(ctxStub, bad) }, /sandbox-grant-advisor/)
  }
})

test('with the default config the plugin never blocks anything', async () => {
  const { ctx } = await world(undefined, [failingTool('bash', REPORTED)])
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const result = await call(ctx, 'bash', { command: 'ls' })
    assert.equal(result.isError, true)
    assert.match(text(result), /SetNamedSecurityInfoW failed/, 'the tool really ran and really failed')
    assert.doesNotMatch(text(result), /Blocked by sandbox-grant-advisor/)
  }
  assert.equal(runs('bash'), 5, 'the blocking half is off unless asked for')
})

test('the fail-fast half refuses an identical call it has watched fail, and only that', async () => {
  const { ctx } = await world({ enforceAfter: 2, maxDenials: 2 }, [failingTool('bash', REPORTED)])
  // Two real failures teach the plugin that this call, in this environment, cannot run.
  assert.equal((await call(ctx, 'bash', { command: 'ls' })).isError, true)
  assert.equal((await call(ctx, 'bash', { command: 'ls' })).isError, true)
  assert.equal(runs('bash'), 2)

  const blocked = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(blocked.isError, true)
  assert.equal(runs('bash'), 2, 'the refused call never reached the body')
  assert.match(text(blocked), /Blocked by sandbox-grant-advisor/)
  assert.match(text(blocked), /already failed 2 times/)
  assert.match(text(blocked), /automatic block 1 of 2/)

  // A different command is a different attempt: it is not the call we watched fail.
  const other = await call(ctx, 'bash', { command: 'pwd' })
  assert.equal(runs('bash'), 3, 'an untried call still reaches the body')

  // The budget is bounded: past it the identical call proceeds again.
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 2 of 2/)
  const allowed = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(runs('bash'), 4, 'the guard must never make a session unfinishable')
  assert.match(text(allowed), /SetNamedSecurityInfoW failed/, 'and the environment still reports itself')
})

test('the guard never counts its own denial as an environment failure', async () => {
  // The discriminating arm needs a second denial: if our own denial text (which
  // quotes the Win32 line on purpose) were read back as an environment failure,
  // the second denial would report an inflated count and the model would be told
  // the environment is worse than it is.
  const { ctx } = await world({ enforceAfter: 2, maxDenials: 2 }, [failingTool('bash', REPORTED)])
  await call(ctx, 'bash', { command: 'ls' })
  await call(ctx, 'bash', { command: 'ls' })
  const first = await call(ctx, 'bash', { command: 'ls' })
  assert.match(text(first), /already failed 2 times/)
  const second = await call(ctx, 'bash', { command: 'ls' })
  assert.match(text(second), /already failed 2 times/, 'the count still describes the ENVIRONMENT')
  assert.doesNotMatch(text(second), /already failed 3 times/)
})

test('a call that finally succeeds stops being a denial target', async () => {
  // The environment can start working mid-session (the user fixes the ACL). The
  // plugin must notice, or it would keep refusing a call that now works.
  const flaky = flakyTool('bash', REPORTED)
  const { ctx } = await world({ enforceAfter: 2, maxDenials: 2 }, [flaky.definition])
  await call(ctx, 'bash', { command: 'ls' })
  await call(ctx, 'bash', { command: 'ls' })
  // The budget is what lets a repaired environment be discovered at all: two
  // refusals, and then the very call under suspicion gets to run again.
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 1 of 2/)
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 2 of 2/)
  flaky.state.fail = false
  const success = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(success.isError, false, 'a repaired environment must be allowed to proceed')
  flaky.state.fail = true
  const after = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(after.isError, true)
  assert.match(text(after), /SetNamedSecurityInfoW failed/, 'a fresh failure re-earns its own attempt')
  assert.doesNotMatch(text(after), /Blocked by sandbox-grant-advisor/)
  // That success also re-armed the budget: the refusal is bounded per episode
  // of brokenness, not one refusal budget for the whole session.
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 1 of 2/)
})

test('this plugin\'s notice comes before another listener\'s context on the same result', async () => {
  const { ctx } = await world(undefined, [failingTool('bash', REPORTED)])
  // A second observer, mounted later, attaches its own context after delegating.
  ctx.on('tools/post-execute', async (_exec, _result, next) => {
    const downstream = await next()
    const extra = { id: 'ctx-other', role: 'user', content: [{ type: 'text', text: 'other' }], source: { kind: 'user' } }
    if (downstream.kind === 'block') {
      return { kind: 'block', feedback: downstream.feedback, additionalContexts: [...downstream.additionalContexts ?? [], extra] }
    }
    return { ...downstream, additionalContexts: [...downstream.additionalContexts ?? [], extra] }
  })
  const attached = contexts(await call(ctx, 'bash', { command: 'ls' }))
  assert.equal(attached.length, 2)
  assert.equal(attached[0].source.kind, 'sandbox-grant-advisor', 'the diagnosis leads')
  assert.equal(attached[1].id, 'ctx-other')
})

test('a later listener rewriting the content cannot hide the diagnosis', async () => {
  const { ctx } = await world(undefined, [failingTool('bash', REPORTED)])
  // A spill/hook-style listener replaces the rendered content of the failure.
  // The plugin reads the authoritative `error.message` field before delegating,
  // so the classification does not depend on what other listeners keep.
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    if (exec.name !== 'bash') return next()
    const downstream = await next()
    if (downstream.kind !== 'accept') return downstream
    return { ...downstream, content: [{ type: 'text', text: '<spilled: 1 file, see locator>' }] }
  })
  const result = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(result.isError, true)
  assert.equal(text(result), '<spilled: 1 file, see locator>')
  const attached = contexts(result)
  assert.equal(attached.length, 1)
  assert.match(attached[0].content.map(block => block.text).join('\n'), /grantWrite\(D:\\ws\)/,
    'the advisory still quotes the real error line')
})
