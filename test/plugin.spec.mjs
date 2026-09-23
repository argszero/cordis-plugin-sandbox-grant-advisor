/**
 * Integration: mount the plugin on a REAL cordis context together with the REAL
 * `dsh-tools` ToolRuntime, register fixtures, and drive calls through the actual
 * `tools/pre-execute` / `tools/post-execute` waterfalls.
 *
 * What this shape proves that a unit arm cannot: the listener is wired to the
 * seam, the advisory really rides `additionalContexts` on the settled result
 * (the channel the agent loop turns into a durable user-role message), and a
 * denial really stops the tool body from running.
 *
 * What it cannot prove, and does not claim: the Windows ACL path itself. The
 * fixtures throw the producer's exact error text — taken from
 * `Win32Error` (`packages/subprocess/win32-process/src/errors.ts`) — because
 * that text is the plugin's entire input on every platform.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { Context } from '@deepseek-ai/cordis'
import systemPromptPlugin from '@deepseek-ai/dsh-system-prompt'
import toolsPlugin from '@deepseek-ai/dsh-tools'
import * as plugin from '../lib/index.js'

/** The exact failure three reports describe. */
const REPORTED = 'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'

/** How many tool bodies actually ran, per fixture name. */
const ran = new Map()

/** A body counter that survives a fixture being called through the pipeline. */
function count(toolName) {
  ran.set(toolName, (ran.get(toolName) ?? 0) + 1)
}

/** One registrable tool whose body returns a value. */
function okTool(toolName, value) {
  return {
    name: toolName,
    description: 'integration fixture',
    parameters: { type: 'object', properties: {} },
    output: { schema: { type: 'string' }, render: (_args, settled) => [{ type: 'text', text: settled }] },
    execute: () => {
      count(toolName)
      return Promise.resolve(value)
    },
  }
}

/** One registrable tool whose body always throws `message`. */
function failingTool(toolName, message) {
  return {
    name: toolName,
    description: 'always-failing integration fixture',
    parameters: { type: 'object', properties: {} },
    output: { schema: { type: 'string' }, render: (_args, settled) => [{ type: 'text', text: settled }] },
    execute: () => {
      count(toolName)
      return Promise.reject(new Error(message))
    },
  }
}

const signal = () => new AbortController().signal

/** One agent identity, memoized per id: the plugin keys its state on the object. */
const agents = new Map()
function who(id) {
  if (!agents.has(id)) agents.set(id, { id, session: { id } })
  return agents.get(id)
}

/**
 * Mount the real registry plus this plugin.
 * @param config - plugin config to forward; omitted → defaults.
 * @param fixtures - tool definitions to register after the plugin is mounted.
 * @returns the context, the captured log messages, and the tool names.
 */
async function world(config, fixtures) {
  ran.clear()
  const ctx = new Context()
  const logged = []
  // `levels.default` is the highest level an exporter admits (2 = WARN).
  ctx.logger.exporter({ levels: { default: 2 }, export: message => { logged.push(message) } })
  await ctx.plugin(systemPromptPlugin, {})
  await ctx.plugin(toolsPlugin)
  await ctx.plugin({ name: plugin.name, apply: c => { plugin.apply(c, config ?? {}) } })
  for (const fixture of fixtures) ctx.tools.register(fixture)
  return { ctx, logged }
}

/** Drive one call through the real pipeline. */
function call(ctx, toolName, args = {}, agent = who('s1')) {
  return ctx.tools.execute({ name: toolName, arguments: args, signal: signal(), agent })
}

/** The contexts one settled result carries. */
function contexts(result) {
  return result.additionalContexts ?? []
}

/** One settled result's text. */
function text(result) {
  return result.content.filter(block => block.type === 'text').map(block => block.text).join('\n')
}

/**
 * The captured log as one string.
 *
 * A message carries the format string plus its arguments, unformatted — the
 * exporter renders them — so the arguments are joined in too.
 */
function logText(logged) {
  return logged.map(message => message.args.map(value => String(value)).join(' ')).join('\n')
}

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
  assert.equal(ran.get('bash'), 5, 'the blocking half is off unless asked for')
})

test('the fail-fast half refuses an identical call it has watched fail, and only that', async () => {
  const { ctx } = await world({ enforceAfter: 2, maxDenials: 2 }, [failingTool('bash', REPORTED)])
  // Two real failures teach the plugin that this call, in this environment, cannot run.
  assert.equal((await call(ctx, 'bash', { command: 'ls' })).isError, true)
  assert.equal((await call(ctx, 'bash', { command: 'ls' })).isError, true)
  assert.equal(ran.get('bash'), 2)

  const blocked = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(blocked.isError, true)
  assert.equal(ran.get('bash'), 2, 'the refused call never reached the body')
  assert.match(text(blocked), /Blocked by sandbox-grant-advisor/)
  assert.match(text(blocked), /already failed 2 times/)
  assert.match(text(blocked), /automatic block 1 of 2/)

  // A different command is a different attempt: it is not the call we watched fail.
  const other = await call(ctx, 'bash', { command: 'pwd' })
  assert.equal(ran.get('bash'), 3, 'an untried call still reaches the body')

  // The budget is bounded: past it the identical call proceeds again.
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 2 of 2/)
  const allowed = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(ran.get('bash'), 4, 'the guard must never make a session unfinishable')
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
  let fail = true
  const flaky = {
    name: 'bash',
    description: 'fails until the environment is repaired',
    parameters: { type: 'object', properties: {} },
    output: { schema: { type: 'string' }, render: (_args, settled) => [{ type: 'text', text: settled }] },
    execute: () => {
      count('bash')
      return fail ? Promise.reject(new Error(REPORTED)) : Promise.resolve('ok')
    },
  }
  const { ctx } = await world({ enforceAfter: 2, maxDenials: 2 }, [flaky])
  await call(ctx, 'bash', { command: 'ls' })
  await call(ctx, 'bash', { command: 'ls' })
  // The budget is what lets a repaired environment be discovered at all: two
  // refusals, and then the very call under suspicion gets to run again.
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 1 of 2/)
  assert.match(text(await call(ctx, 'bash', { command: 'ls' })), /automatic block 2 of 2/)
  fail = false
  const success = await call(ctx, 'bash', { command: 'ls' })
  assert.equal(success.isError, false, 'a repaired environment must be allowed to proceed')
  fail = true
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
