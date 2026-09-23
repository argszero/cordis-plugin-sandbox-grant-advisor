/**
 * The integration harness both behavior suites mount the plugin on: a REAL
 * cordis context, the REAL `dsh-tools` ToolRuntime, registrable fixtures, and
 * the real `tools/pre-execute` / `tools/post-execute` waterfalls.
 *
 * What this shape proves that a unit arm cannot: the listeners are wired to the
 * seam, an advisory really rides `additionalContexts` on the settled result
 * (the channel the agent loop turns into a durable user-role message), and a
 * denial really stops the tool body from running.
 *
 * What it cannot prove, and does not claim: the Windows ACL path or the Windows
 * PTY path themselves. The fixtures throw the producers' exact error text —
 * taken from `Win32Error`
 * (`packages/subprocess/win32-process/src/errors.ts`) and from
 * `dsh-terminal-bash`'s `session.ts` / `index.ts` — because that text is the
 * plugin's entire input on every platform.
 *
 * The sandbox-policy stand-in is deliberately not the real service: the point
 * of `sandboxPolicy` in these suites is that its *answer* is what the plugin
 * gates on, so what the stub returns (a mode, a malformed value, or a throw) is
 * the variable under test. It records every request so a suite can assert which
 * session the plugin resolved for.
 */

import { Context } from '@deepseek-ai/cordis'
import systemPromptPlugin from '@deepseek-ai/dsh-system-prompt'
import toolsPlugin from '@deepseek-ai/dsh-tools'
import * as plugin from '../lib/index.js'

/** The exact ACL failure three reports describe (#7538 / #7622 / #7646). */
export const REPORTED = 'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'

/** The exact persistent-shell failure #7638 reports. */
export const PTY_EXIT = 'PTY shell exited during startup'

/** How many tool bodies actually ran, per fixture name. */
const ran = new Map()

/** A body counter that survives a fixture being called through the pipeline. */
export function count(toolName) {
  ran.set(toolName, (ran.get(toolName) ?? 0) + 1)
}

/** How many times one fixture's body ran since the last `world()`. */
export function runs(toolName) {
  return ran.get(toolName) ?? 0
}

/** One registrable tool whose body returns a value. */
export function okTool(toolName, value) {
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
export function failingTool(toolName, message) {
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

/** One registrable tool whose body succeeds until told otherwise. */
export function flakyTool(toolName, message) {
  const state = { fail: true }
  return {
    state,
    definition: {
      name: toolName,
      description: 'fails until the environment is repaired',
      parameters: { type: 'object', properties: {} },
      output: { schema: { type: 'string' }, render: (_args, settled) => [{ type: 'text', text: settled }] },
      execute: () => {
        count(toolName)
        return state.fail ? Promise.reject(new Error(message)) : Promise.resolve('ok')
      },
    },
  }
}

/** A fresh abort signal per call, as the tool pipeline expects. */
export const signal = () => new AbortController().signal

/** One agent identity, memoized per id: the plugin keys its state on the object. */
const agents = new Map()
export function who(id) {
  if (!agents.has(id)) agents.set(id, { id, session: { id } })
  return agents.get(id)
}

/** One agent identity that exposes no session, for the fail-closed arm. */
export function whoWithoutSession(id) {
  const key = `${id}:no-session`
  if (!agents.has(key)) agents.set(key, { id })
  return agents.get(key)
}

/**
 * A `sandboxPolicy` stand-in.
 *
 * Shaped like the real service where it matters — `resolve({ session })`
 * returns a policy carrying the mode — and unlike it everywhere else, so a
 * suite can make it lie, throw, or hand back a value that is not a policy.
 * @param mode - the mode `resolve` reports.
 * @param options - `calls` collects every request; `resolve` replaces the answer.
 * @returns the stand-in service.
 */
export function sandboxPolicy(mode, options = {}) {
  const calls = options.calls ?? []
  return {
    calls,
    resolve: options.resolve ?? (request => {
      calls.push(request)
      return { mode }
    }),
  }
}

/**
 * Mount the real registry, the optional policy stand-in, and this plugin.
 * @param config - plugin config to forward; omitted → defaults.
 * @param fixtures - tool definitions to register after the plugin is mounted.
 * @param options - `policy` mounts a `sandboxPolicy` service; omit to leave it
 * unmounted, which is its own arm.
 * @returns the context and the captured log messages.
 */
export async function world(config, fixtures = [], options = {}) {
  ran.clear()
  const ctx = new Context()
  const logged = []
  // `levels.default` is the highest level an exporter admits (2 = WARN).
  ctx.logger.exporter({ levels: { default: 2 }, export: message => { logged.push(message) } })
  await ctx.plugin(systemPromptPlugin, {})
  await ctx.plugin(toolsPlugin)
  if (options.policy !== undefined) {
    // Provided from a fiber, so the service's lifetime is the test's and the
    // lookup under test is genuinely the optional `ctx.get` path.
    await ctx.plugin({ name: 'sandbox-policy-stand-in', apply: c => { c.provide('sandboxPolicy', options.policy) } })
  }
  await ctx.plugin({ name: plugin.name, apply: c => { plugin.apply(c, config ?? {}) } })
  for (const fixture of fixtures) ctx.tools.register(fixture)
  return { ctx, logged }
}

/** Drive one call through the real pipeline. */
export function call(ctx, toolName, args = {}, agent = who('s1')) {
  return ctx.tools.execute({ name: toolName, arguments: args, signal: signal(), agent })
}

/** The contexts one settled result carries. */
export function contexts(result) {
  return result.additionalContexts ?? []
}

/** One settled result's text. */
export function text(result) {
  return result.content.filter(block => block.type === 'text').map(block => block.text).join('\n')
}

/**
 * The captured log as one string.
 *
 * A message carries the format string plus its arguments, unformatted — the
 * exporter renders them — so the arguments are joined in too.
 */
export function logText(logged) {
  return logged.map(message => message.args.map(value => String(value)).join(' ')).join('\n')
}

/**
 * The captured log lines that mention one phrase.
 * @param logged - the array `world()` returned.
 * @param needle - the substring a line must contain.
 * @returns the matching lines, in order.
 */
export function logLines(logged, needle) {
  return logText(logged).split('\n').filter(line => line.includes(needle))
}
