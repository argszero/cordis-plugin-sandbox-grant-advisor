/**
 * Per-agent bookkeeping: what this environment has already been told, and (in
 * the optional fail-fast half) which calls have already been refused by it.
 *
 * The state is deliberately keyed by **agent**, not by session id string: the
 * failing call carries `exec.agent`, one agent owns one session, and a WeakMap
 * keyed by the agent object lets a finished session's state be collected.
 *
 * Two counters, two meanings — keeping them apart is what stops the plugin from
 * feeding on itself:
 *
 * - `observations` counts *provisioning failures of this environment*, i.e.
 *   tool results the environment itself produced. A call this plugin denied is
 *   not one of them, even though its denial text quotes the Win32 line.
 * - `failingKeys` holds the call identities (tool + canonical arguments) that
 *   have already failed this way. The fail-fast half may only refuse a call it
 *   has *watched fail* — never a call it merely recognizes as similar.
 *
 * `denials` is spent per *episode*: it is re-armed when a watched call finally
 * succeeds (see `observeSuccess`), not carried for the whole session.
 *
 * @module
 */

import type { ProvisioningFailure } from './signature.js'

/** Everything the plugin remembers about one agent. */
export interface AgentState {
  /** Provisioning failures observed for this agent. */
  observations: number
  /** The most recent failure, for the denial text. */
  last: ProvisioningFailure
  /** Identity keys of the calls that failed this way. */
  failingKeys: Set<string>
  /** Denials already spent. */
  denials: number
  /** Whether the durable advisory has been delivered for this agent. */
  advised: boolean
}

/**
 * Canonicalize a parsed argument value into a stable string.
 *
 * Key order in a JavaScript object is insertion order, so two structurally
 * identical calls can serialize differently depending on how the model ordered
 * its JSON. Sorting keys recursively gives the identity the fail-fast half
 * needs; unsupported values (functions, symbols, cycles) fall back to a type
 * tag rather than throwing, because a guard must never be the reason a call
 * dies.
 * @param value - the parsed tool arguments.
 * @returns a stable string.
 */
export function canonicalize(value: unknown): string {
  const seen = new WeakSet<object>()
  const walk = (node: unknown, depth: number): unknown => {
    if (depth > 32) return '<depth>'
    if (node === null || typeof node !== 'object') {
      return typeof node === 'bigint' ? `${node.toString()}n` : node
    }
    if (seen.has(node)) return '<cycle>'
    seen.add(node)
    if (Array.isArray(node)) return node.map(item => walk(item, depth + 1))
    const entries = Object.entries(node as Record<string, unknown>)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => [key, walk(item, depth + 1)])
    return Object.fromEntries(entries)
  }
  return JSON.stringify(walk(value, 0)) ?? '<unserializable>'
}

/**
 * The identity of one call: its tool name plus its canonical arguments.
 * @param name - the tool name.
 * @param args - the parsed arguments.
 * @returns the identity key.
 */
export function callKey(name: string, args: unknown): string {
  return `${name}(${canonicalize(args)})`
}

/**
 * Record one observed provisioning failure.
 * @param state - the agent's current state, or undefined on first sight.
 * @param failure - the recognized failure.
 * @param key - the identity of the call that failed.
 * @returns the updated state.
 */
export function observe(state: AgentState | undefined, failure: ProvisioningFailure, key: string): AgentState {
  const failingKeys = new Set(state?.failingKeys ?? [])
  failingKeys.add(key)
  return {
    observations: (state?.observations ?? 0) + 1,
    last: failure,
    failingKeys,
    denials: state?.denials ?? 0,
    advised: state?.advised ?? false,
  }
}

/**
 * Record that a call carrying the same identity as a previously failing one
 * succeeded. The environment worked at least once for that call, so the entry
 * stops justifying a denial — and is dropped rather than kept, so a later
 * failure re-earns it.
 *
 * The denial budget is re-armed at the same moment, and only then. Measured
 * consequence: without it the budget is per agent for the whole session, which
 * makes the entry above unobservable — past `maxDenials` this plugin refuses
 * nothing ever again, so clearing the key would change no decision. With it the
 * bound reads as "at most `maxDenials` refusals per episode of brokenness": an
 * environment that breaks, is repaired and breaks again may be refused again,
 * while a session can always make progress by spending the budget.
 * @param state - the agent's current state.
 * @param key - the identity of the call that just succeeded.
 * @returns the updated state, unchanged when the key was not failing.
 */
export function observeSuccess(state: AgentState, key: string): AgentState {
  if (!state.failingKeys.has(key)) return state
  const failingKeys = new Set(state.failingKeys)
  failingKeys.delete(key)
  return { ...state, failingKeys, denials: 0 }
}

/**
 * Whether a call may be refused before dispatch.
 *
 * Both conditions are required: the environment has failed provisioning at
 * least `enforceAfter` times, **and** this exact call is one this plugin watched
 * fail. The second condition is what keeps the fail-fast half from blocking a
 * workaround: a different command, or the same command under a different policy
 * after the user changed configuration, has no key here.
 * @param state - the agent's current state, or undefined.
 * @param key - the identity of the call about to dispatch.
 * @param enforceAfter - the configured threshold; 0 disables the half entirely.
 * @param maxDenials - the configured denial budget.
 * @returns whether to deny.
 */
export function shouldDeny(
  state: AgentState | undefined,
  key: string,
  enforceAfter: number,
  maxDenials: number,
): boolean {
  if (enforceAfter === 0 || state === undefined) return false
  if (state.observations < enforceAfter) return false
  if (state.denials >= maxDenials) return false
  return state.failingKeys.has(key)
}

/**
 * Spend one denial.
 * @param state - the agent's current state.
 * @returns the updated state.
 */
export function recordDenial(state: AgentState): AgentState {
  return { ...state, denials: state.denials + 1 }
}

/**
 * Mark the durable advisory as delivered.
 * @param state - the agent's current state.
 * @returns the updated state.
 */
export function recordAdvice(state: AgentState): AgentState {
  return { ...state, advised: true }
}
