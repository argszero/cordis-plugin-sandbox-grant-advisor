/**
 * Which sandbox mode a call ran under, and whether that mode confines.
 *
 * The persistent-shell diagnosis is only true under a **confining** mode. The
 * terminal backend hands the shell argv straight through when the resolved mode
 * is `danger-full-access` and confines it otherwise
 * (`packages/terminal/terminal-bash/src/index.ts`:
 * `if (policy.mode === 'danger-full-access') return argv`), so the same
 * `PTY shell exited during startup` under `danger-full-access` is a different
 * story — a broken or missing shell — and this plugin must stay silent about it
 * rather than assert a sandbox cause it cannot support. The report that frames
 * this family (#7638) says the same thing from the other side: its author's
 * three-arm control shows the mode is the discriminator (minimal × confining
 * fails, minimal × `danger-full-access` succeeds, standard × confining
 * succeeds).
 *
 * The answer is taken from `ctx.sandboxPolicy.resolve({ session })` — the same
 * resolver the terminal layer itself calls before spawning, with the same
 * session — so what is quoted in the advisory is the policy that actually
 * governed the failing call, not a guess reconstructed from configuration.
 *
 * ## Why this is a guarded lookup instead of an import
 *
 * `@deepseek-ai/dsh-sandbox-policy` is **optional** in this plugin's world: a
 * composition may simply not mount the service, and this plugin must degrade to
 * silence rather than fail to load. Two consequences shape this module:
 *
 * - A declared peer dependency is a claim about versions, and this package's
 *   packaging guard refuses both an import that is not declared and a
 *   declaration that is not imported. A *type-only* import would therefore turn
 *   an optional integration into a mandatory claim on every line the peer range
 *   admits — and a range that admits a line nobody ran is exactly the defect
 *   that guard exists to prevent.
 * - What is left is the consumer-side capability guard: look the service up,
 *   check the shape of the answer instead of trusting it, and **fail closed**
 *   (`{ ok: false }`): an unresolvable mode withholds the advisory, and the
 *   caller discloses that withholding on the host side. An unresolvable mode is
 *   emphatically *not* an invitation to fall back to the deployment default —
 *   a session that overrode its mode to `danger-full-access` would then be
 *   diagnosed as if it were confined.
 *
 * The call site this module depends on is stable across every line the peer
 * range claims: `resolve(request?: SandboxPolicyRequest): SandboxExecutionPolicy`
 * is declared at the same position of `lib/types/index.d.ts` in every published
 * build from `0.1.2-rc.1` to `0.1.7-rc.1`, and `Agent.session` is present on
 * the same span of `@deepseek-ai/dsh-agent`.
 *
 * @module
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'

/** The three modes the harness resolves. */
export type SandboxModeName = 'read-only' | 'workspace-write' | 'danger-full-access'

/**
 * Whether a mode confines the process it is asked to spawn.
 * @param mode - the resolved mode.
 * @returns true for every mode except `danger-full-access`.
 */
export function confines(mode: SandboxModeName): boolean {
  return mode !== 'danger-full-access'
}

/** The outcome of resolving one agent's effective sandbox mode. */
export type ModeResolution =
  /**
   * The mode the failing call ran under. `danger-full-access` is reported too:
   * it is a real answer, and the caller's job (not this module's) is to decide
   * that a non-confining mode is not this plugin's story.
   */
  | { readonly ok: true, readonly mode: SandboxModeName }
  /** No answer was available, and why — the host side says so out loud. */
  | { readonly ok: false, readonly withheld: string }

/** The `resolve` face this module consumes, structurally. */
interface PolicyLike {
  resolve(request: { session: object }): unknown
}

/**
 * Narrow an optional lookup result to the resolver shape.
 * @param value - whatever `ctx.get('sandboxPolicy')` returned.
 * @returns the same object, typed as the resolver, or undefined.
 */
function asPolicy(value: unknown): PolicyLike | undefined {
  if (value === null || typeof value !== 'object') return undefined
  if (typeof (value as { resolve?: unknown }).resolve !== 'function') return undefined
  return value as PolicyLike
}

/**
 * The agent's live session, read defensively.
 *
 * `Agent.session` is declared by `@deepseek-ai/dsh-agent`'s runtime face and is
 * present on every claimed line; it is read as `unknown` here anyway, because a
 * gate that trusts the shape of its input is the same gate that reports a cause
 * from the wrong world when the input is not what it expected.
 * @param agent - the agent whose call failed.
 * @returns the session object, or undefined.
 */
function agentSession(agent: Agent): object | undefined {
  const session = (agent as { session?: unknown }).session
  return session !== null && typeof session === 'object' ? session : undefined
}

/**
 * The mode inside a resolved policy, if it is one this harness defines.
 * @param resolved - the resolver's return value.
 * @returns the mode, or undefined when the value is not a recognizable policy.
 */
function recognizedMode(resolved: unknown): SandboxModeName | undefined {
  if (resolved === null || typeof resolved !== 'object') return undefined
  const mode = (resolved as { mode?: unknown }).mode
  return mode === 'read-only' || mode === 'workspace-write' || mode === 'danger-full-access'
    ? mode
    : undefined
}

/**
 * Resolve the effective sandbox mode for one agent's call.
 *
 * The service is looked up through `ctx.get` — the documented optional lookup —
 * and the resolver is invoked with the agent's own session, so a session that
 * logged a `sandbox/mode` override is answered with that override rather than
 * with the deployment default.
 * @param ctx - the plugin's context.
 * @param agent - the agent whose call failed.
 * @returns the mode, or the reason it could not be resolved.
 */
export function resolveSandboxMode(ctx: Context, agent: Agent): ModeResolution {
  const policy = asPolicy(ctx.get('sandboxPolicy'))
  if (policy === undefined) {
    return {
      ok: false,
      withheld: 'no `sandboxPolicy` service is mounted in this composition, so the effective mode is unknown',
    }
  }
  const session = agentSession(agent)
  if (session === undefined) {
    return {
      ok: false,
      withheld: 'the agent exposes no session, and the policy must be resolved from it rather than from the deployment default',
    }
  }
  let resolved: unknown
  try {
    resolved = policy.resolve({ session })
  } catch (error: unknown) {
    return { ok: false, withheld: `\`sandboxPolicy.resolve\` threw (${String(error)})` }
  }
  const mode = recognizedMode(resolved)
  if (mode === undefined) {
    return { ok: false, withheld: '`sandboxPolicy.resolve` returned a value without a recognizable mode' }
  }
  return { ok: true, mode }
}
