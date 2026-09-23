/**
 * `sandbox-grant-advisor`: turn a Windows ACL provisioning failure that has no
 * path forward into a diagnosis the model — and the user reading the
 * transcript — can act on.
 *
 * Three reports of one signature (`#7538`, `#7622`, `#7646`) describe the same
 * shape: the host-side write grant for a sandboxed workspace cannot be applied,
 * every sandboxed command then fails identically **before it runs**, and the
 * error text is a bare Win32 line:
 *
 *   SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)
 *
 * The grant is materialized lazily on the first confined call and nothing is
 * cached when it throws, so the failure repeats per command rather than once
 * (850 calls / 39 sessions in `#7622`; 52,588 output tokens with no output in
 * `#7538`). The `workspace-write` policy is simply unusable in such a
 * workspace, and the remedy the backend documents — the directory must grant
 * the caller `WRITE_OWNER` — never reaches the user, so sessions escape into
 * `danger-full-access` or die on the model's output cap.
 *
 * ## Where it acts, and why there
 *
 * One listener on the public `tools/post-execute` waterfall
 * (`@deepseek-ai/dsh-tools`). Admissibility was decided by which half of the
 * defect this seam can reach: the failure text (the provider propagates its
 * error unchanged, and the tool pipeline turns it into an `isError` result), an
 * agent identity to attribute it to (`exec.agent`), and a channel that speaks
 * to the model in the same step (`PostToolDecision`'s `additionalContexts`,
 * a durable user-role message).
 *
 * `ctx.sandbox.confine(argv, policy, signal)` sees the failure too, and cannot
 * do this: its signature carries no agent, so a wrapper could detect the
 * condition and never deliver a word about it to the session that is stuck.
 *
 * ## What it does
 *
 * 1. **One durable advisory per agent.** On the first recognized provisioning
 *    failure, the failing tool result is enriched with a user-role notice that
 *    names the missing right (`WRITE_OWNER` on the directory, not
 *    `SeSecurityPrivilege`), gives the unelevated one-line `icacls` remedy, and
 *    gives the discriminator that separates a Modify-only directory from a
 *    wrong prerequisite. Attached through `additionalContexts`, so the model
 *    sees it beside the failure rather than only in a log the model never reads.
 * 2. **An optional bounded fail-fast.** With `enforceAfter` set, a call this
 *    plugin has *watched fail* this way is refused at `tools/pre-execute` once
 *    the environment has failed at least that many times. It is off by default:
 *    the useful signal here is the diagnosis, and a plugin that blocks command
 *    execution for a reason it merely recognizes is a risk, not a feature. See
 *    the README for why the blocking half is deliberately narrow.
 *
 * ## Honest boundaries
 *
 * - **The Windows path cannot be witnessed on macOS**, where this plugin was
 *   built and tested. What is tested is the decision layer: classification,
 *   once-per-agent delivery, the fail-fast budget, and the wiring to the real
 *   `ToolRuntime` — against synthetic results carrying the producer's exact
 *   error shape, with the format taken from
 *   `packages/subprocess/win32-process/src/errors.ts`.
 * - **It does not repair anything.** No ACL is written, no privilege is
 *   requested, nothing is elevated: the `icacls` line is the user's to run.
 * - **It complements, rather than replaces, `repeat-guard-escalation`.** That
 *   guard keys on *call identity* (identical arguments retried); this one keys
 *   on the *environment signature*, which is how several different commands can
 *   share one cause. They can be mounted together.
 * - **The real fix is upstream**: the failure should name the outstanding
 *   condition at the site that knows it (`grantWrite` computes
 *   `hasExactGrant`/`hasExactDeny`/`hasExactLabel` and discards which was
 *   false). This plugin is the stopgap.
 *
 * @module @argszero/cordis-plugin-sandbox-grant-advisor
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import type { UserMessage } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { advisoryText, denialText, DISCUSSIONS } from './advice.js'
import { classifyProvisioningFailure } from './signature.js'
import type { ProvisioningFailure } from './signature.js'
import { callKey, observe, observeSuccess, recordAdvice, recordDenial, shouldDeny } from './state.js'
import type { AgentState } from './state.js'

export const name = 'sandbox-grant-advisor'

/** The tool pipeline this plugin observes and (optionally) gates. */
export const inject = ['tools']

/**
 * The producer kind every message this plugin writes carries.
 *
 * It is deliberately its own kind rather than the retired `plugin` wrapper: the
 * current session format admits only a producer-owned kind — a message whose
 * `source.kind` is the string `plugin` is refused on the way in
 * (`packages/session/session-format-v3-to-v4/src/message-sources.ts`) — and the
 * source union is documented as merge-extensible, one kind per producer.
 */
export const SOURCE_KIND = 'sandbox-grant-advisor'

/** Default fail-fast threshold: 0, i.e. the blocking half is off. */
export const DEFAULT_ENFORCE_AFTER = 0

/** Default denial budget once the blocking half is enabled. */
export const DEFAULT_MAX_DENIALS = 2

/** Configures what is watched and whether the blocking half runs. */
export interface Config {
  /**
   * Provisioning failures after which an identical, already-failing call is
   * denied before dispatch. `0` (the default) disables the half entirely; the
   * advisory half is unaffected and always on.
   */
  enforceAfter?: number
  /**
   * How many denials one agent may spend. Defaults to 2. Bounded on purpose:
   * an unbounded refusal turns a stuck session into an unfinishable one.
   */
  maxDenials?: number
  /** Tool-name wildcard patterns to watch; empty means every tool. */
  include?: string[]
  /** Tool-name wildcard patterns never watched. */
  exclude?: string[]
  /** URL quoted in the advisory as the upstream thread; optional. */
  href?: string
}

/** Compile one `*`-wildcard pattern to an anchored RegExp; all else is literal. */
function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, String.raw`\$&`)
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`)
}

/**
 * Validate a count-like option fail-loud, so a typo cannot silently disable the
 * blocking half the operator asked for.
 * @param label - the option name, for the message.
 * @param value - the resolved value.
 * @param minimum - the smallest legal value.
 * @returns the value, once validated.
 */
function integerAtLeast(label: string, value: number | undefined, minimum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new Error(`sandbox-grant-advisor: \`${label}\` must be an integer >= ${minimum} (got ${String(value)})`)
  }
  return value as number
}

/**
 * The plain text of a failed result, from the authoritative field first.
 *
 * `error.message` is what the producing layer recorded and survives content
 * rewriting by other post-execute listeners; the rendered text is the fallback,
 * so a result whose content was replaced (spill policies, hooks) is still
 * classified from its message.
 * @param result - the failed tool result.
 * @returns the text to classify.
 */
function failureText(result: Extract<ToolExecutionResult, { isError: true }>): string {
  const rendered = result.content
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('\n')
  return result.error.message.length > 0 ? `${result.error.message}\n${rendered}` : rendered
}

/**
 * The one-line host-side account of a recognized failure.
 * @param failure - the recognized failure.
 * @returns a single log line.
 */
function hostLine(failure: ProvisioningFailure): string {
  const where = failure.detail.length === 0 ? '' : ` at ${failure.detail}`
  return `sandbox-grant-advisor: workspace ACL provisioning failed (${failure.api} Win32 `
    + `${String(failure.win32Code)})${where} — sandboxed commands will keep failing until the directory grants `
    + `this account Full control; advisory delivered to the model (discussions ${DISCUSSIONS})`
}

/**
 * Wrap one notice as a user-role message.
 *
 * The double cast encodes a documented fact the installed type cannot express:
 * the message source union is **merge-extensible** — "each producer declares its
 * own `kind` in its own module; there is no shared catch-all `plugin` kind", and
 * "consumers fall through unknown kinds" — while the union shipped in the peer
 * package is a closed list written before this producer existed. A plugin cannot
 * augment an interface it does not own, and the session format admits any
 * non-empty kind except the retired `plugin` wrapper
 * (`packages/session/session-format-v3-to-v4/src/message-sources.ts`), which is
 * asserted by `test/plugin.spec.mjs` against the message this function returns.
 * @param text - the notice body.
 * @param summary - one-line account for the transcript row.
 * @returns the message, identified and frozen by the harness factory.
 */
function notice(text: string, summary: string): UserMessage {
  return createUserMessage({
    content: [{ type: 'text', text }],
    source: {
      kind: SOURCE_KIND,
      form: 'notice',
      summary: boundContextSummary(summary),
    } as unknown as UserMessage['source'],
  })
}

/** Keep this plugin's notices ahead of any other context on the same result. */
function prepend(ours: UserMessage, theirs: readonly UserMessage[] | undefined): UserMessage[] {
  return [ours, ...theirs ?? []]
}

/**
 * Install the advisor.
 * @param ctx - context carrying the tool pipeline.
 * @param config - resolved options; validated fail-loud here.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const enforceAfter = integerAtLeast('enforceAfter', config.enforceAfter ?? DEFAULT_ENFORCE_AFTER, 0)
  const maxDenials = integerAtLeast('maxDenials', config.maxDenials ?? DEFAULT_MAX_DENIALS, 1)
  const includePatterns = (config.include ?? []).map(wildcardToRegExp)
  const excludePatterns = (config.exclude ?? []).map(wildcardToRegExp)
  const href = config.href

  /** One state per agent; a WeakMap keeps a finished agent's state collectable. */
  const states = new WeakMap<Agent, AgentState>()

  /**
   * The executions this plugin denied, so the post-execute listener never reads
   * its own denial as an environment failure. A denial's text quotes the Win32
   * line on purpose (that is what the model must see), which makes it
   * indistinguishable from the real thing by content alone — the identity of
   * the execution object, shared by reference across both seams, is what
   * separates them.
   */
  const ownDenials = new WeakSet<object>()

  /** Whether a tool participates; untracked calls are transparent. */
  function tracked(toolName: string): boolean {
    if (includePatterns.length > 0 && !includePatterns.some(pattern => pattern.test(toolName))) return false
    return !excludePatterns.some(pattern => pattern.test(toolName))
  }

  /**
   * Read one settled call: advance the state, and decide whether it is the
   * failure the model needs told about.
   * @param exec - the call that just ran.
   * @param result - its settled outcome.
   * @returns the notice to attach, or undefined.
   */
  function inspect(exec: ToolExecution, result: ToolExecutionResult): UserMessage | undefined {
    const agent = exec.agent
    if (agent === undefined || !tracked(exec.name)) return undefined
    if (ownDenials.has(exec)) {
      ownDenials.delete(exec)
      return undefined
    }
    const key = callKey(exec.name, exec.arguments)
    const previous = states.get(agent)
    if (result.isError !== true) {
      if (previous !== undefined) states.set(agent, observeSuccess(previous, key))
      return undefined
    }
    const failure = classifyProvisioningFailure(failureText(result))
    if (failure === undefined) return undefined
    const advanced = observe(previous, failure, key)
    if (advanced.advised) {
      states.set(agent, advanced)
      return undefined
    }
    states.set(agent, recordAdvice(advanced))
    ctx.logger.warn(hostLine(failure))
    return notice(
      advisoryText(failure, href),
      `workspace ACL provisioning failed (Win32 ${String(failure.win32Code)})`,
    )
  }

  // Observe-and-enrich, never veto by itself: delegate first, then fold this
  // plugin's notice onto whatever came back. `additionalContexts` rides both
  // decision variants, so a result another listener blocked still carries the
  // diagnosis.
  ctx.on('tools/post-execute', async (exec, result, next): Promise<PostToolDecision> => {
    let message: UserMessage | undefined
    try {
      message = inspect(exec, result)
    } catch (error: unknown) {
      // A broken advisor must not become a broken tool call.
      ctx.logger.warn(`sandbox-grant-advisor: result left alone after internal error: ${String(error)}`)
    }
    const downstream = await next()
    if (message === undefined) return downstream
    if (downstream.kind === 'block') {
      return {
        kind: 'block',
        feedback: downstream.feedback,
        additionalContexts: prepend(message, downstream.additionalContexts),
      }
    }
    return { ...downstream, additionalContexts: prepend(message, downstream.additionalContexts) }
  })

  // The optional blocking half. Registered only when asked for: with the default
  // `enforceAfter: 0` this plugin never sits in a waterfall it can veto from.
  if (enforceAfter === 0) return

  ctx.on('tools/pre-execute', (exec, next): Promise<PreToolDecision> => {
    try {
      const agent = exec.agent
      if (agent === undefined || !tracked(exec.name)) return next()
      const state = states.get(agent)
      if (!shouldDeny(state, callKey(exec.name, exec.arguments), enforceAfter, maxDenials)) return next()
      if (state === undefined) return next()
      // Tag before delegating, and spend the budget immediately: the denial must
      // be accounted for even if a later listener replaces this decision.
      ownDenials.add(exec)
      states.set(agent, recordDenial(state))
      return Promise.resolve({
        kind: 'deny',
        reason: denialText(state.last, state.observations, state.denials + 1, maxDenials),
      })
    } catch (error: unknown) {
      ctx.logger.warn(`sandbox-grant-advisor: call allowed after internal error: ${String(error)}`)
      return next()
    }
  })
}
