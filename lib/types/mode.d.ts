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
 * The same lookup answers the **workspace root** for the fourth family
 * (`workspace-denial`, #423), whose claim is that the path a denied command
 * named lies inside the session's own workspace. Same request, same fail-closed
 * posture, separate function ({@link resolveWorkspaceRoot}), so that neither
 * family can fail on a field it never reads and each can name the failure in its
 * own words.
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
import type { Context } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
/** The three modes the harness resolves. */
export type SandboxModeName = 'read-only' | 'workspace-write' | 'danger-full-access';
/**
 * Whether a mode confines the process it is asked to spawn.
 * @param mode - the resolved mode.
 * @returns true for every mode except `danger-full-access`.
 */
export declare function confines(mode: SandboxModeName): boolean;
/** The outcome of resolving one agent's effective sandbox mode. */
export type ModeResolution = 
/**
 * The mode the failing call ran under. `danger-full-access` is reported too:
 * it is a real answer, and the caller's job (not this module's) is to decide
 * that a non-confining mode is not this plugin's story.
 */
{
    readonly ok: true;
    readonly mode: SandboxModeName;
}
/** No answer was available, and why — the host side says so out loud. */
 | {
    readonly ok: false;
    readonly withheld: string;
};
/** The outcome of resolving one agent's workspace root. */
export type RootResolution = 
/** The workspace root the enforcing providers were handed. */
{
    readonly ok: true;
    readonly workspaceRoot: string;
}
/** No answer was available, and why — the host side says so out loud. */
 | {
    readonly ok: false;
    readonly withheld: string;
};
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
export declare function resolveSandboxMode(ctx: Context, agent: Agent): ModeResolution;
/**
 * The workspace root the policy resolver reports for one agent's call.
 *
 * The same lookup, the same request and the same fail-closed posture as
 * {@link resolveSandboxMode}, and for the same reason: the root is what the
 * enforcing providers were handed, so it is the value the workspace-denial
 * family must test containment against rather than one reconstructed from
 * configuration. The two are separate functions rather than one that returns
 * both because each family needs one of them, and a family that needs only the
 * mode must not be able to fail on a missing root (nor the other way round).
 * @param ctx - the plugin's context.
 * @param agent - the agent whose call failed.
 * @returns the root, or the reason it could not be resolved.
 */
export declare function resolveWorkspaceRoot(ctx: Context, agent: Agent): RootResolution;
