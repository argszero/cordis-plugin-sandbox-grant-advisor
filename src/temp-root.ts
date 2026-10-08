/**
 * The pre-flight half of the temp-root family: whether a session is *already* in
 * the state that kills its command executor, decided before anything fails.
 *
 * The failure half of the family needs no policy lookup — the producer's sentence
 * carries both operands — and this module exists for the case where there is no
 * sentence yet: a `workspace-write` session whose workspace contains the temp root
 * will have its every command refused, and the model can be told that at the start
 * of the session instead of at the first `echo` (`#9175` asked for exactly this).
 *
 * ## What it computes, and why it is a re-implementation
 *
 * The predicate is the backend's own capability-disjointness check
 * (`packages/sandbox/sandbox-windows-acl/src/path-boundary.ts:11-16`): the
 * candidate lies at or under the root when `path.relative` of the two
 * `realpathSync.native` paths is empty, or is neither absolute nor `..`-prefixed.
 * It is mirrored rather than imported for the reason the plugin's other optional
 * integrations are: `@deepseek-ai/dsh-sandbox-windows-acl` is a Windows-only
 * package this plugin must not claim as a peer, and a *type-only* import would
 * turn an optional integration into a mandatory claim on every line the range
 * admits.
 *
 * Mirroring carries a drift risk that the failure half does not have, and it is
 * bounded on purpose: this module can only ever *stay silent* (a path that does
 * not resolve, a platform or mode it does not recognize, a rule that grew a third
 * operand upstream) or *predict the refusal the producer itself would have
 * made*. The sentence the producer writes — "temp root must be outside the
 * workspace" — is the rule this predicates, so a change to the rule changes the
 * text this plugin recognizes at the same moment.
 *
 * ## Why the comparison is canonical rather than textual
 *
 * A string prefix test would disagree with the executor in both directions: on
 * darwin `/tmp` and `/private/tmp` are one directory, and on Windows a
 * subst'd/case-differing spelling is one directory too. The whole value of a
 * pre-flight report is that it is the *same decision* the executor is about to
 * make, so it is the same computation — `realpathSync.native` on both operands,
 * which is also what makes a path that does not exist fail closed (the call
 * throws, and this module answers "no violation").
 *
 * @module
 */

import { realpathSync } from 'node:fs'
import { isAbsolute, relative, sep } from 'node:path'

/**
 * The one mode whose private temp capability makes the invariant matter.
 *
 * Not a policy the plugin could relax: `read-only` grants nothing and therefore
 * asserts nothing (the runner's `--mode read-only` branch passes the ambient temp
 * root through untouched), and `danger-full-access` spawns nothing through the
 * sandbox at all. So a violation of this predicate outside `workspace-write` is
 * not a prediction of anything, and the predicate refuses to make one.
 */
export const PREFLIGHT_MODE = 'workspace-write'

/**
 * Whether `candidate` is the same canonical directory as `root` or lives below it.
 *
 * Mirrors `containsDirectory` in the backend's `path-boundary.ts`, including its
 * choice of `realpathSync.native` — the implementation that follows the
 * filesystem's component-by-component lookup, so a symlinked prefix cannot make
 * this plugin and the executor disagree about the same pair of paths.
 * @param root - the canonical-or-resolvable workspace root.
 * @param candidate - the canonical-or-resolvable candidate.
 * @returns true when the candidate is the root itself or a descendant of it.
 * @throws when either path does not resolve — the caller answers "no violation".
 */
export function containsDirectory(root: string, candidate: string): boolean {
  const relation = relative(realpathSync.native(root), realpathSync.native(candidate))
  return relation === '' || (!isAbsolute(relation) && relation !== '..' && !relation.startsWith(`..${sep}`))
}

/**
 * The facts the pre-flight decision needs, all supplied rather than read.
 *
 * Every one of them is passed in for the reason the other families state: a gate
 * that trusts the shape of its input is the gate that reports a cause from the
 * wrong world. It is also what keeps the platform fact honest — a suite can only
 * exercise the Windows arm by *saying* the host is Windows, never by the plugin
 * quietly assuming it.
 */
export interface TempRootFacts {
  /** The host's `process.platform`, as the caller read it. */
  readonly platform: string
  /** The mode the policy resolver reported for this agent's session. */
  readonly mode: string
  /** The workspace root the policy resolver reported. */
  readonly workspaceRoot: string
  /** The temp root the executor will use (`os.tmpdir()`), as the caller read it. */
  readonly tempRoot: string
}

/**
 * Whether this session is already in the state that will refuse every command.
 *
 * Three facts, in the order that costs least: a host that is not Windows (the
 * mechanism is a Windows ACL capability pair, and only that platform has a
 * chain entry for the backend), a mode whose private temp capability exists, and
 * finally the containment the executor itself performs. Anything that cannot be
 * computed — a path that does not resolve — answers "no violation", which is the
 * fail-closed direction for a *prediction*: the failure half of the family is
 * still there to speak when the refusal actually happens.
 * @param facts - the host, the resolved policy, and the temp root.
 * @returns true when a `workspace-write` command will be refused before it runs.
 */
export function tempRootInsideWorkspace(facts: TempRootFacts): boolean {
  if (facts.platform !== 'win32') return false
  if (facts.mode !== PREFLIGHT_MODE) return false
  try {
    return containsDirectory(facts.workspaceRoot, facts.tempRoot)
  } catch {
    // An unresolvable path is not evidence of anything: stay silent rather than
    // predict a refusal from a comparison that could not be made.
    return false
  }
}
