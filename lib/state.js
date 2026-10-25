/**
 * Per-agent bookkeeping: what this environment has already been told, and (in
 * the optional fail-fast half) which calls have already been refused by it.
 *
 * The state is deliberately keyed by **agent**, not by session id string: the
 * failing call carries `exec.agent`, one agent owns one session, and a WeakMap
 * keyed by the agent object lets a finished session's state be collected.
 *
 * ## One record per family
 *
 * This plugin recognizes five unrelated environment failures — a workspace
 * that cannot be provisioned (`acl-provisioning`), a persistent shell that
 * cannot start (`pty-startup`), a confined Windows child that died during
 * native initialization (`native-init`), a confined command denied a path inside
 * its own workspace (`workspace-denial`), and a sandbox whose private temp root
 * lies inside the workspace it grants against (`temp-root-inside-workspace`).
 * They are different diagnoses with
 * different remedies, so their bookkeeping is kept apart under one agent
 * ({@link AgentState.families}): an agent that hits both is told about both,
 * and an agent that has already been told about one is still told about the
 * other. Sharing one "already advised" flag would silently swallow the second
 * diagnosis, which is the failure mode this split exists to prevent.
 *
 * ## One seat outside the families
 *
 * The temp-root family is the one whose condition is observable **before** it
 * fails — it is a standing fact about two directories, not an event — so that
 * family has a second, pre-flight report of its own, tracked by
 * {@link AgentState.standing} rather than by a family record: it exists to be
 * delivered once *ahead* of any failure, while the family record still gets to
 * speak if the refusal actually happens. The two are deliberately not one seat.
 * A single flag would make the more informative report — the producer's own
 * line, and which of its two carriers refused — unreachable in exactly the
 * sessions that had already been warned, which is the opposite of what a
 * prediction is for. The verdict is memoized on the first tracked call so a
 * host that is *not* in that state pays for the lookup once and never again.
 *
 * Three counters, three meanings — keeping them apart is what stops the plugin
 * from feeding on itself:
 *
 * - `observations` counts *failures of this environment in this family*, i.e.
 *   tool results the environment itself produced. A call this plugin denied is
 *   not one of them, even though its denial text quotes the producer's line.
 * - `failingKeys` holds the call identities (tool + canonical arguments) that
 *   have already failed this way. The fail-fast half may only refuse a call it
 *   has *watched fail* — never a call it merely recognizes as similar.
 * - `denials` is spent per *episode*: it is re-armed when a watched call finally
 *   succeeds (see `observeSuccess`), not carried for the whole session.
 *
 * @module
 */
/** The state of an agent this plugin has never observed. */
export function emptyState() {
    return { families: {}, withheld: false, standing: 'pending' };
}
/** The record for one family, if this agent has one. */
function familyOf(state, family) {
    return state?.families[family];
}
/**
 * Replace one family's record, leaving the others (and the withheld flag) alone.
 * @param state - the agent's current state, or undefined on first sight.
 * @param family - the family being updated.
 * @param record - the family's new record.
 * @returns the updated state.
 */
function withFamily(state, family, record) {
    return {
        families: { ...state?.families, [family]: record },
        withheld: state?.withheld ?? false,
        standing: state?.standing ?? 'pending',
    };
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
export function canonicalize(value) {
    const seen = new WeakSet();
    const walk = (node, depth) => {
        if (depth > 32)
            return '<depth>';
        if (node === null || typeof node !== 'object') {
            return typeof node === 'bigint' ? `${node.toString()}n` : node;
        }
        if (seen.has(node))
            return '<cycle>';
        seen.add(node);
        if (Array.isArray(node))
            return node.map(item => walk(item, depth + 1));
        const entries = Object.entries(node)
            .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
            .map(([key, item]) => [key, walk(item, depth + 1)]);
        return Object.fromEntries(entries);
    };
    return JSON.stringify(walk(value, 0)) ?? '<unserializable>';
}
/**
 * The identity of one call: its tool name plus its canonical arguments.
 * @param name - the tool name.
 * @param args - the parsed arguments.
 * @returns the identity key.
 */
export function callKey(name, args) {
    return `${name}(${canonicalize(args)})`;
}
/**
 * Record one observed failure in one family.
 * @param state - the agent's current state, or undefined on first sight.
 * @param family - the family the failure belongs to.
 * @param failure - the recognized failure.
 * @param key - the identity of the call that failed.
 * @returns the updated state.
 */
export function observe(state, family, failure, key) {
    const previous = familyOf(state, family);
    const failingKeys = new Set(previous?.failingKeys ?? []);
    failingKeys.add(key);
    return withFamily(state, family, {
        observations: (previous?.observations ?? 0) + 1,
        last: failure,
        failingKeys,
        denials: previous?.denials ?? 0,
        advised: previous?.advised ?? false,
    });
}
/**
 * Whether this family's durable advisory has already been delivered.
 * @param state - the agent's current state, or undefined.
 * @param family - the family in question.
 * @returns true when the advice is already in the session.
 */
export function advisedOf(state, family) {
    return familyOf(state, family)?.advised ?? false;
}
/**
 * Mark one family's durable advisory as delivered.
 * @param state - the agent's current state.
 * @param family - the family that was advised.
 * @returns the updated state.
 */
export function recordAdvice(state, family) {
    const previous = familyOf(state, family);
    if (previous === undefined)
        return state;
    return withFamily(state, family, { ...previous, advised: true });
}
/**
 * Record that a recognized failure was withheld from the model.
 * @param state - the agent's current state, or undefined on first sight.
 * @returns the updated state.
 */
export function recordWithheld(state) {
    return {
        families: { ...state?.families },
        withheld: true,
        standing: state?.standing ?? 'pending',
    };
}
/**
 * Where the standing temp-root report stands for one agent.
 * @param state - the agent's current state, or undefined before first sight.
 * @returns the verdict; `pending` for an agent this plugin has not seen.
 */
export function standingOf(state) {
    return state?.standing ?? 'pending';
}
/**
 * Record the verdict of the standing check, leaving every other field alone.
 *
 * Called once per agent, whichever way the check comes out: `clear` memoizes
 * the decision so a host outside the condition never repeats the resolution, and
 * `reported` marks the one delivery. `pending` is not accepted — it is the state
 * before a decision, and writing it here would let a decided agent be asked
 * again, which is the whole thing this seat prevents.
 * @param state - the agent's current state, or undefined on first sight.
 * @param verdict - the decided verdict.
 * @returns the updated state.
 */
export function recordStanding(state, verdict) {
    return {
        families: { ...state?.families },
        withheld: state?.withheld ?? false,
        standing: verdict,
    };
}
/**
 * Record that a call carrying the same identity as a previously failing one
 * succeeded — in **every** family that was watching that identity.
 *
 * The environment worked at least once for that call, so the entry stops
 * justifying a denial — and is dropped rather than kept, so a later failure
 * re-earns it. A success is evidence about the environment, not about one
 * diagnosis: the same call cannot have started working for one family's reason
 * and not the other's.
 *
 * Each affected family's denial budget is re-armed at the same moment, and only
 * then. Measured consequence: without it the budget is per agent for the whole
 * session, which makes the entry above unobservable — past `maxDenials` this
 * plugin refuses nothing ever again, so clearing the key would change no
 * decision. With it, the bound reads as "at most `maxDenials` refusals per
 * episode of brokenness": an environment that breaks, is repaired and breaks
 * again may be refused again, while a session can always make progress by
 * spending the budget.
 * @param state - the agent's current state.
 * @param key - the identity of the call that just succeeded.
 * @returns the updated state, unchanged when no family was watching the key.
 */
export function observeSuccess(state, key) {
    const watched = Object.entries(state.families)
        .filter(([, record]) => record.failingKeys.has(key));
    if (watched.length === 0)
        return state;
    let next = state;
    for (const [family, record] of watched) {
        const failingKeys = new Set(record.failingKeys);
        failingKeys.delete(key);
        next = withFamily(next, family, { ...record, failingKeys, denials: 0 });
    }
    return next;
}
/**
 * Whether a call may be refused before dispatch.
 *
 * Both conditions are required: the environment has failed provisioning at
 * least `enforceAfter` times, **and** this exact call is one this plugin watched
 * fail. The second condition is what keeps the fail-fast half from blocking a
 * workaround: a different command, or the same command under a different policy
 * after the user changed configuration, has no key here.
 *
 * Only the `acl-provisioning` family ever reaches this question; see the
 * `denialText` doc for why the blocking half does not extend to `pty-startup`.
 * @param state - the agent's current state, or undefined.
 * @param family - the family whose threshold is being asked about.
 * @param key - the identity of the call about to dispatch.
 * @param enforceAfter - the configured threshold; 0 disables the half entirely.
 * @param maxDenials - the configured denial budget.
 * @returns whether to deny.
 */
export function shouldDeny(state, family, key, enforceAfter, maxDenials) {
    const record = familyOf(state, family);
    if (enforceAfter === 0 || record === undefined)
        return false;
    if (record.observations < enforceAfter)
        return false;
    if (record.denials >= maxDenials)
        return false;
    return record.failingKeys.has(key);
}
/**
 * Spend one denial.
 * @param state - the agent's current state.
 * @param family - the family being denied.
 * @returns the updated state.
 */
export function recordDenial(state, family) {
    const previous = familyOf(state, family);
    if (previous === undefined)
        return state;
    return withFamily(state, family, { ...previous, denials: previous.denials + 1 });
}
