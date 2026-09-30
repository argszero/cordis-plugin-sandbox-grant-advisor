/**
 * The workspace-internal denial, end to end: the `workspace-denial` family
 * driven through the real tool waterfalls on the shared harness.
 *
 * Three properties need the real pipeline, and they are this family's whole
 * reason for existing:
 *
 * 1. **It is read from a successful result.** A denied command exits nonzero and
 *    the shipped shell tools report that as a finished run, so the arm that
 *    matters is the one where `result.isError === false` and the notice still
 *    rides `additionalContexts`.
 * 2. **The decision uses the call's own arguments and the session's workspace
 *    root**, which no unit arm can supply: the containment claim is a statement
 *    about the path the *arguments* name and the root the *policy resolver*
 *    reports, and both come off the seam.
 * 3. **A root that cannot be resolved withholds rather than guesses**, and says
 *    so once on the host — the disclosure rule, which is only observable here.
 *
 * **The platform fact.** This family is Windows-only by construction (the
 * mechanism is ACE inheritance, which no other backend has), and this suite runs
 * on the maintainer's macOS host. The plugin reads `process.platform`, not a
 * config knob — a knob would be a backdoor into a shipped decision — so the arms
 * that need Windows stub the process-level fact and restore it. That is honest
 * about what is and is not being tested: the *decision layer* is under test
 * against the producers' own stamped values, and the Windows ACL path itself is
 * still unwitnessed here, exactly as the README says.
 *
 * The values are built by `test/foreground.mjs` from the shape `tool-bash` /
 * `tool-pwsh` project onto a settled result (`sandbox: { mode, denied,
 * enforcement? }`) and the stderr dialect the executors match.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { WORKSPACE_DENIAL_DISCUSSIONS } from '../lib/advice.js'
import {
  call,
  contexts,
  denied,
  failingTool,
  foreground,
  INSIDE,
  logLines,
  logText,
  OUTSIDE,
  REPORTED,
  runs,
  sandboxPolicy,
  shellTool,
  text,
  who,
  world,
  WORKSPACE_ROOT,
} from './harness.mjs'

/** The one mode a write inside the workspace is supposed to succeed under. */
const CONFINING = 'workspace-write'

/** The call that names the in-workspace path, as a shell would receive it. */
const WRITE_INSIDE = { command: `cmd /c "echo hi >> ${INSIDE}"` }

/** The host's real platform descriptor, restored after every stubbed arm. */
const REAL_PLATFORM = Object.getOwnPropertyDescriptor(process, 'platform')

/**
 * Run one arm with the host reporting Windows.
 *
 * The descriptor is restored in a `finally`, so a failing assertion cannot leak
 * a Windows host into the rest of the suite — a leak that would make the
 * platform-gate arm below pass for the wrong reason.
 * @param body - the arm to run.
 * @returns whatever the arm returned.
 */
async function onWindows(body) {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true, enumerable: true })
  try {
    return await body()
  } finally {
    Object.defineProperty(process, 'platform', REAL_PLATFORM)
  }
}

/**
 * One mounted world with a denial-stamped shell command.
 * @param config - plugin config.
 * @param options - `value` replaces the settled value; `policyOptions` reaches
 *   the policy stand-in.
 * @returns the mounted world plus the stand-in.
 */
async function denialWorld(config, options = {}) {
  const policy = sandboxPolicy(options.mode ?? CONFINING, options.policyOptions ?? {})
  const built = await world(config, [shellTool('bash', options.value ?? denied())], { policy })
  return { ...built, policy }
}

test('a denial inside the workspace turns a "successful" call into the diagnosis beside it', async () => {
  await onWindows(async () => {
    const { ctx, logged, policy } = await denialWorld()
    const result = await call(ctx, 'bash', WRITE_INSIDE)
    // The producer's own framing, asserted first: this is a success, which is why
    // a plugin reading only error results cannot see this family.
    assert.equal(result.isError, false)
    assert.equal(contexts(result).length, 1, 'the diagnosis rides the successful result')

    const notice = contexts(result)[0]
    assert.equal(notice.role, 'user')
    assert.equal(notice.source.kind, 'sandbox-grant-advisor', 'the producer declares its own source kind')
    assert.equal(notice.source.form, 'notice')
    assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the notice row stays one line')
    assert.match(notice.source.summary, /denied inside the workspace/)
    assert.match(notice.source.summary, /workspace-write/)
    const body = notice.content.map(block => block.text).join('\n')
    assert.match(body, /Denied inside your own workspace/)
    assert.match(body, /D:\\ws\\logs\\app\.log/, 'the path it keyed on is shown')
    assert.match(body, /workspace root: D:\\ws/, 'and so is the root it tested it against')
    assert.match(body, /Do NOT retry this call unchanged/)
    // The fork is ternary since 0.14.0: the two halves above, and the root itself
    // refused — the one branch whose recovery is a user restart rather than a
    // command, because the layer holding the answer is the provider's own map and
    // not the DACL. End to end, so the third branch really reaches the model.
    assert.match(body, /THE ROOT ITSELF IS REFUSED/)
    assert.match(body, /Half three — the standing grant is gone from the ROOT itself \(#8409/)
    assert.match(body, /RESTART IT/)
    assert.match(body, /#8421/, 'the label half cites its second instance')

    // The gate asked the real resolver once, for this agent's own session.
    assert.equal(policy.calls.length, 1, 'one resolution per recognized failure')
    assert.equal(policy.calls[0].session, who('s1').session, 'resolved for the failing agent\'s session')

    // The host-side account carries both halves of the string comparison.
    const host = logLines(logged, 'sandbox-grant-advisor: confined command denied')
    assert.equal(host.length, 1)
    assert.match(host[0], /D:\\ws\\logs\\app\.log/)
    assert.match(host[0], /INSIDE the workspace D:\\ws/)
    assert.match(host[0], /"workspace-write"/)
    assert.match(host[0], new RegExp(WORKSPACE_DENIAL_DISCUSSIONS))
  })
})

test('the advisory is delivered once per agent, not once per denied command', async () => {
  await onWindows(async () => {
    const { ctx, logged } = await denialWorld()
    assert.equal(contexts(await call(ctx, 'bash', WRITE_INSIDE)).length, 1)
    for (const command of [`type ${INSIDE}`, `dir ${WORKSPACE_ROOT}`, `del ${INSIDE}`]) {
      const again = await call(ctx, 'bash', { command })
      assert.equal(again.isError, false)
      assert.equal(contexts(again).length, 0, 'the environment is explained once; repetition is noise')
    }
    assert.equal(runs('bash'), 4, 'the tool body really ran every time — the plugin enriched, never blocked')
    assert.equal(logLines(logged, 'confined command denied').length, 1, 'the host line is not repeated either')
  })
})

test('a second agent gets its own advisory', async () => {
  await onWindows(async () => {
    const { ctx } = await denialWorld()
    assert.equal(contexts(await call(ctx, 'bash', WRITE_INSIDE, who('p1'))).length, 1)
    assert.equal(contexts(await call(ctx, 'bash', WRITE_INSIDE, who('p2'))).length, 1)
  })
})

test('a denial the plugin can place outside the workspace is left alone, and not called withheld', async () => {
  await onWindows(async () => {
    // The designed escalation path: a command naming a path outside the workspace
    // is exactly what a confining sandbox is for, and the denial surface's
    // one-shot escalation offer is correct there. Advising about a missing
    // inherited grant would be the confidently wrong cause this module refuses.
    const { ctx, logged } = await denialWorld()
    const result = await call(ctx, 'bash', { command: `"${OUTSIDE}" --version` })
    assert.equal(result.isError, false)
    assert.equal(contexts(result).length, 0, 'no advisory for the sanctioned path')
    assert.equal(
      logText(logged),
      '',
      'and no withholding note either: this is not "could not tell", it is "not this family"',
    )
  })
})

test('a command the plugin cannot place — no absolute path, or an outside one too — is refused', async () => {
  await onWindows(async () => {
    // Every one of these is the same failure mode: the plugin cannot say WHICH
    // path the sandbox refused, so it says nothing rather than guessing.
    for (const command of [
      'mkdir logs && cat logs/app.log',
      'echo hello',
      `"${OUTSIDE}" --version && echo hi >> ${INSIDE}`,
    ]) {
      const { ctx, logged } = await denialWorld()
      const result = await call(ctx, 'bash', { command })
      assert.equal(result.isError, false)
      assert.equal(contexts(result).length, 0, `must stay silent for: ${command}`)
      assert.equal(logText(logged), '')
    }
  })
})

test('the stamp is the recognition, so the values without it are ordinary successes', async () => {
  await onWindows(async () => {
    // One field at a time, each a situation the harness really produces: a
    // non-denial under the same mode, a read-only denial (the mode working), a
    // mode that spawns nothing through the sandbox, and a runner failure (the
    // executor refuses to call that a denial).
    for (const value of [
      denied({ denied: false }),
      denied({ mode: 'read-only' }),
      denied({ mode: 'danger-full-access' }),
      denied({ runnerFailed: true }),
      foreground(1),
      { kind: 'background', exitCode: 1, sandbox: { mode: 'workspace-write', denied: true } },
    ]) {
      const { ctx, logged } = await denialWorld(undefined, { value })
      const result = await call(ctx, 'bash', WRITE_INSIDE)
      assert.equal(result.isError, false)
      assert.equal(contexts(result).length, 0, `must not advise for ${JSON.stringify(value.sandbox ?? value)}`)
      assert.equal(logText(logged), '', 'and must not log a withholding note for a value that is not this family')
    }
  })
})

test('a workspace root the resolver cannot report withholds, and the host says so once', async () => {
  await onWindows(async () => {
    // The containment claim is a statement about two strings. Without the root
    // there is nothing to test against, and silence alone would read as "the
    // sandbox is not the cause" — which this plugin cannot claim.
    const { ctx, logged } = await denialWorld(undefined, {
      policyOptions: { resolve: () => ({ mode: CONFINING }) },
    })
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const result = await call(ctx, 'bash', WRITE_INSIDE, who('r1'))
      assert.equal(result.isError, false)
      assert.equal(contexts(result).length, 0)
    }
    const withheld = logLines(logged, 'no advisory sent')
    assert.equal(withheld.length, 1, 'the decision is recorded once, not once per retry')
    assert.match(withheld[0], /workspace-denial/)
    assert.match(withheld[0], /without a usable workspace root/)
    assert.match(withheld[0], new RegExp(WORKSPACE_DENIAL_DISCUSSIONS), 'the note cites this family\'s thread, not another\'s')
    assert.equal(logLines(logged, 'advisory delivered to the model').length, 0, 'and nothing was delivered')
  })
})

test('an unmountable policy service withholds rather than guessing at the root', async () => {
  await onWindows(async () => {
    const { ctx, logged } = await world(undefined, [shellTool('bash', denied())])
    assert.equal(contexts(await call(ctx, 'bash', WRITE_INSIDE)).length, 0)
    const withheld = logLines(logged, 'no advisory sent')
    assert.equal(withheld.length, 1)
    assert.match(withheld[0], /no `sandboxPolicy` service is mounted/)
    assert.match(withheld[0], /workspace root is unknown/)
  })
})

test('off Windows the same value is a different story, and is left silent', async () => {
  // No stub here: this is the real host, and the arm is that the platform fact
  // really gates recognition. The mechanism this family explains is ACE
  // inheritance; a Landlock/Seatbelt/bwrap denial of an in-workspace path has no
  // descendant to have missed a propagation and is not this family.
  assert.notEqual(process.platform, 'win32', 'this arm is only meaningful off Windows')
  const { ctx, logged, policy } = await denialWorld()
  const result = await call(ctx, 'bash', WRITE_INSIDE)
  assert.equal(result.isError, false)
  assert.equal(contexts(result).length, 0)
  assert.equal(logText(logged), '', 'the gate is recognition, not a withheld decision — nothing is logged')
  assert.equal(policy.calls.length, 0, 'and the platform fact is read before the policy lookup, so no host pays for a family it cannot have')
})

test('the blocking half does not extend to the workspace-denial family', async () => {
  // Its remedy is not a command the session can wait out: the object was skipped
  // when the grant was written and nothing revisits it. Refusing calls could only
  // pad a session that is already unable to do the thing being refused.
  await onWindows(async () => {
    const { ctx } = await denialWorld({ enforceAfter: 1, maxDenials: 2 })
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const result = await call(ctx, 'bash', WRITE_INSIDE)
      assert.equal(result.isError, false, 'the tool really ran and really reported a finished run')
      assert.doesNotMatch(text(result), /Blocked by sandbox-grant-advisor/)
    }
    assert.equal(runs('bash'), 4)
    assert.equal(contexts(await call(ctx, 'bash', WRITE_INSIDE)).length, 0)
  })
})

test('an agent that hits the two ACL halves is told about both, each in its own words', async () => {
  await onWindows(async () => {
    const policy = sandboxPolicy(CONFINING)
    const built = await world(undefined, [shellTool('bash', denied()), failingTool('pwsh', REPORTED)], { policy })
    const agent = who('both2')
    const denial = await call(built.ctx, 'bash', WRITE_INSIDE, agent)
    const provisioning = await call(built.ctx, 'pwsh', { command: 'ls' }, agent)
    assert.equal(contexts(denial).length, 1, 'the family whose input is a success is still first-class')
    assert.equal(contexts(provisioning).length, 1)
    const denialBody = contexts(denial)[0].content.map(block => block.text).join('\n')
    const aclBody = contexts(provisioning)[0].content.map(block => block.text).join('\n')
    assert.match(denialBody, /Denied inside your own workspace/)
    assert.match(aclBody, /WRITE_OWNER/)
    // The two are the same backend's two ends, so the texts must not be each
    // other's: the provisioning advisory's remedy is refused here, and this
    // family's diagnosis is not about a grant that could not be applied.
    assert.doesNotMatch(denialBody, /SetNamedSecurityInfoW/)
    assert.doesNotMatch(aclBody, /ACE inheritance/)
    assert.equal(logLines(built.logged, 'confined command denied').length, 1)
    assert.equal(logLines(built.logged, 'workspace ACL provisioning failed').length, 1)
    // The second call of each family is still quiet.
    assert.equal(contexts(await call(built.ctx, 'bash', { command: `type ${INSIDE}` }, agent)).length, 0)
    assert.equal(contexts(await call(built.ctx, 'pwsh', { command: 'pwd' }, agent)).length, 0)
  })
})

test('the watching lists narrow this family too, without pretending it was withheld', async () => {
  await onWindows(async () => {
    const excluded = await denialWorld({ exclude: ['bash'] })
    assert.equal(contexts(await call(excluded.ctx, 'bash', WRITE_INSIDE)).length, 0)
    assert.equal(logText(excluded.logged), '', 'an excluded tool is not a withheld diagnosis — the operator asked for silence')

    const wrongInclude = await denialWorld({ include: ['pwsh'] })
    assert.equal(contexts(await call(wrongInclude.ctx, 'bash', WRITE_INSIDE)).length, 0)
    assert.equal(logText(wrongInclude.logged), '')
  })
})

test('a configured href replaces the thread line in this family as well', async () => {
  await onWindows(async () => {
    const { ctx } = await denialWorld({ href: 'https://example.invalid/t/423' })
    const body = contexts(await call(ctx, 'bash', WRITE_INSIDE))[0].content.map(block => block.text).join('\n')
    assert.match(body, /tracked upstream: https:\/\/example\.invalid\/t\/423/)
    assert.doesNotMatch(body, /tracked upstream \(discussion/)
    assert.match(body, /#423 measured 170 of 729/, 'the measurements keep their reference, which the href cannot replace')
    assert.match(body, /#8383/, 'and the branch the second report measured keeps its own id')
    const citations = body.match(/#\d+/g) ?? []
    for (const id of WORKSPACE_DENIAL_DISCUSSIONS.match(/#\d+/g) ?? []) {
      assert.ok(citations.includes(id), `an href replaced the thread line and dropped ${id}`)
    }
  })
})

test('a broken advisor still lets the call through unchanged', async () => {
  await onWindows(async () => {
    // The throw comes from inside the classification, through a resolver that
    // lies in the one way the guarded lookup advertises as impossible.
    const { ctx, logged } = await denialWorld(undefined, {
      policyOptions: { resolve: () => { throw new Error('policy exploded') } },
    })
    const result = await call(ctx, 'bash', WRITE_INSIDE)
    assert.equal(result.isError, false)
    assert.equal(contexts(result).length, 0)
    assert.match(logText(logged), /result left alone after internal error|no advisory sent/)
  })
})
