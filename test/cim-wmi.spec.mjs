/**
 * The CIM/WMI boundary, end to end: the `cim-wmi-denial` family driven through
 * the real tool waterfalls on the shared harness.
 *
 * Four properties need the real pipeline here, and the first two are what make
 * the family necessary at all:
 *
 * 1. **It is read from a successful result, out of the value's own `stderr`.** A
 *    refused cmdlet is a nonzero exit, which the shipped shell tools report as a
 *    finished run (`packages/shell/tool-pwsh/src/render.ts`: "Non-zero exits are
 *    reported, not errored … only infrastructure failures (spawn errors, aborts)
 *    surface as isError results"). The arm that matters is the one where
 *    `result.isError === false` and the notice still rides `additionalContexts`,
 *    and its complement — the same record delivered as an *error* result, which
 *    this family cannot read and deliberately does not try to.
 * 2. **The mode is still the gate**, and the family's wording for a
 *    non-confining one is its own: `danger-full-access` is not a mode where
 *    commands are unsandboxed, it is a mode where the sandbox does not exist, so
 *    CIM works there and the refusal cannot be this story.
 * 3. **The platform is a fact the plugin measures**, and it is read before the
 *    policy lookup, so a host this condition cannot apply to pays nothing.
 * 4. **A policy that cannot answer withholds rather than guessing**, and says so
 *    once on the host — the disclosure rule, observable only here.
 *
 * **What this suite does not prove, and does not claim**: the Windows ACL
 * backend's WMI behaviour. This host is not Windows, so the arms that need the
 * platform stub the process-level fact and restore it in a `finally`. The
 * *decision layer* is under test against the record `#9272` pasted; the refusal
 * itself is upstream's, and this plugin's job is only to say what it means and
 * what to use instead.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { advisoryText, CIM_WMI_DISCUSSIONS } from '../lib/advice.js'
import { classifyCimDenial, hasCimDenialShape } from '../lib/signature.js'
import {
  call,
  CIM_DENIED_STDERR,
  cimDenied,
  contexts,
  failingTool,
  foreground,
  logLines,
  logText,
  MSYS2_STDERR,
  NATIVE_DEATH,
  okTool,
  runs,
  sandboxPolicy,
  shellTool,
  text,
  who,
  world,
} from './harness.mjs'

/** A confining mode: the one the report's failures were measured under. */
const CONFINING = 'workspace-write'

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

/** The one line of the advisory body that names the mechanism. */
const DOCUMENTED = 'WMI namespace security check'

/**
 * One mounted world whose `pwsh` fixture returns a refused CIM query.
 * @param config - plugin config.
 * @param options - `value` replaces the settled value; `mode` and
 *   `policyOptions` reach the policy stand-in.
 * @returns the mounted world plus the stand-in.
 */
async function cimWorld(config, options = {}) {
  const policy = sandboxPolicy(options.mode ?? CONFINING, options.policyOptions ?? {})
  const built = await world(config, [shellTool('pwsh', options.value ?? cimDenied())], { policy })
  return { ...built, policy }
}

// ---------------------------------------------------------------------------
// The classifier, on its own: what is and is not this family.
// ---------------------------------------------------------------------------

test('the reporter\'s own error record is recognized, and the status is carried through', () => {
  const failure = classifyCimDenial(cimDenied(), { platform: 'win32' })
  assert.equal(failure?.family, 'cim-wmi-denial')
  assert.equal(failure.exitCode, 1)
})

test('the code is the discriminator, so the localized sentence does not have to be English', () => {
  // The reporter's install prints 拒绝访问; an English one prints "Access denied".
  // Both carry the same FullyQualifiedErrorId, which is why the classifier keys
  // on the code — this arm is the reason that choice is not cosmetic.
  const english = CIM_DENIED_STDERR.replace('拒绝访问', 'Access denied')
  assert.equal(classifyCimDenial(cimDenied({ stderr: english }), { platform: 'win32' })?.family, 'cim-wmi-denial')
  assert.match(CIM_DENIED_STDERR, /拒绝访问/, 'the fixture keeps the reporter\'s own language')
  assert.match(CIM_DENIED_STDERR, /0x80041003/, 'and the code, which is what recognition reads')
})

test('the code is compared case-insensitively, because hex has two spellings', () => {
  const upper = CIM_DENIED_STDERR.replace('0x80041003', '0X80041003')
  assert.equal(classifyCimDenial(cimDenied({ stderr: upper }), { platform: 'win32' })?.family, 'cim-wmi-denial')
})

test('the code without a CIM context marker is not recognized — a quoted log line is not this failure', () => {
  const quoted = 'read the archived transcript: line 42 mentions 0x80041003 and gives no more detail'
  assert.equal(hasCimDenialShape(cimDenied({ stderr: quoted })), false)
  assert.equal(classifyCimDenial(cimDenied({ stderr: quoted }), { platform: 'win32' }), undefined)
})

test('a CIM context marker without the code is not recognized either', () => {
  const other = 'Get-CimInstance : Access is denied\n'
    + '    + CategoryInfo : PermissionDenied: (root\\cimv2:Win32_OperatingSystem), CimException'
  assert.equal(hasCimDenialShape(cimDenied({ stderr: other })), false)
})

test('a host this condition cannot apply to refuses the identical value', () => {
  for (const platform of ['darwin', 'linux', 'freebsd']) {
    assert.equal(classifyCimDenial(cimDenied(), { platform }), undefined, `${platform} must not be recognized`)
  }
})

test('only the shipped foreground projection is read', () => {
  // A command's own output cannot reach this classifier (the read is the value's
  // stderr field), and neither can another tool's value that happens to carry one.
  const value = cimDenied()
  for (const candidate of [null, undefined, '0x80041003', 42, [], { kind: 'background', stderr: value.stderr }]) {
    assert.equal(hasCimDenialShape(candidate), false, `${JSON.stringify(candidate)} must not be read as this family`)
  }
})

test('a stderr field that is missing, empty or not a string is not a record', () => {
  for (const stderr of [undefined, null, '', { text: undefined }, { text: 7 }, 'not-an-object']) {
    assert.equal(hasCimDenialShape({ ...foreground(1), stderr }), false)
  }
  assert.equal(hasCimDenialShape({ kind: 'foreground', exitCode: 1 }), false, 'no stderr field at all')
})

test('an exit status the tool did not report is carried as null rather than invented', () => {
  const value = { ...cimDenied(), exitCode: null }
  assert.equal(classifyCimDenial(value, { platform: 'win32' })?.exitCode, null)
  const fractional = { ...cimDenied(), exitCode: 1.5 }
  assert.equal(classifyCimDenial(fractional, { platform: 'win32' })?.exitCode, null)
})

test('the two shapes that answer with a wrong value and no error are NOT recognized — and that is the disclosure', () => {
  // The family's most dangerous half raises nothing at all: `Get-PSDrive` returns
  // its zeroes with an empty stderr, and a `-ErrorAction SilentlyContinue` call
  // returns an empty result. There is nothing for a classifier to key on, so the
  // plugin stays silent and the *rule* is delivered by the advisory attached to a
  // recognized refusal instead. Recorded here so a later reader does not mistake
  // the silence for an oversight.
  assert.equal(classifyCimDenial(foreground(0), { platform: 'win32' }), undefined, 'Get-PSDrive: no stderr, no error')
  assert.equal(classifyCimDenial(foreground(0, '    + CategoryInfo : PermissionDenied'), { platform: 'win32' }), undefined)
})

test('the advisory refuses to be built without the resolved mode, like the other gated families', () => {
  const failure = classifyCimDenial(cimDenied(), { platform: 'win32' })
  assert.throws(() => advisoryText(failure), /requires the resolved sandbox mode/)
})

// ---------------------------------------------------------------------------
// Through the real pipeline.
// ---------------------------------------------------------------------------

test('a confining mode turns a "successful" refused query into the diagnosis beside it', async () => {
  await onWindows(async () => {
    const { ctx, logged, policy } = await cimWorld()
    const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })

    // The producer's own framing, asserted first: this is a success, which is the
    // whole reason the family has to read a value rather than an error.
    assert.equal(result.isError, false)
    assert.match(text(result), /\[exit code: 1\]/, 'the shell tool still reports the status to the model')

    const attached = contexts(result)
    assert.equal(attached.length, 1, 'exactly one context rides the result')
    const notice = attached[0]
    assert.equal(notice.role, 'user')
    assert.equal(notice.source.kind, 'sandbox-grant-advisor', 'the producer declares its own source kind')
    assert.equal(notice.source.form, 'notice')
    assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the notice row stays one line')
    assert.match(notice.source.summary, /CIM\/WMI/)
    assert.match(notice.source.summary, /workspace-write/, 'the transcript row names the mode')

    const body = notice.content.map(block => block.text).join('\n')
    assert.match(body, /0x80041003/)
    assert.match(body, /WBEM_E_ACCESS_DENIED/)
    assert.match(body, /`workspace-write`/)
    assert.match(body, new RegExp(DOCUMENTED), 'the mechanism is quoted from the backend\'s own statement')
    assert.match(body, /Do not retry this call/)
    // The two silent shapes are named as rules, because neither raises anything.
    assert.match(body, /-ErrorAction SilentlyContinue/)
    assert.match(body, /Get-PSDrive/)
    // The measured substitutes are handed over...
    assert.match(body, /netstat -ano/)
    assert.match(body, /Get-Process/)
    assert.match(body, /Get-Service/)
    assert.match(body, /DriveInfo/)
    assert.match(body, /Get-Counter/)
    assert.match(body, /CurrentVersion/, 'the OS-version substitute is the registry key')
    // ...and the gap is stated rather than filled.
    assert.match(body, /Get-NetIPAddress \/ Get-NetAdapter/)
    assert.match(body, /ipconfig \/all/)
    assert.match(body, /NOT measured under a confining mode/)
    // No repair, and the reasons.
    assert.match(body, /No `icacls` line and no elevation/)
    assert.match(body, /not a fix/)
    assert.match(body, /root\/cimv2/)
    assert.match(body, /tree-creation escape/, 'the trade the narrow allowance would be weighed against')

    // The gate asked the real resolver, for this agent's own session, once.
    assert.equal(policy.calls.length, 1, 'one resolution per recognized failure')
    assert.equal(policy.calls[0].session, who('s1').session, 'resolved for the failing agent\'s session')
    // And the host log accounts for the recognition, with the mode and the code.
    const host = logLines(logged, 'sandbox-grant-advisor')
    assert.equal(host.length, 1)
    assert.match(logText(logged), /WBEM_E_ACCESS_DENIED \(0x80041003\)/)
    assert.match(logText(logged), /workspace-write/)
    assert.match(logText(logged), /native/)
  })
})

test('the advisory is delivered once per agent, not once per refused query', async () => {
  await onWindows(async () => {
    const { ctx } = await cimWorld()
    const first = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    const second = await call(ctx, 'pwsh', { command: 'Get-NetTCPConnection -State Listen' })
    assert.equal(contexts(first).length, 1)
    assert.equal(contexts(second).length, 0, 'the second refusal is left alone')
  })
})

test('a second agent gets its own advisory', async () => {
  await onWindows(async () => {
    const { ctx } = await cimWorld()
    const first = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' }, who('s1'))
    const other = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' }, who('s2'))
    assert.equal(contexts(first).length, 1)
    assert.equal(contexts(other).length, 1, 'the once-per-agent rule is per agent')
  })
})

test('a non-confining mode is not this family\'s story, and says so on the host', async () => {
  await onWindows(async () => {
    const { ctx, logged, policy } = await cimWorld(undefined, { mode: 'danger-full-access' })
    const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    assert.equal(contexts(result).length, 0, 'nothing is attached under a mode this condition cannot hold in')
    const withheld = logLines(logged, 'no advisory sent')
    assert.equal(withheld.length, 1, 'the withholding is recorded once')
    assert.match(withheld[0], /danger-full-access/)
    assert.match(withheld[0], /nothing is spawned through the sandbox/)
    assert.match(withheld[0], /cim-wmi-denial/, 'the note names the family it withheld')
    assert.equal(policy.calls[0].session, who('s1').session)
  })
})

test('a policy service that is not mounted withholds rather than guessing at the mode', async () => {
  await onWindows(async () => {
    const { ctx, logged } = await world(undefined, [shellTool('pwsh', cimDenied())])
    const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    assert.equal(contexts(result).length, 0)
    const withheld = logLines(logged, 'no advisory sent')
    assert.equal(withheld.length, 1)
    assert.match(withheld[0], /no `sandboxPolicy` service is mounted/)
    assert.match(withheld[0], /NOT a claim that the sandbox is unrelated/)
  })
})

test('off Windows the platform fact is read before the policy lookup, so no host pays for it', async () => {
  assert.notEqual(process.platform, 'win32', 'this arm is only meaningful off Windows')
  const { ctx, logged, policy } = await cimWorld()
  const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
  assert.equal(contexts(result).length, 0, 'the condition is a property of one backend')
  assert.equal(policy.calls.length, 0, 'and the platform is read before any resolution')
  assert.equal(logLines(logged, 'sandbox-grant-advisor').length, 0, 'nothing is withheld either: it is simply not this family')
})

test('an ERROR result carrying the same record is not this family — the family is value-read on purpose', async () => {
  // The record can only reach the session as a value, because the cmdlet error is
  // a nonzero exit and the renderer does not mark those as errors. Feeding the
  // same text to the error path is the arm that pins the narrower read: no
  // classification, and no `withhold` note either, since nothing was recognized.
  const { ctx, logged } = await world(undefined, [failingTool('pwsh', CIM_DENIED_STDERR)])
  const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
  assert.equal(result.isError, true, 'the fixture really did take the error path')
  assert.equal(contexts(result).length, 0)
  assert.equal(logLines(logged, 'sandbox-grant-advisor').length, 0)
})

test('a record on stdout instead of stderr is left alone', async () => {
  await onWindows(async () => {
    const value = { ...foreground(1), stdout: { text: CIM_DENIED_STDERR, truncated: false } }
    const { ctx } = await cimWorld(undefined, { value })
    const result = await call(ctx, 'pwsh', { command: 'Get-Content cim-error.log' })
    assert.equal(contexts(result).length, 0, 'a command that prints such a record has not been refused')
  })
})

test('the blocking half does not extend to this family', async () => {
  // `enforceAfter` is an ACL-only fail-fast: its remedy is a command the user can
  // run while the session continues, which is why spending the budget always lets
  // the call through and a repaired environment is discovered. Here the
  // environment is not the user's to change mid-session, so refusing calls could
  // only pad a session that is already unable to do the thing being refused.
  await onWindows(async () => {
    const { ctx } = await world({ enforceAfter: 1, maxDenials: 1 }, [shellTool('pwsh', cimDenied())], {
      policy: sandboxPolicy(CONFINING),
    })
    const command = { command: 'Get-CimInstance Win32_OperatingSystem' }
    const first = await call(ctx, 'pwsh', command)
    const second = await call(ctx, 'pwsh', command)
    assert.equal(runs('pwsh'), 2, 'the second identical call still ran')
    assert.equal(contexts(first).length, 1)
    assert.equal(contexts(second).length, 0)
  })
})

test('the watching lists narrow this family too, without pretending it was withheld', async () => {
  await onWindows(async () => {
    const { ctx, logged } = await cimWorld({ include: ['bash'] })
    const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    assert.equal(contexts(result).length, 0)
    assert.equal(logLines(logged, 'sandbox-grant-advisor').length, 0, 'an untracked call is transparent, not withheld')
  })
})

test('a configured href replaces the thread line in this family as well', async () => {
  const href = 'https://github.com/deepseek-ai/deepseek-harness/discussions/9272'
  await onWindows(async () => {
    const { ctx } = await cimWorld({ href })
    const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    const body = contexts(result)[0].content.map(block => block.text).join('\n')
    assert.match(body, new RegExp(href.replaceAll('/', '\\/').replaceAll('.', '\\.')))
    assert.ok(!body.includes(CIM_WMI_DISCUSSIONS), 'the default thread list gives way to the configured URL')
  })
})

test('an agent that hits this family and another is told about both, each in its own words', async () => {
  // The one record per family split, exercised across the two value-read families
  // that share this seam: a CIM refusal and a loader death must both survive.
  await onWindows(async () => {
    const { ctx } = await world(undefined, [
      shellTool('pwsh', cimDenied()),
      failingTool('bash', 'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'),
    ], { policy: sandboxPolicy(CONFINING) })
    const cim = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    const acl = await call(ctx, 'bash', { command: 'echo hi' })
    assert.match(contexts(cim)[0].content.map(block => block.text).join('\n'), /CIM\/WMI/)
    assert.match(contexts(acl)[0].content.map(block => block.text).join('\n'), /WRITE_OWNER/)
  })
})

test('a policy answer without a recognizable mode withholds, not guesses', async () => {
  await onWindows(async () => {
    const { ctx, logged } = await world(undefined, [shellTool('pwsh', cimDenied())], {
      policy: sandboxPolicy(CONFINING, { resolve: () => ({ mode: 'something-else' }) }),
    })
    const result = await call(ctx, 'pwsh', { command: 'Get-CimInstance Win32_OperatingSystem' })
    assert.equal(contexts(result).length, 0, 'an unrecognizable mode is not an invitation to assume the default')
    const withheld = logLines(logged, 'no advisory sent')
    assert.equal(withheld.length, 1)
    assert.match(withheld[0], /without a recognizable mode/)
    assert.match(withheld[0], /cim-wmi-denial/)
  })
})

test('an ordinary successful call is not examined for this family', async () => {
  await onWindows(async () => {
    const { ctx, logged, policy } = await cimWorld(undefined, { value: foreground(0) })
    const result = await call(ctx, 'pwsh', { command: 'echo hi' })
    assert.equal(contexts(result).length, 0)
    assert.equal(logLines(logged, 'sandbox-grant-advisor').length, 0)
    // Two lookups, and both belong to the standing temp-root check that runs after
    // this family declined: one for the mode and one for the workspace root. The
    // point of the arm is that a command which ran does not cost a CIM resolution
    // of its own — the count is pinned so a later CIM branch added to the success
    // path is caught here.
    assert.equal(policy.calls.length, 2, 'the standing check resolves the mode and the root, and nothing else')
  })
})

test('recognition is structural, so text a command prints can never reach it', async () => {
  // The counterpart to the classifier arm above, driven through the seam: a tool
  // that returns the record as a *string* is not a shell projection, and a value
  // shaped like one but carrying an ordinary run is not a refusal.
  await onWindows(async () => {
    const quoted = okTool('read_file', CIM_DENIED_STDERR)
    const running = shellTool('pwsh', foreground(0))
    const { ctx, logged } = await world(undefined, [quoted, running], { policy: sandboxPolicy(CONFINING) })

    const read = await call(ctx, 'read_file', { path: 'cim-error.log' })
    assert.equal(read.isError, false)
    assert.match(text(read), /0x80041003/, 'the text really does carry the code')
    assert.equal(contexts(read).length, 0, 'a line of text is not a settled shell value')

    const echo = await call(ctx, 'pwsh', { command: 'echo hi' })
    assert.equal(contexts(echo).length, 0)
    assert.equal(logLines(logged, 'sandbox-grant-advisor').length, 0, 'no failure was recognized, so nothing is logged either')
  })
})

test('a loader death whose stderr also mentions WMI stays the native-init family', async () => {
  // The three value-read families share this seam and all read the settled value,
  // so the arm that keeps them apart is a value carrying one producer's identity
  // and another's prose: a process killed by the loader whose captured stderr
  // happens to quote the WMI status. It is still a loader death — the branch that
  // owns the value decides first — and the CIM advisory must not claim it.
  await onWindows(async () => {
    const mixed = foreground(NATIVE_DEATH, `${MSYS2_STDERR}; meanwhile the WMI service is stopped (0x80041003, root\\cimv2)`)
    const { ctx } = await cimWorld(undefined, { value: mixed })
    const result = await call(ctx, 'pwsh', { command: 'cmd /c exit /b 1' })
    const body = contexts(result)[0].content.map(block => block.text).join('\n')
    assert.match(body, /Sandboxed command never started/, 'the native-init family owns this value')
    assert.ok(!body.includes('CIM/WMI is unavailable'), 'the CIM advisory must not claim a loader death')
  })
})
