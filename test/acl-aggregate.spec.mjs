/**
 * The aggregate-refusal family, unit and end to end.
 *
 * One property makes this family worth its own file: **the producer's line is an
 * `AggregateError` message**, and Node builds that message from the argument the
 * thrower passed rather than from the members. So the Win32 code, the API name
 * and the directory being edited are absent *by construction*, and the whole
 * family is the decision to advise what the line does say instead of inventing
 * the cause it cannot. Four consequences get their own arms:
 *
 * 1. **It is a sentence, verbatim, and there are two of them.** Each is a
 *    different half of the same backend — the standing workspace root grant and
 *    the per-session private temp capability — so the recognition keeps the
 *    `layer` and the advisory forks on it. Both spellings are pinned against
 *    `packages/sandbox/sandbox-local/src/index.ts`, which is where they are
 *    thrown.
 * 2. **Only the message is read.** The integration arm throws a real
 *    `AggregateError` whose members carry a Win32 line naming a real directory,
 *    and asserts that none of that member text reaches the advisory: reading it
 *    would be reading something the session never sees.
 * 3. **The more specific family wins.** A message that also carries
 *    `(Set|Get)NamedSecurityInfoW failed (Win32 N)` is the ACL family's — that
 *    line names the API, the code and usually the directory, which is exactly
 *    what this family's reason for existing is the absence of — so the
 *    classifier refuses it and the ACL diagnosis is what speaks.
 * 4. **Nothing is handed to the shell but one aimed grant.** The line names no
 *    directory, so the advisory ships no grant aimed at the FAILED one; what it
 *    hands over is the listing that names it, in first position because it is the
 *    only candidate a directory listing can rule out and the only one that needs
 *    no ACL at all. Since 0.27.0 it also hands over one grant — aimed at the only
 *    object this family can name without that line, the temp root, where a fix
 *    has to be INHERITABLE to outlive the session that needed it.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ACL_AGGREGATE_DISCUSSIONS, advisoryText } from '../lib/advice.js'
import {
  ACL_AGGREGATE_TEMP_SENTENCE,
  ACL_AGGREGATE_WORKSPACE_SENTENCE,
  classifyAclAggregateFailure,
  classifyProvisioningFailure,
  failureLine,
} from '../lib/signature.js'
import { aggregateTool, call, contexts, failingTool, logLines, who, world } from './harness.mjs'

/**
 * The workspace-half sentence, as `sandbox-local` throws it, copied from the
 * `throw new AggregateError(...)` line in
 * `packages/sandbox/sandbox-local/src/index.ts` (the `catch` around
 * `AclWriteGrant.add(workspaceRoot, true)`). Note that this half does **not**
 * say "materialization" while the temp half does — that asymmetry is in the
 * producer, and the recognition follows the producer, not a tidied guess.
 */
const WORKSPACE_SENTENCE = 'sandbox-local windows-acl workspace grant failed and its cleanup also failed'

/**
 * The temp-half sentence, the one `#9460` reports, copied from the
 * `throw new AggregateError(...)` line in the same file's
 * `materializeAclGrant`.
 */
const TEMP_SENTENCE = 'sandbox-local windows-acl temp grant materialization failed and its cleanup also failed'

/** What the tool runtime renders around a thrown error's message. */
const RENDERED = (message) => `Error: ${message}`

test('both producer sentences are recognized verbatim, and the layer is kept', () => {
  const workspace = classifyAclAggregateFailure(WORKSPACE_SENTENCE)
  assert.ok(workspace, 'the workspace sentence is a recognition on its own')
  assert.equal(workspace.family, 'acl-aggregate-failure')
  assert.equal(workspace.layer, 'workspace')
  assert.equal(workspace.line, WORKSPACE_SENTENCE)
  const temp = classifyAclAggregateFailure(TEMP_SENTENCE)
  assert.ok(temp)
  assert.equal(temp.layer, 'temp')
  assert.equal(temp.line, TEMP_SENTENCE)
  // The constants and the sentences they stand for are the same strings, so a
  // future edit to one cannot leave the other behind.
  assert.equal(ACL_AGGREGATE_WORKSPACE_SENTENCE, WORKSPACE_SENTENCE)
  assert.equal(ACL_AGGREGATE_TEMP_SENTENCE, TEMP_SENTENCE)
  assert.notEqual(WORKSPACE_SENTENCE, TEMP_SENTENCE, 'the two halves are not the same sentence')
})

test('the runtime\'s own rendering is tolerated, and the producer\'s line is what is kept', () => {
  // A thrown error arrives as two lines: `error.message`, then the tool
  // runtime's rendering of it. Both carry the sentence, and the second is
  // prefixed by the runtime rather than by the producer, so the prefix is not
  // part of what is recognized or quoted back.
  const arrived = `${TEMP_SENTENCE}\n${RENDERED(TEMP_SENTENCE)}`
  const failure = classifyAclAggregateFailure(arrived)
  assert.ok(failure)
  assert.equal(failure.layer, 'temp')
  assert.equal(failure.line, TEMP_SENTENCE, 'the producer\'s own spelling, not the runtime\'s rendering')
  assert.equal(failureLine(failure), TEMP_SENTENCE)
  // The envelope alone is recognized too, which is the tolerance the PTY family
  // documents for its own sentence: the runtime writes `Error: <message>` and a
  // reader that only ever saw that rendering must not be left blind. It is the
  // whole envelope, never a substring of it.
  assert.equal(classifyAclAggregateFailure(RENDERED(TEMP_SENTENCE))?.layer, 'temp')
  assert.equal(classifyAclAggregateFailure(RENDERED(WORKSPACE_SENTENCE))?.layer, 'workspace')
  assert.equal(classifyAclAggregateFailure(`Error: ${TEMP_SENTENCE} (see the log)`), undefined)
  // Order does not matter, and neither does surrounding whitespace.
  assert.equal(classifyAclAggregateFailure(`${RENDERED(TEMP_SENTENCE)}\n${TEMP_SENTENCE}`)?.layer, 'temp')
  assert.equal(classifyAclAggregateFailure(`   ${TEMP_SENTENCE}   `)?.layer, 'temp')
})

test('everything that merely resembles the sentence is refused, not guessed at', () => {
  for (const message of [
    // The sentences of the two families that DO name a cause, which is what a
    // reader who has not seen this line would expect here.
    'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
    'sandbox-local windows-acl temp grant materialization failed', // the prefix of the real sentence
    'sandbox-local windows-acl workspace grant failed',
    // A sentence that quotes the producer instead of being it — a log line, a
    // document, or a command's own output. The match is `===` on a line, so
    // anything around the sentence disqualifies it, which is what keeps a
    // working session from being told its sandbox is broken.
    `error: ${TEMP_SENTENCE}`,
    `${TEMP_SENTENCE} (see the log)`,
    `windows-acl: ${TEMP_SENTENCE}`,
    // The runner's own refusal line, which is a different condition with its own
    // family: it is written to stderr behind a marker and is about the runner
    // never having started.
    'windows-acl-run: the runner refused its profile',
    // The other five families' texts, and an empty message.
    'PTY shell exited during startup',
    "[sandbox-local] assertTempRootOutsideWorkspace: workspace=D:\\ws; temp=D:\\ws\\tmp",
    '[exit code: -1073741502]',
    'WBEM_E_ACCESS_DENIED (0x80041003)',
    '',
  ]) {
    assert.equal(classifyAclAggregateFailure(message), undefined, `must refuse: ${JSON.stringify(message)}`)
  }
})

test('the more specific family wins, so a line that names the code is never told it is missing', () => {
  // A message that carries BOTH the aggregate sentence and the ACL signature is
  // the ACL family's: the signature's whole value is that it names the API, the
  // code and usually the directory, and this family exists for the absence of
  // exactly those. It is asserted from the classifier's own side rather than
  // left to the caller's ordering, so neither entry point can get it wrong.
  const both = `${TEMP_SENTENCE}\nError: SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)`
  assert.equal(classifyAclAggregateFailure(both), undefined)
  // The same for the read side of the same backend.
  assert.equal(
    classifyAclAggregateFailure(`${WORKSPACE_SENTENCE}\nGetNamedSecurityInfoW failed (Win32 5): revokeWrite(D:\\ws)`),
    undefined,
  )
})

test('the advisory names no cause, because the line withholds one', () => {
  const failure = classifyAclAggregateFailure(TEMP_SENTENCE)
  assert.ok(failure)
  const text = advisoryText(failure, { tool: 'pwsh' })
  // What it is, in the reader's own terms.
  assert.match(text, /Sandbox provisioning failed/)
  assert.match(text, /no sandboxed command can run in this workspace until it is fixed/)
  assert.match(text, /The `pwsh` command never started/)
  // The producer's line, quoted rather than summarized.
  assert.match(text, /sandbox-local windows-acl temp grant materialization failed and its cleanup also failed/)
  // The mechanism of the withholding, which is the whole reason the text does not
  // name a cause.
  assert.match(text, /`AggregateError` message/)
  assert.match(text, /Node builds that message from the argument/)
  assert.match(text, /It is in `errors` \(and on the raw/)
  // It never claims a cause of its own.
  assert.match(text, /Candidates, in the order a probe can separate them/)
  assert.match(text, /They are candidates and not findings/)
  assert.match(text, new RegExp(ACL_AGGREGATE_DISCUSSIONS))
})

test('the per-path lock leads the candidates, because it is the only one a listing can settle', () => {
  const failure = classifyAclAggregateFailure(TEMP_SENTENCE)
  assert.ok(failure)
  const text = advisoryText(failure, {})
  // The lock: named first, with its exact path shape and the reason it produces
  // this sentence with no ACL work having happened at all.
  const lock = text.indexOf('THE PER-PATH LOCK')
  const refused = text.indexOf('THE GRANT WAS REFUSED')
  assert.ok(lock >= 0 && refused >= 0 && lock < refused, 'the lock candidate is stated first')
  assert.match(text, /needs no ACL at all/)
  assert.match(text, /dsh-acl-locks/)
  assert.match(text, /first 16 hex of sha256\(lowercased path\)/)
  assert.match(text, /The grant and the revocation that follows it take the SAME lock/)
  assert.match(text, /dir "<temp root>\\dsh-acl-locks"/)
  assert.match(text, /the only candidate a reader can rule in or out with a directory listing/)
  // The documented prerequisite is still carried, and is a right on the
  // directory rather than a privilege or elevation.
  assert.match(text, /WRITE_OWNER/)
  assert.match(text, /a right on the\s+DIRECTORY rather than `SeSecurityPrivilege` or elevation/)
  // And the third candidate, with the trap a reader would otherwise fall into.
  assert.match(text, /a failing removal is not by itself independent evidence/)
})

test('the two halves of the one backend are told apart in the text', () => {
  const temp = advisoryText(classifyAclAggregateFailure(TEMP_SENTENCE), {})
  const workspace = advisoryText(classifyAclAggregateFailure(WORKSPACE_SENTENCE), {})
  assert.match(temp, /This is the TEMP half/)
  assert.match(temp, /the private capability directory the backend creates per live session\/workspace/)
  assert.doesNotMatch(temp, /This is the WORKSPACE half/)
  assert.match(workspace, /This is the WORKSPACE half/)
  assert.match(workspace, /the standing root ACE itself/)
  assert.match(workspace, /the temp directory was never created at all/)
  assert.doesNotMatch(workspace, /This is the TEMP half/)
  // Both halves are the same sentence's two spellings, and both say so.
  for (const text of [temp, workspace]) {
    assert.match(text, /is two throws: the grant failed, and then the fail-closed cleanup failed with it/)
    // The cleanup is layer-specific, and the text says which is which rather than
    // describing one rollback for both.
    assert.match(text, /the temp sentence's cleanup/)
    assert.match(text, /the workspace sentence's cleanup only/)
  }
})

test('no grant is aimed at the failed directory, and the one that is handed over names its target', () => {
  const text = advisoryText(classifyAclAggregateFailure(TEMP_SENTENCE), { tool: 'pwsh' })
  // 0.27.0 narrowed this contract deliberately, so the two halves of it are stated
  // separately. The rule was "no grant command at all", on the reason that a grant
  // aimed at the wrong directory is worse than none — and that reason still holds
  // for the FAILED directory, which this line never names. What changed is that the
  // family gained one object it CAN name without the withheld line: the temp root,
  // the parent every per-session directory is created under. Every grant in the
  // text must therefore carry that placeholder rather than a bare path, which is
  // what keeps the aiming auditable instead of guessed.
  const grants = [...text.matchAll(/icacls .*\/grant[^\n]*/g)].map(match => match[0])
  assert.equal(grants.length, 2, `the two spellings of the one grant, saw ${grants.length}`)
  for (const line of grants) {
    assert.match(line, /<the root os\.tmpdir\(\) resolves to>/, line)
    // ...and it is the INHERITABLE form, because the directory it must reach does
    // not exist yet when the grant is written.
    assert.match(line, /:\(OI\)\(CI\)\(WO\)/, line)
  }
  assert.match(text, /it ships no grant aimed at the FAILED\s+directory/)
  assert.match(text, /The one grant above is aimed at the temp root instead/)
  assert.match(text, /the only object here that can be named without the withheld line/)
  // What it hands over as the probe: the listing that names the directory, and the
  // backend's own repair skill.
  assert.match(text, /Get-ChildItem -Force "<root>" -Filter dsh-\*/)
  assert.match(text, /diagnose-windows-sandbox-acl/)
  assert.match(text, /It needs ONE unconfined call/)
  // The version boundary that introduced the skill, so a 0.1.7 reader does not go
  // looking for something that line does not ship.
  assert.match(text, /that skill arrives with the 0\.2\.0 line/)
  // The two temp roots, and why repairing the redirected one can change nothing.
  assert.match(text, /`os\.tmpdir\(\)` \(Node\) chooses the private capability directory/)
  assert.match(text, /`GetTempPathW\(\)` \(the Win32 call the lock path uses\)/)
  assert.match(text, /%TMP%/)
  assert.match(text, /%TEMP%/)
  assert.match(text, /%USERPROFILE%/)
  // The two repairs #9460 measured as not working, each with its reason.
  assert.match(text, /takeown \/F "<root>" \/A/)
  assert.match(text, /icacls "<root>" \/reset \/T \/C/)
  // And the config-schema inference the reporter itself flagged as an inference,
  // discarded on the source.
  assert.match(text, /this backend has no capability/)
  assert.match(text, /probe/)
  // With an href the thread line moves and the discussion id stops being a link.
  const linked = advisoryText(classifyAclAggregateFailure(TEMP_SENTENCE), { href: 'https://example.invalid/d/9460' })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/d\/9460/)
  assert.doesNotMatch(linked, /tracked upstream \(discussion/)
})

test('elevation is presented as two variables, so a successful elevated run proves neither', () => {
  // #9831 read the label flag correctly and concluded from it that the label needs
  // `SeSecurityPrivilege`. The claim this section has to answer is the EVIDENCE the
  // reporter offers — "it works elevated" — and the answer is that elevation moves
  // a second variable too. Both halves are asserted, because the section is
  // worthless if it only denies the privilege without naming what else elevation
  // changed.
  const text = advisoryText(classifyAclAggregateFailure(TEMP_SENTENCE), {})
  const flat = text.replace(/\s+/g, ' ')
  assert.match(flat, /IS ELEVATION THE ANSWER\? On a UAC-filtered Administrators token it changes TWO variables/)
  assert.match(flat, /a single successful elevated run supports BOTH readings/)
  assert.match(flat, /into an enabled group/)
  assert.match(flat, /`Administrators:\(OI\)\(CI\)\(F\)` entry/)
  // The read that CANNOT separate them is named as such, since it is the one the
  // reporter reached for.
  assert.match(flat, /`whoami \/priv` is not one of them/)
  assert.match(flat, /it shows the privilege in the elevated run, which is the run whose conclusion is in question/)
  // ...and the two reads that do, both unelevated.
  assert.match(flat, /`whoami \/groups` shows whether/)
  assert.match(flat, /`icacls "<the directory>"` shows whether an ACE naming your OWN account carries \(F\) or \(WO\)/)
  // The section is SHARED, so the plain ACL family carries it too — where the
  // advisory hands over an elevated command in its second branch and a reader would
  // otherwise read success there as confirmation of the privilege.
  const acl = advisoryText(classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'))
  assert.match(acl.replace(/\s+/g, ' '), /IS ELEVATION THE ANSWER\?/)
})

test('the durable instance is the parent, and the skill is named as the wrong tool for it', () => {
  // #9831's own reading of its report is "the root works, every new directory
  // fails" — so a fix aimed at the directory the probe found is a fix aimed at one
  // session. This is the section that says so, and it is only useful if it also
  // names the trap: the recommended skill's ACE is EXPLICIT, so the tool would
  // reproduce exactly the failure it was meant to prevent.
  const text = advisoryText(classifyAclAggregateFailure(TEMP_SENTENCE), {})
  const flat = text.replace(/\s+/g, ' ')
  assert.match(flat, /IF WHAT THE PROBE FOUND IS A PER-SESSION DIRECTORY, ITS PARENT IS THE DURABLE INSTANCE/)
  assert.match(flat, /created per live session\/workspace pair, so it is a different object every session/)
  assert.match(flat, /repairing it repairs this one and leaves the next one failing identically/)
  assert.match(flat, /the root `os\.tmpdir\(\)` resolves to in the harness process/)
  assert.match(flat, /only an INHERITABLE ACE there reaches a directory that does not exist yet/)
  assert.match(flat, /`\(OI\)\(CI\)` is the whole of the difference/)
  // The trap, on the shipped constructor rather than as advice about style.
  assert.match(flat, /the three-argument `FileSystemAccessRule\(SID, FullControl, Allow\)`\s+constructor/)
  assert.match(flat, /which \.NET defines with `InheritanceFlags\.None`/)
  assert.match(flat, /the skill aimed at the temp root repairs the temp root itself/)
  // Both outcomes of the experiment are stated, including the one that would be an
  // upstream finding — so a reader who fails it does not read that as their error.
  assert.match(flat, /Read the result as the experiment it is, and run it unelevated/)
  assert.match(flat, /Under candidate 2 the next private\s+directory provisions and the privilege reading is refuted/)
  assert.match(flat, /that is a finding about the documented prerequisite rather than a reason to run the/)
  // Its own boundary: the lock of candidate 1 sits under the OTHER root.
  assert.match(flat, /this settles the private capability, which is `os\.tmpdir\(\)`'s/)
  assert.match(flat, /lives under the OTHER root, and that one is settled by the listing rather than by any grant/)
})

test('the refusal arrives as a notice beside the failing call, and its members never do', async () => {
  // A real `AggregateError`, exactly as the producer throws it: the members hold
  // the Win32 line naming a directory, and the message holds only the sentence.
  const member = new Error('SetNamedSecurityInfoW failed (Win32 5): grantWrite(C:\\Users\\me\\AppData\\Local\\Temp\\dsh-abc123)')
  const { ctx, logged } = await world(undefined, [
    aggregateTool('pwsh', TEMP_SENTENCE, [member, new Error('Access is denied: removeTempDir')]),
  ])
  const result = await call(ctx, 'pwsh', { command: 'Write-Output "test"' })
  assert.equal(result.isError, true, 'the producer throws, so the call really is an error')
  assert.equal(contexts(result).length, 1, 'the diagnosis rides the failing result')
  const notice = contexts(result)[0]
  assert.equal(notice.role, 'user')
  assert.equal(notice.source.kind, 'sandbox-grant-advisor')
  assert.equal(notice.source.form, 'notice')
  assert.ok(notice.source.summary.length > 0 && notice.source.summary.length <= 120, 'the row stays one line')
  assert.match(notice.source.summary, /ACL grant refused \(private temp capability\)/)
  const body = notice.content.map(block => block.text).join('\n')
  assert.match(body, /Sandbox provisioning failed/)
  assert.match(body, /THE PER-PATH LOCK/)
  // Nothing the producer withheld may be invented back from the members: the
  // session never sees them, so neither may the advisory.
  assert.doesNotMatch(body, /dsh-abc123/, 'the member\'s directory is not on the line, so it is not in the advice')
  assert.doesNotMatch(body, /removeTempDir/)
  assert.doesNotMatch(body, /Win32 5/)
  // The host-side account says what was recognized and what the line withheld.
  const host = logLines(logged, 'sandbox-grant-advisor: ')
  assert.equal(host.length, 1)
  assert.match(host[0], /ACL provisioning refused the private temp capability/)
  assert.match(host[0], /AggregateError message carrying neither the Win32 code nor the directory/)
  assert.match(host[0], /#9460/)
})

test('the workspace half gets its own summary row and its own host line', async () => {
  const { ctx, logged } = await world(undefined, [failingTool('pwsh', WORKSPACE_SENTENCE)])
  const result = await call(ctx, 'pwsh', { command: 'Write-Output "test"' })
  const summary = contexts(result)[0].source.summary
  assert.match(summary, /ACL grant refused \(standing workspace grant\)/)
  assert.match(logLines(logged, 'sandbox-grant-advisor: ')[0], /the standing workspace-root grant/)
})

test('the advisory is delivered once per agent, and a second agent gets its own', async () => {
  const { ctx, logged } = await world(undefined, [failingTool('pwsh', TEMP_SENTENCE)])
  const first = await call(ctx, 'pwsh', { command: 'echo one' })
  assert.equal(contexts(first).length, 1)
  // A different call under the same agent is still not told twice.
  const second = await call(ctx, 'pwsh', { command: 'echo two' })
  assert.equal(contexts(second).length, 0, 'one advisory per agent per family')
  assert.equal(logLines(logged, 'sandbox-grant-advisor: ').length, 1)
  const other = await call(ctx, 'pwsh', { command: 'echo three' }, who('s2'))
  assert.equal(contexts(other).length, 1, 'a second agent is its own session')
  assert.equal(logLines(logged, 'sandbox-grant-advisor: ').length, 2)
})

test('a command whose own output quotes the sentence is an ordinary failure', async () => {
  // The producer's line is what the *throw* carries. A command that merely
  // printed it is a different event, and the classifier's whole-line equality is
  // what separates them — so the plugin says nothing rather than diagnosing a
  // working sandbox as broken.
  const { ctx } = await world(undefined, [failingTool('pwsh', `the sandbox said: ${TEMP_SENTENCE}`)])
  const result = await call(ctx, 'pwsh', { command: 'cat log.txt' })
  assert.equal(result.isError, true)
  assert.equal(contexts(result).length, 0)
})
