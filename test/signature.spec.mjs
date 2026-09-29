/**
 * Signature recognition and advisory text — the pure arms.
 *
 * The strings asserted here are the producer's, not this plugin's invention:
 * `Win32Error` (`packages/subprocess/win32-process/src/errors.ts`) formats every
 * failure as `` `${api} failed (Win32 ${code}): ${detail}` ``, and the ACL
 * backend throws it from `acl.ts` with `detail = grantWrite(<path>)`. Pinning
 * the shape in the test is what makes a future change on the producer side
 * visible as a failure here rather than as silence in a user's session.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  advisoryText,
  denialText,
  ACL_DISCUSSIONS,
  NATIVE_INIT_DISCUSSIONS,
  PREREQUISITE,
  PTY_DISCUSSIONS,
  WORKSPACE_DENIAL_DISCUSSIONS,
} from '../lib/advice.js'
import {
  classifyNativeInitDeath,
  classifyProvisioningFailure,
  classifyPtyStartupFailure,
  classifyWorkspaceDenial,
  failureLine,
  hasWorkspaceDenialStamp,
  isInsideWorkspace,
  STATUS_DLL_INIT_FAILED,
  windowsPathsIn,
} from '../lib/signature.js'
import {
  denied,
  foreground,
  INSIDE,
  MSYS2_STDERR,
  NATIVE_DEATH,
  OUTSIDE,
  WORKSPACE_ROOT,
} from './foreground.mjs'

/** The exact text reported in #7538 / #7622 / #7646. */
const REPORTED = 'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'

test('the reported signature is recognized, with every producer field kept', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure, 'the reported string must classify')
  assert.equal(failure.klass, 'apply-denied')
  assert.equal(failure.api, 'SetNamedSecurityInfoW')
  assert.equal(failure.win32Code, 5)
  assert.equal(failure.detail, 'grantWrite(D:\\ws)')
  assert.equal(failure.label, 'grantWrite')
  assert.equal(failure.path, 'D:\\ws')
})

test('recognition survives the framing a tool result adds', () => {
  for (const wrapped of [
    `Error: ${REPORTED}`,
    `bash failed with exit code 1\nError: ${REPORTED}\nsee log`,
    `[provider] ${REPORTED}`,
  ]) {
    const failure = classifyProvisioningFailure(wrapped)
    assert.ok(failure, `wrapped text must classify: ${wrapped}`)
    assert.equal(failure.path, 'D:\\ws')
  }
})

test('a failure with no detail still classifies, without inventing a path', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  assert.equal(failure.detail, '')
  assert.equal(failure.label, undefined)
  assert.equal(failure.path, undefined)
  assert.equal(failureLine(failure), 'SetNamedSecurityInfoW failed (Win32 5)')
})

test('the read half and a non-ACCESS_DENIED code are their own classes', () => {
  const read = classifyProvisioningFailure('GetNamedSecurityInfoW failed (Win32 5): grantWrite(C:\\ws)')
  assert.equal(read?.klass, 'read-denied')
  const other = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)')
  assert.equal(other?.klass, 'apply-other')
  assert.equal(other?.win32Code, 1332)
})

test('failures this plugin must NOT explain are refused, not guessed at', () => {
  // `SetEntriesInAclW` merges entries in process memory: no object, no rights.
  // Advising an ACL fix there would send a user to change the wrong thing.
  for (const message of [
    'SetEntriesInAclW failed (Win32 8): grantWrite(D:\\ws)',
    'LocalFree failed (Win32 6): grantWrite(D:\\ws) descriptor',
    'LockFileEx failed (Win32 33): C:\\lock',
    'SetConsoleCtrlHandler failed (Win32 6)',
    'SetEnvironmentVariableW TMP failed (Win32 5)',
    'Error: EACCES: permission denied, open \'/etc/hosts\'',
    'bash: command not found: icacls',
    'XSetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
  ]) {
    assert.equal(classifyProvisioningFailure(message), undefined, `must not classify: ${message}`)
  }
})

test('failureLine reproduces the producer format exactly', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  assert.equal(failureLine(failure), REPORTED)
})

test('the advisory names the right that is actually missing, and the wrong lever', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // The line the user is staring at, quoted verbatim.
  assert.match(text, /SetNamedSecurityInfoW failed \(Win32 5\): grantWrite\(D:\\ws\)/)
  // The missing right and the mask that lacks it. The remedy lines themselves are
  // pinned by the dedicated arm below, which asserts the form actually recommended.
  assert.match(text, /WRITE_OWNER/)
  assert.match(text, /0x1301bf/)
  // The natural-but-wrong hypothesis is addressed rather than ignored.
  assert.match(text, /SeSecurityPrivilege is the wrong lever/)
  assert.match(text, /whoami \/priv/)
  // The documented prerequisite, the upstream threads, and the boundary.
  assert.match(text, new RegExp(PREREQUISITE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, new RegExp(ACL_DISCUSSIONS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, /neither edits ACLs nor elevates/)
})

test('the remedy is the right the prerequisite actually names, and the broad form is offered second', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // The narrow grant: WRITE_OWNER alone, which is what the backend documents —
  // it is the same right the diagnosis named, so the reader can see the one-liner
  // and the explanation are about the same thing.
  assert.match(text, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)\(WO\)"/)
  assert.match(text, /icacls "D:\\ws" \/grant "%USERNAME%:\(OI\)\(CI\)\(WO\)"/)
  assert.match(text, /exactly the right the prerequisite names/)
  // ...and the inheritable form, so one command reaches existing subdirectories.
  assert.match(text, /\(OI\)\(CI\) makes the ACE inheritable/)
  // What the inheritable form does NOT cover, which a field report (#8232) had to
  // find out for itself: the ACE is scoped to this directory and its children, so
  // another workspace root on the same volume is a sibling and needs the line again.
  assert.match(text, /scoped to THIS directory and its children/)
  assert.match(text, /another workspace root on the same volume is/)
  assert.match(text, /a sibling rather than a child/)
  assert.match(text, /a second workspace fails on a\s+machine where the first one was already repaired/)
  // Full control still works, and saying so is not a second recipe but the same
  // remedy with more than it needs — hence the derivation, not a second syntax pair.
  assert.match(text, /Full control works just as well — the same line with `F` in place of `\(WO\)`/)
  assert.match(text, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)F"/)
  // The condition under which the one-liner is enough is stated, not assumed:
  // owner-implicit rights cover the DACL half, and the caller owns the directory
  // in the environments this branch describes. Where the caller does not own it,
  // the advisory branches instead of pretending the condition holds.
  assert.match(text, /an owner holds READ_CONTROL and WRITE_DAC implicitly/)
  assert.match(text, /WRITE_OWNER is the single missing piece/)
  // The order is the claim: the narrow form is the one being recommended.
  assert.ok(
    text.indexOf('(WO)') < text.indexOf('(OI)(CI)F'),
    'the narrow grant must be offered before the broad one, not after it',
  )
})

test('the advisory says the failure is the workspace\'s, not the command\'s', () => {
  // #8232's severity point: the failure lands at workspace provisioning, so every
  // command in the session fails — including one that would only read. A reader who
  // believes otherwise retries with something "harmless" and learns nothing, which
  // is the loop this plugin exists to cut short.
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure, { tool: 'pwsh' })
  assert.match(text, /The failure belongs to the WORKSPACE, not to the command/)
  assert.match(text, /a command that only reads\s+fails identically/)
  assert.match(text, /is not a retry that can succeed/)
  // It is stated for the ACL family only: the other two families have their own
  // retry instructions, and none of them may borrow this one.
  const native = advisoryText(classifyNativeInitDeath(foreground(NATIVE_DEATH)), { mode: 'workspace-write' })
  assert.doesNotMatch(native, /The failure belongs to the WORKSPACE/)
  const pty = advisoryText(classifyPtyStartupFailure(PTY_EXIT), { mode: 'workspace-write' })
  assert.doesNotMatch(pty, /The failure belongs to the WORKSPACE/)
})

test('both environments that share this signature are named, because the text cannot tell them apart', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // #7622 / #7646 / #7720: an inherited Modify-only entry.
  assert.match(text, /Authenticated Users: Modify" \(`0x1301bf`\) from the drive root/)
  // #7750 / #7735: a data volume where that inherited entry is all the caller has.
  assert.match(text, /on a data\s+volume there may be no ACE naming you at all/)
  assert.match(text, /that inherited entry is the whole of your access/)
  // And why a refused label costs execution, not just a label: one merged call,
  // atomically rejected, fail-closed.
  assert.match(text, /halves go out as one call, so a refused label discards the write grant/)
  assert.match(text, /refuses to start any command in the workspace instead of running it unconfined/)
  // The discriminator covers both shapes — no ACE naming you is still this failure.
  assert.match(text, /no entry names you at all and/)
})

test('the version boundary the error does not carry is stated, with the build and the flag', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // Where the label arrives — the fact neither report could read off the error.
  assert.match(text, /the label half is new to this package/)
  assert.match(text, /Up to `0\.1\.6-alpha\.x` the backend touched the DACL only \(flag 4\)/)
  assert.match(text, /`0\.1\.7-alpha\.1` is where the mandatory label/)
  assert.match(text, /with it the SACL, flag 20/)
  // It is a *discriminator*: the same string on an older line is another story.
  assert.match(text, /belongs to a different cause space/)
  assert.match(text, /on any\s+`0\.1\.7-\*` line it is this one/)
  // And the reach it invites is refused with the reason: the label is the fix
  // for out-of-workspace deletion, so downgrading trades one defect for another.
  assert.match(text, /Rolling back is not the fix either/)
  assert.match(text, /reverting it reintroduces the escape it closed/)
})

test('the version boundary is emitted in every class this module speaks in', () => {
  // The boundary is a fact about the backend's flag, not about which of its calls
  // failed, so withholding it in the other two classes would hide it exactly where
  // a user is most likely to reach for an older build.
  for (const message of [
    REPORTED,
    'SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)',
    'GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
  ]) {
    const text = advisoryText(classifyProvisioningFailure(message))
    assert.match(text, /0\.1\.7-alpha\.1/, `the boundary must be present for: ${message}`)
    assert.match(text, /Rolling back is not the fix either/, `the boundary's second half must be present for: ${message}`)
    // The second boundary is a fact about the *line*, not about the failing
    // call, so it travels with the first: the built-in repair the later reports
    // went looking for is not in `0.1.7-*` at all.
    assert.match(text, /it arrives with `0\.2\.0`/, `the skill boundary must be present for: ${message}`)
  }
})

test('the built-in repair is placed on the line it actually ships on, not called a packaging gap', () => {
  // #8272 read the skill's name in a README while running 0.1.7-rc.2 and
  // reported the package as having dropped it. Measured on both published
  // tarballs (2026-09-29): 0.1.7-rc.2 names `diagnose-windows-sandbox-acl` zero
  // times in either README, ships no `assets/` at all, and no file in its tree
  // carries the registration symbol; 0.2.0-rc.2 ships
  // `assets/diagnose-windows-sandbox-acl/` and names it three times per README.
  // Sending a reader to repair the `files` glob would be the wrong repair, so
  // the advisory has to say the skill is new rather than missing.
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  assert.match(text, /`diagnose-windows-sandbox-acl` skill is not part of `0\.1\.7-\*` at all/)
  assert.match(text, /starts shipping it under `assets\/`/)
  assert.match(text, /was reading a `0\.2\.0`-era document/)
  assert.match(text, /nothing was\s+dropped from the `0\.1\.7` file list, because there was nothing in `0\.1\.7` to drop/)
})

test('an href replaces the thread line without dropping the fix', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure, { href: 'https://example.invalid/t/1' })
  assert.match(text, /tracked upstream: https:\/\/example\.invalid\/t\/1/)
  assert.match(text, /WRITE_OWNER/)
})

test('the two remedies that look right and are not are named, with the reason each fails', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // Both came from #7720, quoted with the directory the error named.
  assert.match(text, /takeown \/F "D:\\ws" \/R \/D Y/)
  assert.match(text, /icacls "D:\\ws" \/reset \/T \/C/)
  // The reasons are different, and each is the fact that makes the command fail:
  // the owner's implicit rights, and what `/reset` puts back.
  assert.match(text, /ownership's implicit rights are READ_CONTROL and WRITE_DAC only/)
  assert.match(text, /still not WRITE_OWNER, the right this call needs/)
  assert.match(text, /restores inheritance, and inheritance is what supplied the Modify-only ACE/)
  // Both are still promised as *not* the fix, never as the remedy. `takeown` is
  // claimed to fail only as a complete fix — it is a real first step with
  // elevation where the caller is not the owner, and denying that would be the
  // mirror-image error.
  assert.match(text, /What will NOT fix it on its own/)
  assert.match(text, /it is never the fix by itself/)
})

test('the weaker-grant idea is answered with the mechanism, not with a bare no', () => {
  // #8275's proposal: degrade provisioning to DACL-only when the label is what
  // gets refused. The advisory must not pretend that is a switch — the label
  // rides the same `SetNamedSecurityInfoW` as the DACL, and there is no
  // DACL-only apply path in `grantWrite` to fall back to — but it also must not
  // stop at "no": a reader told only "no" reaches for a workaround without
  // knowing what else it has to change.
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  assert.match(text, /One thing to know before asking for a weaker grant/)
  // The reason there is nothing to fall back to: one call, two flags.
  assert.match(text, /The label rides the SAME `SetNamedSecurityInfoW` as the DACL \(one call, two security-information flags\)/)
  assert.match(text, /there is no DACL-only path to fall back to — it would have to be built/)
  // The reason dropping the label alone does not work: the token is Low too, so
  // the object's Low label is what lets the confined child write at all.
  assert.match(text, /the backend lowers the confined token to Low before any child starts/)
  assert.match(text, /the level the mandatory labels `grantWrite` applies are matched against/)
  assert.match(text, /one the sandbox can start a command in and the command then cannot write to/)
  assert.match(text, /Declining the label usefully means declining the token's Low level with it/)
  // ...and it is still refused as a remedy, in the same breath, because the
  // answer is a reason and not an offer.
  assert.match(text, /This is not offered here as a fix, and neither is `danger-full-access`/)
})

test('the weaker-grant section is emitted only for the class whose diagnosis is the missing right', () => {
  // `read-denied` wants READ_CONTROL and `apply-other` is not an access denial at
  // all, so neither one's diagnosis invites declining the label. Emitting the
  // section there would attach a claim to a class that has not established its
  // premise — the failure mode this module is built to avoid.
  for (const message of [
    'SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)',
    'GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
  ]) {
    const text = advisoryText(classifyProvisioningFailure(message))
    assert.doesNotMatch(text, /One thing to know before asking for a weaker grant/, message)
    assert.doesNotMatch(text, /there is no DACL-only path to fall back to/, message)
  }
})

test('the remedy forks on ownership, because one command cannot serve both environments', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // The branch selector is a check the user runs, not a guess: the text is
  // identical in both environments, so the advisory cannot pick a branch for
  // them — it hands over the ownership read instead.
  assert.match(text, /Ownership decides which of the two commands below can work/)
  assert.match(text, /\(Get-Acl "D:\\ws"\)\.Owner/)
  assert.match(text, /compare with: whoami/)
  assert.match(text, /the first one is refused before it runs/)
  // Branch one: the caller owns it, and the narrow grant runs unelevated.
  assert.match(text, /IF YOU OWN THE DIRECTORY/)
  assert.match(text, /an owner holds READ_CONTROL and WRITE_DAC implicitly/)
  assert.match(text, /WRITE_DAC is what `icacls \/grant` itself needs/)
  // Branch two: an owner that is not the caller — `#7771`'s shape.
  assert.match(text, /IF YOU DO NOT OWN IT/)
  assert.match(text, /`BUILTIN\\Administrators`/)
  assert.match(text, /Changing a DACL takes WRITE_DAC/)
  assert.match(text, /`icacls \/grant` is refused with `Access is denied` — for the very command that would/)
  assert.match(text, /so `\(WO\)` alone would not be enough/)
  // ...and the path out of it: elevation, the two reaches the reports name, and
  // the sidestep that needs no ACL edit at all.
  assert.match(text, /ELEVATED prompt/)
  assert.match(text, /icacls "D:\\ws" \/grant "<your-account>:\(OI\)\(CI\)F"/)
  assert.match(text, /icacls "D:\\ws" \/setowner "<your-account>"/)
  assert.match(text, /it wants SeTakeOwnership/)
  assert.match(text, /after which the unelevated/)
  assert.match(text, /create the workspace under `%USERPROFILE%`/)
  // The fork is a fork: the owner branch is offered as branch one, so the narrow
  // unelevated line still comes before any elevated command.
  assert.ok(
    text.indexOf('IF YOU OWN THE DIRECTORY') < text.indexOf('IF YOU DO NOT OWN IT'),
    'the owner branch must come first — it is the environment the reports describe most often',
  )
})

test('the non-fix section is emitted only where its claim is true', () => {
  // `read-denied` wants READ_CONTROL, which taking ownership does carry — so the
  // section would be false there, not merely unhelpful.
  const read = advisoryText(classifyProvisioningFailure('GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'))
  assert.doesNotMatch(read, /takeown/)
  assert.doesNotMatch(read, /reset \/T \/C/)
  assert.doesNotMatch(read, /What will NOT fix it/)
  // `apply-other` says the missing-rights story does not apply verbatim, so a
  // section presupposing it would contradict the paragraph above it.
  const other = advisoryText(classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)'))
  assert.doesNotMatch(other, /takeown/)
  assert.doesNotMatch(other, /What will NOT fix it/)
})

test('the non-fix section follows the placeholder rule too', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  const text = advisoryText(failure)
  assert.match(text, /takeown \/F "<the directory from the error line above>" \/R \/D Y/)
  assert.doesNotMatch(text, /takeown \/F ""/)
})

test('the grant is described from the other side, because this module is what hands it over', () => {
  // #8312 / #8314 report the end of the same backend the other twelve reports
  // describe: not the write that fails, but what the successful one leaves
  // behind. The facts are read off the shipped source, and the two that a reader
  // cannot discover from the error are the ones this asserts first.
  const text = advisoryText(classifyProvisioningFailure(REPORTED))
  const flat = text.replace(/\s+/g, ' ')
  assert.match(flat, /What the grant leaves behind, once it applies/)
  // Standing by design — the dispose path and the fail-closed path both say so,
  // in the backend's own words, which is why they are quoted instead of
  // paraphrased.
  assert.match(flat, /The three entries are STANDING, deliberately, and nothing revokes them/)
  assert.match(flat, /the intended end state \(the reuse cache\), not an error artifact/)
  assert.match(flat, /They outlive the session and the harness/)
  assert.match(flat, /`sandbox-windows-acl\/src\/grant\.ts`, `src\/index\.ts`/)
  // The label is the half a DACL reset cannot reach, and the reason every child
  // started from the tree runs at Low integrity.
  assert.match(flat, /The Low integrity label is INHERITABLE \(`\(OI\|CI\)`\) and it lives in the SACL/)
  assert.match(flat, /that command rebuilds the DACL/)
  assert.match(flat, /Windows starts a process at the minimum of the user's and the program's integrity/)
  // The reach past the tree, attributed to the report that measured the chain
  // rather than asserted as our own measurement — this project has no Windows
  // host, and the backend's own suite is what pins the link boundary.
  assert.match(flat, /An NTFS hard link is a SECOND NAME for one file object/)
  assert.match(flat, /a workspace hard link lets the grant reach an external file object/)
  assert.match(flat, /\(#8314 measured the whole chain\)/)
  // Both halves of the pair are named upstream, so a reader can follow either.
  assert.ok(ACL_DISCUSSIONS.includes('#8312') && ACL_DISCUSSIONS.includes('#8314'), ACL_DISCUSSIONS)
})

test('the label gets no removal command, and the reason replaces it', () => {
  // The one command that would remove an inheritable integrity label must not be
  // published here. This project cannot verify a line on Windows, and an
  // unverified removal handed to a reader is the same defect the rest of this
  // module exists to answer — the maintainers' own diagnosis skill stops at
  // reporting it too.
  const text = advisoryText(classifyProvisioningFailure(REPORTED))
  const flat = text.replace(/\s+/g, ' ')
  assert.match(flat, /This advisory hands over no removal command/)
  assert.match(flat, /removing an integrity label needs/)
  assert.match(flat, /reports `LOW_LABEL` and by design does not remove it/)
  // `/setintegritylevel` is the command that removes one; `/grant` and `/reset`
  // above are the DACL half and stay.
  assert.doesNotMatch(text, /setintegritylevel/i)
})

test('each class explains itself instead of borrowing another class\'s story', () => {
  const denied = advisoryText(classifyProvisioningFailure(REPORTED))
  const other = advisoryText(classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)'))
  const read = advisoryText(classifyProvisioningFailure('GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'))
  assert.notEqual(denied, other)
  assert.notEqual(denied, read)
  assert.match(other, /not ERROR_ACCESS_DENIED \(5\)/)
  assert.doesNotMatch(other, /MERGED write — the DACL/)
  assert.match(read, /could not even read the directory's security descriptor/)
  assert.doesNotMatch(read, /MERGED write — the DACL/)
})

test('a failure with no path hands the user a placeholder, not a broken command', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  const text = advisoryText(failure)
  assert.match(text, /icacls "<the directory from the error line above>"/)
  assert.doesNotMatch(text, /icacls ""/)
})

test('the denial says what happened, how bounded it is, and what to do', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const first = denialText(failure, 2, 1, 2)
  assert.match(first, /already failed 2 times/)
  assert.match(first, /SetNamedSecurityInfoW failed \(Win32 5\): grantWrite\(D:\\ws\)/)
  assert.match(first, /automatic block 1 of 2/)
  // The denial hands over the *same* remedy the advisory recommends, narrow form
  // first: a model told to run a different command than the advisory printed is
  // two answers to one question.
  assert.match(first, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)\(WO\)"/)
  const last = denialText(failure, 3, 2, 2)
  assert.match(last, /automatic block 2 of 2/)
  assert.match(last, /the last one/, 'the model must know the budget is spent, not expect another block')
  assert.doesNotMatch(last, /after that the call is allowed again/, 'the last block must not promise a further block')
})

test('a denial for a failure with no path omits the fix line rather than faking one', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  const text = denialText(failure, 2, 1, 1)
  assert.doesNotMatch(text, /icacls/)
  assert.match(text, /Stop, and either apply the fix or hand the problem to the user/)
})

/**
 * The second family's producer strings, taken from the throwing sites:
 * `packages/terminal/terminal-bash/src/session.ts` and `src/index.ts`, both on
 * the `waitReason === 'session_exit'` branch — the report #7638 is against.
 */
const PTY_EXIT = 'PTY shell exited during startup'

test('the persistent-shell failure is recognized, and only as a whole line', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure, 'the reported string must classify')
  assert.equal(failure.family, 'pty-startup')
  assert.equal(failureLine(failure), PTY_EXIT)
  // The envelope a tool result adds is the only decoration that is still the
  // producer speaking.
  assert.ok(classifyPtyStartupFailure(`Error: ${PTY_EXIT}`))

  // Anything else that contains the sentence is quoting it, not producing it:
  // a transcript, a log the failing command printed, a pasted report. The
  // producer's message has no fields, so there is nothing else to anchor on —
  // the whole line IS the signature.
  for (const message of [
    `bash: cat terminal.log | grep -c 'PTY shell exited during startup'`,
    `See #7638: PTY shell exited during startup when minimal meets a sandbox`,
    `${PTY_EXIT} (see docs)`,
    `error: ${PTY_EXIT}`,
    'PTY shell did not reach readiness before startup timeout',
    'PTY session is closing',
    'PTY session has exited',
  ]) {
    assert.equal(classifyPtyStartupFailure(message), undefined, `must not classify: ${message}`)
  }
  // A stack trace after the producer's line is the producer's line: the message
  // a thrown `Error` carries never includes the frames, but an envelope of them
  // does not change which sentence failed.
  assert.ok(classifyPtyStartupFailure(`${PTY_EXIT}\n  at LocalPtySession.initialize`))
})

test('neither family claims the other family\'s message', () => {
  // The entry classifies the ACL family first and the persistent-shell family
  // second, so each producer's text has to belong to exactly one of them —
  // otherwise the second family's diagnosis would never be reached. (A
  // synthetic string carrying BOTH producers' lines is not a message any single
  // producer writes; the ACL branch simply wins it, which is what the entry's
  // order documents.)
  assert.equal(classifyProvisioningFailure(PTY_EXIT), undefined)
  assert.equal(classifyPtyStartupFailure(REPORTED), undefined)
  assert.equal(classifyProvisioningFailure(REPORTED)?.family, 'acl-provisioning')
  assert.equal(classifyPtyStartupFailure(PTY_EXIT)?.family, 'pty-startup')
  // The shell rule is a whole-line rule, not a substring rule: a line that
  // merely contains the ACL producer's API name is not the other family.
  assert.equal(classifyPtyStartupFailure(`Error: ${REPORTED}`), undefined)
})

test('the persistent-shell advisory names the mode, the combination, and the user-side paths', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  const text = advisoryText(failure, { mode: 'workspace-write', tool: 'pwsh' })
  // Sentences are asserted against a whitespace-flattened copy: the advisory is
  // hard-wrapped for a terminal, and a phrase crossing a wrap is still one claim.
  const flat = text.replace(/\s+/g, ' ')
  // The line the user is staring at, quoted verbatim.
  assert.match(flat, /^Persistent shell failed to start[\s\S]*PTY shell exited during startup/)
  // The discriminator the reporter's own control isolated, and the mode actually in force.
  assert.match(flat, /PERSISTENT PTY session/)
  assert.match(flat, /sandbox mode is `workspace-write` — not `danger-full-access`/)
  assert.match(flat, /persistent PTY × confining sandbox is the combination that fails/)
  // The call being advised about, named.
  assert.match(flat, /The `pwsh` tool is a PERSISTENT PTY session/)
  // The instruction the model must follow...
  assert.match(flat, /Do NOT retry, and do not look for a command that fixes it/)
  assert.match(flat, /there is no shell to run a command in/)
  assert.match(flat, /Use your file read\/write tools instead/)
  // ...and the remedy addressed to the user, matching the report's own workarounds.
  assert.match(flat, /switch the agent preset to `standard`/)
  // The override route, named as the patch layer it actually is. This arm is
  // also the regression guard for a remedy that reads plausibly and does not
  // work: `$DSH_HOME/.agent-presets/<id>/` is the pre-declarative preset
  // directory, and nothing reads it any more.
  assert.match(flat, /override the `preset-minimal` row in your profile patch/)
  assert.match(flat, /\$DSH_HOME\/profiles\/<profile>\/cordis\.patch\.yml/)
  assert.match(flat, /\$DSH_HOME\/cordis\.patch\.yml/)
  assert.doesNotMatch(flat, /\.agent-presets/)
  assert.match(flat, /@deepseek-ai\/dsh-tool-pwsh/)
  assert.match(flat, /run the session with `danger-full-access`/)
  assert.match(flat, new RegExp(PTY_DISCUSSIONS))
  // What it must NOT say: the ACL family's story, or a command to paste.
  assert.doesNotMatch(text, /icacls/)
  assert.doesNotMatch(text, /WRITE_OWNER/)
  assert.doesNotMatch(text, /USERNAME/)
  // The negative decision is stated, not implied: silence would read as "not the sandbox".
  assert.match(flat, /this plugin stays silent, because a shell can fail to start for other reasons/)
})

test('the persistent-shell advisory names the host binary, not chance', () => {
  // #8322 separated the arms inside one confining mode with the same runner and
  // the same ConPTY throughout: what changes the outcome is the host binary that
  // carries the runner. An advisory that leaves this out invites the reader to
  // conclude the failure is flaky, when the same (mode × host) pair fails every
  // single time.
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  const text = advisoryText(failure, { mode: 'workspace-write' })
  const flat = text.replace(/\s+/g, ' ')
  assert.match(flat, /deterministic per \(session mode × the host/)
  assert.match(flat, /a "working now" attempt in the same session is not evidence of flakiness/)
  // Both arms, named: the two hosts differ only by their subsystem, and the
  // console rule behind it is the one the third family already states.
  assert.match(flat, /console-subsystem `node\.exe` → the confined shell starts/)
  assert.match(flat, /GUI-subsystem Electron executable/)
  assert.match(flat, /a console can be INHERITED but not CREATED/)
  // The mode that decides is the recorded one — the second half of #8322, and the
  // reason a restart with a different environment does not clear the failure.
  assert.match(flat, /the mode that decides is the one the SESSION records/)
  // The console-owning host that works is named as a user-side option, from the
  // report that found the same variable from the outside.
  assert.match(flat, /#8313/)
  assert.ok(PTY_DISCUSSIONS.includes('#8322'), PTY_DISCUSSIONS)
  // Still no command: there is no shell to run one in.
  assert.doesNotMatch(text, /icacls/)
})

test('the persistent-shell advisory covers the unowned tool and url variants', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  // Without a tool name the advice is still addressed to the call that failed.
  assert.match(advisoryText(failure, { mode: 'read-only' }), /This tool is a PERSISTENT PTY session/)
  // An href replaces the thread line, exactly as in the ACL family.
  const linked = advisoryText(failure, { mode: 'read-only', href: 'https://example.invalid/t/9' })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/t\/9/)
  assert.doesNotMatch(linked, new RegExp(PTY_DISCUSSIONS))
  assert.match(linked, /`read-only`/)
})

test('the persistent-shell advisory refuses to be built without the mode it explains', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  // The gate in `src/index.ts` resolves the mode before it can get here, so this
  // is the invariant that keeps a mode-less advisory from ever existing.
  assert.throws(() => advisoryText(failure), /requires the resolved sandbox mode/)
  assert.throws(() => advisoryText(failure, { tool: 'pwsh' }), /requires the resolved sandbox mode/)
})

test('each family explains itself instead of borrowing the other\'s story', () => {
  const acl = advisoryText(classifyProvisioningFailure(REPORTED))
  const pty = advisoryText(classifyPtyStartupFailure(PTY_EXIT), { mode: 'read-only' })
  assert.notEqual(acl, pty)
  assert.match(pty, /`read-only`/, 'the mode is quoted as resolved, without translation')
  assert.doesNotMatch(pty, /MERGED write|SACL|SeSecurityPrivilege/)
})

test('the loader status is recognized from the canonical value, in both spellings of the sign', () => {
  // #7877 pastes the signed form; the unsigned NTSTATUS spelling is the same
  // number. `>>> 0` is what makes the classifier indifferent to which one arrives.
  for (const exitCode of [-1073741502, 3221225794, 0xC0000142]) {
    const failure = classifyNativeInitDeath(foreground(exitCode))
    assert.ok(failure, `must classify: ${String(exitCode)}`)
    assert.equal(failure.family, 'native-init')
    assert.equal(failure.rawExitCode, exitCode, 'the code as reported is kept, so it can be quoted back')
    assert.equal(failure.exitCode, STATUS_DLL_INIT_FAILED)
    assert.equal(failureLine(failure), `[exit code: ${String(exitCode)}]`)
  }
  assert.equal(STATUS_DLL_INIT_FAILED, 0xC0000142)
})

test('a value that is not the shipped foreground projection is refused', () => {
  // The family is read from a result the pipeline calls a success, so the
  // discriminator that keeps other tools out is the projection's own `kind` —
  // and the neighbouring statuses are other stories this module must not tell.
  for (const value of [
    undefined,
    null,
    'foreground',
    42,
    [],
    {},
    { exitCode: -1073741502 },
    { kind: 'background', exitCode: -1073741502 },
    { kind: 'foreground' },
    { kind: 'foreground', exitCode: null },
    { kind: 'foreground', exitCode: '-1073741502' },
    { kind: 'foreground', exitCode: 1.5 },
    // Other Windows statuses with their own causes: the Cygwin/MSYS2 runtime's
    // deliberate fast-fail, and a missing DLL (a packaging problem, not a
    // sandbox one). Neither is this family.
    { kind: 'foreground', exitCode: -1073740791 }, // 0xC0000409
    { kind: 'foreground', exitCode: -1073741515 }, // 0xC0000135
    { kind: 'foreground', exitCode: 127 }, // the one code the runner-failure rule owns
    { kind: 'foreground', exitCode: 1 },
    { kind: 'foreground', exitCode: 0 },
  ]) {
    assert.equal(classifyNativeInitDeath(value), undefined, `must not classify: ${JSON.stringify(value)}`)
  }
})

test('the native-init advisory names the class, both producers, and their checks', () => {
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH, MSYS2_STDERR))
  assert.ok(failure)
  const text = advisoryText(failure, { mode: 'read-only', tool: 'pwsh', electronHost: false })
  const flat = text.replace(/\s+/g, ' ')
  // The code, quoted as the tool reported it and named for what it is.
  assert.match(flat, /\[exit code: -1073741502\]/)
  assert.match(flat, /0xC0000142 STATUS_DLL_INIT_FAILED/)
  // The claim that makes it a diagnosis rather than a restatement: the process
  // never reached its entry point, and the number is not a portable status.
  assert.match(flat, /BEFORE the program's entry point/)
  assert.match(flat, /those are 0-255, and this is a 32-bit NTSTATUS/)
  // The mode the call ran under is stated, and is where the sandbox becomes a
  // candidate rather than an assertion.
  assert.match(flat, /sandbox mode `read-only`/)
  assert.match(flat, /Nothing in the code says "sandbox" by itself/)
  // It enumerates rather than asserts: the header is the claim that this is a
  // list to be checked, not a cause that was identified.
  assert.match(flat, /Two producers have been measured under a confining Windows mode\. Check which one this is:/)
  // Producer 1: the MSYS2 runtime, with the report's own line and the one
  // conversion the model can actually make.
  assert.match(flat, /couldn't create signal pipe, Win32 error 5/)
  assert.match(flat, /#7877/)
  assert.match(flat, /write the same work as a PowerShell or `cmd` command instead/)
  // Producer 2: the packaged desktop runner, with the mechanism #8208 measured
  // and the two console-less shapes it has been observed in.
  assert.match(flat, /\[process\.execPath, runner\.js\]/)
  assert.match(flat, /#8193/)
  assert.match(flat, /the runner's CONSOLE, not its token/, 'the mechanism is named, not the token story')
  assert.match(flat, /conhost\.exe` is created BY the restricted child/)
  assert.match(flat, /0xC0000022 STATUS_ACCESS_DENIED/)
  assert.match(flat, /#8208/)
  assert.match(flat, /Both console-less configurations are measured/)
  assert.match(flat, /the host binary is a GUI-subsystem program/)
  // The machine-independent shape, which is why the text can hand the reader a
  // check that needs no desktop and no particular machine.
  assert.match(flat, /spawnSync\(node, \[runner, …\], \{ detached: true \}\)/)
  assert.match(flat, /needs no desktop and no particular machine/)
  // The discriminator 0.7.x named is refuted by measurement, and the text says so
  // rather than quietly dropping it.
  assert.match(flat, /What is NOT the discriminator: the token/)
  assert.match(flat, /a low-integrity `cmd\.exe` runs fine on that machine/)
  // And the withdrawn cause: "the runner does not start at all" cannot arise in
  // this build, because the desktop starts its own host child with exactly the
  // variable that sentence said was missing (`apps/desktop/src/host-process.ts`
  // -> `desktopNodeEnvironment()`).
  assert.doesNotMatch(flat, /nothing on the runner path ran/)
  assert.doesNotMatch(flat, /the runner does not start at all/)
  assert.doesNotMatch(flat, /ELECTRON_RUN_AS_NODE=1/)
  assert.doesNotMatch(flat, /the runner never ran/)
  // The measured fact about THIS process, not an assumption about it: this arm
  // runs off the packaged desktop, so the producer that needs Electron is ruled
  // out — and it says why.
  assert.match(flat, /This process is NOT an Electron binary/)
  assert.match(flat, /the runner is a real Node binary here/)
  assert.doesNotMatch(flat, /This process IS an Electron binary/)
  // The instruction, and the boundary that keeps the claim honest.
  assert.match(flat, /Do not retry this call/)
  assert.match(flat, /Convert the work only in case 1; otherwise stop and hand it to the user/)
  assert.match(flat, /producers this list does not have/)
  assert.match(flat, /records the console case as an inherent limit of the backend/)
  // What it must NOT say: the other families' stories, or an offer to widen the
  // sandbox as a remedy.
  assert.doesNotMatch(text, /icacls|WRITE_OWNER|SeSecurityPrivilege/)
  assert.doesNotMatch(text, /PTY shell exited during startup/)
  assert.doesNotMatch(flat, /use danger-full-access to fix/)
  assert.match(flat, /`danger-full-access` is not offered as a fix/)
  assert.match(flat, new RegExp(NATIVE_INIT_DISCUSSIONS))
})

test('the Electron fact is reported, so the same code reads differently on the two hosts', () => {
  // The check is a fact the plugin measures rather than one it asks the reader
  // for, so the two answers must actually differ — a producer list that reads the
  // same either way would be a guess wearing a measurement's clothes.
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH))
  assert.ok(failure)
  const onElectron = advisoryText(failure, { mode: 'workspace-write', electronHost: true })
  const offElectron = advisoryText(failure, { mode: 'workspace-write', electronHost: false })
  assert.notEqual(onElectron, offElectron)
  assert.match(onElectron.replace(/\s+/g, ' '), /This process IS an Electron binary/)
  assert.doesNotMatch(onElectron.replace(/\s+/g, ' '), /This process is NOT an Electron binary/)
  // Everything else about the two texts is identical: only the finding — and the
  // next step it implies — differs. The rest of the advisory is one text, not two.
  const head = text => text.slice(0, text.indexOf('     This process '))
  const tail = text => text.slice(text.indexOf('Do not retry this call'))
  assert.equal(head(onElectron), head(offElectron))
  assert.equal(tail(onElectron), tail(offElectron))
  // Each branch ends with a next step rather than a dead end: the Electron host
  // is sent to a real node host — the fix #8193 measured, and the one the
  // reporter asked for — while the other one is told the failure is outside
  // both measured producers.
  const flatOn = onElectron.replace(/\s+/g, ' ')
  assert.match(flatOn, /dependencies\/node\/bin\/node\.exe/, 'the desktop\'s own standalone node is named')
  assert.match(flatOn, /unpacked `node apps\/cli\/lib\/bin\.js web`/)
  assert.match(flatOn, /`danger-full-access` only CONFIRMS the diagnosis/)
  assert.doesNotMatch(flatOn, /run the same command with `danger-full-access`/, 'the widened mode is no longer the remedy offered')
  assert.match(offElectron.replace(/\s+/g, ' '), /outside both measured producers/)
  // With no explicit answer the plugin asks the live process, which on the host
  // this suite runs on is not Electron — and says so rather than staying silent.
  assert.match(advisoryText(failure, { mode: 'workspace-write' }), /This process is NOT an Electron binary/)
})

test('the Electron host names the console mechanism, both of its shapes, and the condition on the remedy', () => {
  // The defect this pins against, in the shape it shipped: `0.6.0` asserted one
  // cause ("starts as an *application* unless `ELECTRON_RUN_AS_NODE=1` — so the
  // runner never runs"), `0.7.x` replaced it with two named measurements that
  // still explained the failure by the restricted token derived from an Electron
  // image. `#8208` measures the token to be identical between a working and a
  // failing host, and traces the failure to the runner's console. What has to
  // survive here is the mechanism, the two shapes it takes, and the *condition*
  // the remedy carries — because a real node host alone is not the fix either.
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH))
  assert.ok(failure)
  const flat = advisoryText(failure, { mode: 'workspace-write', electronHost: false }).replace(/\s+/g, ' ')
  assert.match(flat, /The mechanism behind this one is the runner's CONSOLE, not its token/)
  assert.match(flat, /a console can be INHERITED but not CREATED/)
  assert.match(flat, /Both console-less configurations are measured/)
  // The non-Electron branch keeps the shape that is still open to it, and stops
  // short of naming a cause it cannot see.
  assert.match(flat, /One measured shape is still open/)
  assert.match(flat, /fails exactly this way on a real node host too \(#8208\)/)
  assert.match(flat, /outside both measured producers/)
  const onElectron = advisoryText(failure, { mode: 'workspace-write', electronHost: true }).replace(/\s+/g, ' ')
  assert.match(onElectron, /ONE CONDITION RIDES WITH THAT/)
  assert.match(onElectron, /the runner must be spawned WITH a console/)
  assert.match(onElectron, /not with `DETACHED_PROCESS`/)
  assert.match(onElectron, /the host binary is what supplies the console/)
  assert.match(onElectron, /the spawn flag is what can take it away again/)
  // The host-independent fallback, named as what it is: a change inside the one
  // funnel every restricted child goes through, with its own measured effect.
  assert.match(onElectron, /AllocConsole/)
  assert.match(onElectron, /createRestrictedProcess/)
  assert.match(onElectron, /a no-op on a runner that already owns a console/)
  assert.doesNotMatch(onElectron, /the runner never ran/)
  assert.doesNotMatch(onElectron, /the runner never runs/)
  assert.doesNotMatch(onElectron, /ELECTRON_RUN_AS_NODE=1/)
  // The remedy is the host, but the wrapper it disclaims is the other variable:
  // `ELECTRON_RUN_AS_NODE` is what lets that Electron binary run `runner.js` at
  // all, which is the interaction `#8193` records with `#8174`.
  assert.match(onElectron, /Do not unset `ELECTRON_RUN_AS_NODE`/)
  assert.match(onElectron, /would take `runner\.js` down with it/)
  assert.match(onElectron, /#8193 records this interaction with #8174/)
  // The honest boundary repeats the backend's own recording of the console
  // limitation and then *explains* it, with all three flag sets that are actually
  // passed — `0` on the piped path is the one 0.7.x left out, and it is the path
  // a shell call takes.
  const boundary = advisoryText(failure, { mode: 'workspace-write', electronHost: false }).replace(/\s+/g, ' ')
  assert.match(boundary, /three sets and none of them is `CREATE_NO_WINDOW`/)
  assert.match(boundary, /`0` on the piped path/)
  assert.match(boundary, /`CREATE_SUSPENDED` on the inherited-job path/)
  assert.match(boundary, /`CREATE_SUSPENDED \| CREATE_UNICODE_ENVIRONMENT` on the ordinary path/)
  assert.match(boundary, /it is the console and not the flag list that decides/)
  assert.doesNotMatch(boundary, /necessary ingredient/)
  assert.doesNotMatch(boundary, /which is why that backend avoids `CREATE_NO_WINDOW`/)
  // The rejected arm, with both halves of its measurement: it stops the crash and
  // silently discards the output of the interpreter most likely to be used.
  assert.match(boundary, /applied, measured, and rejected/)
  assert.match(boundary, /on the RESTRICTED CHILD/)
  assert.match(boundary, /zero bytes on stdout AND stderr/)
  assert.match(boundary, /`cmd\.exe` keeps its output/)
})

test('the native-init advisory refuses to be built without the mode it explains', () => {
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH))
  assert.ok(failure)
  assert.throws(() => advisoryText(failure), /requires the resolved sandbox mode/)
  assert.throws(() => advisoryText(failure, { tool: 'pwsh' }), /requires the resolved sandbox mode/)
})

test('the third family names itself, and borrows neither of the other two stories', () => {
  const native = advisoryText(classifyNativeInitDeath(foreground(NATIVE_DEATH)), { mode: 'read-only' })
  assert.match(native, /`read-only`/)
  assert.notEqual(native, advisoryText(classifyProvisioningFailure(REPORTED)))
  assert.notEqual(native, advisoryText(classifyPtyStartupFailure(PTY_EXIT), { mode: 'read-only' }))
  // An href replaces the thread line, exactly as in the other two families.
  const linked = advisoryText(classifyNativeInitDeath(foreground(NATIVE_DEATH)), {
    mode: 'read-only',
    href: 'https://example.invalid/t/11',
  })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/t\/11/)
  assert.doesNotMatch(linked, new RegExp(NATIVE_INIT_DISCUSSIONS))
})

test('the three families share no message: each producer\'s input reaches exactly one classifier', () => {
  assert.equal(classifyProvisioningFailure(PTY_EXIT), undefined)
  assert.equal(classifyPtyStartupFailure(REPORTED), undefined)
  // The native-init family is not text-driven at all, so no message can reach it
  // and no value can reach the other two.
  assert.equal(classifyNativeInitDeath(REPORTED), undefined)
  assert.equal(classifyNativeInitDeath(PTY_EXIT), undefined)
  assert.equal(classifyProvisioningFailure('[exit code: -1073741502]'), undefined)
  assert.equal(classifyPtyStartupFailure('[exit code: -1073741502]'), undefined)
})

test('the path literals are recovered from the command, and only the ones a shell can carry', () => {
  // Windows shells spell an absolute path two ways, and the second is the one a
  // drive-letter regex alone misses.
  assert.deepEqual(windowsPathsIn('cmd /c "mkdir D:\\ws\\logs"'), ['D:\\ws\\logs'])
  assert.deepEqual(windowsPathsIn('copy \\\\server\\share\\f.txt .'), ['\\\\server\\share\\f.txt'])
  // A trailing separator is not part of the path for comparison; a path named
  // twice is one path.
  assert.deepEqual(windowsPathsIn('x D:\\ws\\ D:/ws D:\\ws'), ['D:\\ws', 'D:/ws'])
  // Case and separator are the caller's, not the parser's: normalising here would
  // hide a difference the containment test is supposed to decide.
  assert.deepEqual(windowsPathsIn('touch "C:\\Users\\a\\x.log"; ls /tmp/x'), ['C:\\Users\\a\\x.log'])
  // Relative paths are not paths this family can key on — the plugin cannot say
  // what they resolve to, and silence is the fail-closed direction.
  assert.deepEqual(windowsPathsIn('mkdir logs && cat ./logs/app.log'), [])
  // A path containing a space is recovered as its first segment: a PREFIX of the
  // real path, which keeps the containment answer for any descendant of the root.
  assert.deepEqual(windowsPathsIn('cp C:\\Program Files\\x.exe .'), ['C:\\Program'])
})

test('containment folds case and separators, and never by prefix of a sibling name', () => {
  assert.equal(isInsideWorkspace('D:\\ws', 'D:\\ws'), true, 'the root itself is inside it')
  assert.equal(isInsideWorkspace('D:\\ws', 'D:\\ws\\logs\\app.log'), true)
  assert.equal(isInsideWorkspace('D:\\ws', 'd:/WS/Logs/App.Log'), true, 'Windows compares these equal')
  assert.equal(isInsideWorkspace('D:\\ws\\', 'D:\\ws\\a'), true, 'a trailing separator on the root is not a difference')
  // The near-miss that a `startsWith` without the separator would call inside.
  assert.equal(isInsideWorkspace('D:\\ws', 'D:\\ws-other\\a'), false)
  assert.equal(isInsideWorkspace('D:\\ws', 'C:\\ws\\a'), false, 'another volume is another root')
  assert.equal(isInsideWorkspace('D:\\ws', 'D:\\wsx'), false)
  assert.equal(isInsideWorkspace('', 'D:\\ws\\a'), false, 'an unknown root contains nothing')
})

test('the denial stamp is read from the executors\' own projection, and only there', () => {
  assert.equal(hasWorkspaceDenialStamp(denied()), true)
  // Everything the producers do NOT stamp is refused, one field at a time.
  assert.equal(hasWorkspaceDenialStamp(denied({ denied: false })), false)
  assert.equal(hasWorkspaceDenialStamp(denied({ mode: 'read-only' })), false, 'read-only denies every write by construction')
  assert.equal(hasWorkspaceDenialStamp(denied({ mode: 'danger-full-access' })), false)
  assert.equal(hasWorkspaceDenialStamp(denied({ runnerFailed: true })), false, 'a runner failure is not a denial the sandbox chose')
  assert.equal(hasWorkspaceDenialStamp(foreground(1)), false, 'a shell projection without the stamp')
  assert.equal(hasWorkspaceDenialStamp({ kind: 'background', exitCode: 1 }), false)
  // A command's own output cannot fabricate it: the stamp is a field, not a line.
  assert.equal(hasWorkspaceDenialStamp('sandbox: { mode: "workspace-write", denied: true }'), false)
  assert.equal(hasWorkspaceDenialStamp({ kind: 'foreground', sandbox: 'denied' }), false)
  assert.equal(hasWorkspaceDenialStamp(null), false)
  assert.equal(hasWorkspaceDenialStamp([denied()]), false)
})

test('a denial inside the workspace is recognized, with the paths and the root kept', () => {
  const failure = classifyWorkspaceDenial(
    denied(),
    { command: `cmd /c "type ${INSIDE}"` },
    { platform: 'win32', workspaceRoot: WORKSPACE_ROOT },
  )
  assert.ok(failure, 'the reported combination must classify')
  assert.equal(failure.family, 'workspace-denial')
  assert.equal(failure.mode, 'workspace-write')
  assert.equal(failure.exitCode, 1)
  assert.deepEqual(failure.paths, [INSIDE])
  assert.equal(failure.workspaceRoot, WORKSPACE_ROOT)
  // The line the advisory shows is the producer's stamp, not a sentence this
  // plugin made up: the reader can match it against the result they saw.
  assert.equal(failureLine(failure), '[exit code: 1] sandbox: { mode: "workspace-write", denied: true }')
})

test('every narrowing that keeps a denial from being this family is a refusal, not a guess', () => {
  const facts = { platform: 'win32', workspaceRoot: WORKSPACE_ROOT }
  const at = (args, value = denied()) => classifyWorkspaceDenial(value, args, facts)
  // The platform gate cannot be dropped here: the mechanism is ACE inheritance,
  // which no other backend has.
  assert.equal(classifyWorkspaceDenial(denied(), { command: `type ${INSIDE}` }, { ...facts, platform: 'darwin' }), undefined)
  assert.equal(classifyWorkspaceDenial(denied(), { command: `type ${INSIDE}` }, { ...facts, platform: 'linux' }), undefined)
  // A path outside the workspace is the DESIGNED escalation path.
  assert.equal(at({ command: `"${OUTSIDE}" --version` }), undefined)
  // A command naming any outside path as well is refused rather than guessed at:
  // the plugin cannot say which of the two the sandbox refused.
  assert.equal(at({ command: `"${OUTSIDE}" --version && type ${INSIDE}` }), undefined)
  // Only relative paths: no literal to test, so nothing is claimed.
  assert.equal(at({ command: 'mkdir logs && cat logs/app.log' }), undefined)
  assert.equal(at({ command: 'echo hello' }), undefined)
  assert.equal(at({}), undefined, 'arguments without a command string')
  assert.equal(at({ command: 42 }), undefined)
  // The other narrowings, which live in the stamp.
  assert.equal(at({ command: `type ${INSIDE}` }, denied({ denied: false })), undefined)
  assert.equal(at({ command: `type ${INSIDE}` }, denied({ mode: 'read-only' })), undefined)
  assert.equal(at({ command: `type ${INSIDE}` }, denied({ runnerFailed: true })), undefined)
  assert.equal(at({ command: `type ${INSIDE}` }, foreground(1)), undefined)
  // An exit the tool did not report stays "not reported" rather than becoming 0.
  const noExit = denied()
  delete noExit.exitCode
  const failure = at({ command: `type ${INSIDE}` }, noExit)
  assert.ok(failure)
  assert.equal(failure.exitCode, null)
  assert.equal(failureLine(failure), 'sandbox: { mode: "workspace-write", denied: true }')
})

test('the workspace-denial advisory shows its work, and prints no repair command', () => {
  const failure = classifyWorkspaceDenial(
    denied(),
    { command: `cmd /c "type ${INSIDE}"` },
    { platform: 'win32', workspaceRoot: WORKSPACE_ROOT },
  )
  assert.ok(failure)
  const flat = advisoryText(failure, { tool: 'bash' }).replace(/\s+/g, ' ')
  // What is being claimed, and the two strings it is a claim about — printed, so
  // the reader audits the plugin's own reasoning.
  assert.match(flat, /Denied inside your own workspace/)
  assert.match(flat, new RegExp(INSIDE.replace(/\\/g, '\\\\')))
  assert.match(flat, new RegExp(WORKSPACE_ROOT.replace(/\\/g, '\\\\')))
  assert.match(flat, /The `bash` command ran under sandbox mode `workspace-write`/)
  // The mechanism, and the reason retrying is provably useless.
  assert.match(flat, /ACE inheritance/)
  assert.match(flat, /WRITE_DAC/)
  assert.match(flat, /hasExactGrant\(workspaceRoot\)/)
  assert.match(flat, /NEVER revisited|never revisited/)
  assert.match(flat, /Do NOT retry this call unchanged/)
  // The measurement that says the shape is wider than "subdirectories".
  assert.match(flat, /170 of 729/)
  assert.match(flat, /INCLUDING root-level files/)
  // The discriminator's second half: a check that only greps for the SID is wrong.
  assert.match(flat, /THE TRAP/)
  assert.match(flat, /NORMAL token/)
  assert.match(flat, /RESTRICTED/)
  assert.match(flat, /Administrators\/SYSTEM/)
  // The label variant of the same shape, and the tool that separates them.
  assert.match(flat, /mandatory-integrity LABEL/)
  assert.match(flat, /2026-09-29/)
  assert.match(flat, /diagnose-windows-sandbox-acl/)
  assert.match(flat, /LOW_LABEL/)
  assert.match(flat, /S-1-16-4096/)
  assert.match(flat, /hasExactDeny\(\)/)
  // The Windows ceiling that closes the obvious repair.
  assert.match(flat, /ERROR_NONE_MAPPED \(1332\)/)
  // The sanctioned retry is named, so the model is not nudged into it blind.
  assert.match(flat, /offers one retry of this exact command under a wider mode/)
  // And what it does not do: no repair line at all, for the reason the standing
  // grant section gives, and no privilege-elevation vocabulary either.
  assert.doesNotMatch(flat, /icacls "[^"]+" \/(grant|setowner)/, 'no repair command is printed')
  assert.doesNotMatch(flat, /setintegritylevel/i)
  assert.doesNotMatch(flat, /No repair command is printed here on purpose\s*$/)
  assert.match(flat, /No repair command is printed here on purpose/)
  assert.match(flat, /no Windows host to verify one on/)
  // The stopgap line, and the boundary that says when it stays silent.
  assert.match(flat, new RegExp(WORKSPACE_DENIAL_DISCUSSIONS))
  assert.match(flat, /only when the mode is `workspace-write`, the host is Windows/)
})

test('the fourth family names itself, and borrows none of the other three stories', () => {
  const denial = classifyWorkspaceDenial(
    denied(),
    { command: `type ${INSIDE}` },
    { platform: 'win32', workspaceRoot: WORKSPACE_ROOT },
  )
  assert.ok(denial)
  const text = advisoryText(denial, { tool: 'bash' })
  assert.notEqual(text, advisoryText(classifyProvisioningFailure(REPORTED)))
  assert.notEqual(text, advisoryText(classifyPtyStartupFailure(PTY_EXIT), { mode: 'read-only' }))
  assert.notEqual(text, advisoryText(classifyNativeInitDeath(foreground(NATIVE_DEATH)), { mode: 'read-only' }))
  // The ACL family's remedy belongs to the other end of the same backend and must
  // not leak into this one: this family's own text says no command is printed.
  assert.doesNotMatch(text, /\(Get-Acl/)
  assert.doesNotMatch(text, /If you own it/)
  // An href replaces the thread line, exactly as in the other families.
  const linked = advisoryText(denial, { tool: 'bash', href: 'https://example.invalid/t/423' })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/t\/423/)
  assert.doesNotMatch(linked, /tracked upstream \(discussion/)
  // Only the thread LINE moves. This family is one thread, so unlike the others
  // its id is also the reference beside the measurements it quotes — and those
  // citations are what a reader follows to check the numbers, so they stay.
  assert.match(linked, new RegExp(`${WORKSPACE_DENIAL_DISCUSSIONS} measured 170 of 729`))
})

test('the four families share no message: each producer\'s input reaches exactly one classifier', () => {
  const facts = { platform: 'win32', workspaceRoot: WORKSPACE_ROOT }
  const stamped = denied()
  assert.equal(classifyProvisioningFailure(PTY_EXIT), undefined)
  assert.equal(classifyPtyStartupFailure(REPORTED), undefined)
  // The two value-read families are not text-driven at all, and no value reaches
  // the text-read ones.
  assert.equal(classifyNativeInitDeath(REPORTED), undefined)
  assert.equal(classifyNativeInitDeath(stamped, { command: `type ${INSIDE}` }), undefined)
  assert.equal(classifyProvisioningFailure('[exit code: -1073741502]'), undefined)
  assert.equal(classifyPtyStartupFailure('[exit code: -1073741502]'), undefined)
  // The two value families are distinguished by the loader status alone: a denial
  // value carries no such code, and a loader death carries no stamp.
  assert.equal(classifyWorkspaceDenial(foreground(NATIVE_DEATH), { command: `type ${INSIDE}` }, facts), undefined)
  assert.equal(classifyNativeInitDeath(stamped), undefined)
  assert.equal(classifyWorkspaceDenial(stamped, { command: `type ${INSIDE}` }, facts)?.family, 'workspace-denial')
})
