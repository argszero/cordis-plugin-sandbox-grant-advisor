/**
 * What the model — and through it the user — is told about a recognized
 * environment failure, and what is deliberately withheld.
 *
 * The text is assembled here as pure functions so every sentence can be pinned
 * by a test, one family at a time. The six families are shaped by the same
 * question — is this the sandbox's doing, and what can the reader do about it —
 * and they answer it differently:
 *
 * - **The ACL failure** (`acl-provisioning`) *is* fixable by the caller, so its
 *   advice names the right the caller is missing and gives the command.
 *   The reported failures are `ERROR_ACCESS_DENIED` from a *merged* DACL + SACL
 *   write; the missing right is `WRITE_OWNER` on the directory — an object right
 *   the caller can grant itself with `icacls`, unelevated. It is **not**
 *   `SeSecurityPrivilege`, the token privilege the reports naturally reach for;
 *   `whoami /priv` cannot show the difference, and elevation is the wrong lever.
 *   The remedy is the **narrowest** form of that grant — `(WO)` alone, which is
 *   literally the right the backend's prerequisite names — with Full control
 *   offered as the broad alternative; and the advisory carries the **version
 *   boundary** the label introduced (`0.1.7-alpha.1`), because that is what
 *   separates "this is the label failure" from "this is something else", and
 *   because rolling back is the reach it invites while making the very problem
 *   it closed come back.
 *
 *   **The remedy is forked on ownership, because one command cannot serve both
 *   environments.** The reports split into two rights situations behind an
 *   identical error: a workspace **the caller owns** (`#7622`, `#7646`, `#7720`,
 *   `#7750`, `#7804`), where the owner's implicit `WRITE_DAC` satisfies the DACL
 *   half and `(WO)` is the whole of what is missing — so the `icacls /grant`
 *   that supplies it *can itself run*, unelevated; and a directory **the caller
 *   does not own** (`#7771`: owner `BUILTIN\Administrators`, held deny-only for
 *   their token), where `WRITE_DAC` is missing too, so `icacls /grant` is denied
 *   for the very command that would fix it, and `(WO)` alone would not be enough
 *   even if it went through. The classifier cannot tell these apart — the text is
 *   identical — so the advisory does what it can do instead of guessing: it hands
 *   over the **ownership check** (`(Get-Acl "<dir>").Owner`) as the branch
 *   selector, then gives each branch the command that actually works there, and
 *   says why the other branch's command is not a fallback. A single unconditional
 *   one-liner would send the second environment to a command that is refused
 *   before it runs — the same defect this module exists to answer, a remedy that
 *   does not work delivered confidently.
 *
 *   **Two later reports add shape and a boundary, not a new cause.** `#8272`
 *   arrived at the missing right with an independent probe (it set a Low
 *   integrity level on a directory it owned, unelevated, and was refused — the
 *   label half isolated from the merged call), and then went looking for the
 *   backend's own `diagnose-windows-sandbox-acl` skill on a `0.1.7-rc.2` install,
 *   where it does not exist: the skill is new in **`0.2.0`**, and that release's
 *   README is where the promise was read. So the boundary section states where
 *   the skill actually arrives, and calls the "the package dropped it" reading
 *   what it is — version skew, not a `files` glob. `#8275` adds the question the
 *   diagnosis invites: whether the label half can simply be declined, since the
 *   label is what makes the apply a SACL write. It can't, and the reason is a
 *   mechanism rather than a policy — the label rides the *same* call as the grant
 *   and the confined token is itself lowered to Low, so a DACL-only mode that
 *   keeps the token lowering yields a workspace the confined child cannot write
 *   to. That is stated instead of a bare "no", because a reader told only "no"
 *   reaches for the workaround without knowing what else it would have to change.
 *
 *   **It also states what the grant leaves behind** (`#8312`, `#8314`), because
 *   this is the module that hands over the command applying that grant, and these
 *   are facts a reader needs at that moment rather than from a broken build in
 *   another project later. The three entries are standing by design — the
 *   backend's dispose path leaves them, and its own failure-cleanup comment calls
 *   them "the intended end state (the reuse cache)" — the Low label is
 *   inheritable and lives in the SACL (so resetting the DACL does not remove it),
 *   and an NTFS hard link is a second name for one file object, so a pnpm
 *   workspace's `node_modules` → content-addressed-store links carry that label
 *   out of the tree and leave it on objects other projects build from. The
 *   section offers no removal command: the maintainers' own diagnosis skill
 *   reports the label and leaves it, removing one needs `WRITE_OWNER`, and this
 *   project has no Windows host on which to verify a line.
 * - **The persistent-shell failure** (`pty-startup`) is *not* fixable by the
 *   caller — least of all by the model, which has no shell to run anything in.
 *   So its advice says so and stops: the remedy is a user-side preset choice,
 *   and the model's instruction is to stop retrying and use its file tools.
 *   Handing the model a command here would be advice to run something that
 *   cannot run, and naming a one-shot shell tool would be advice to call a tool
 *   the failing composition does not mount. **Inside a confining mode the host
 *   binary decides**, which `#8322` separated with one runner and one ConPTY in
 *   every arm: a console-subsystem `node.exe` host starts the confined shell,
 *   while the packaged desktop's GUI-subsystem Electron host kills it silently.
 *   That is the same console rule the native-init family states — under the
 *   restricted token a console can be inherited but not created — so the advisory
 *   names the host alongside the mode, says the outcome is deterministic per
 *   (session mode × host) rather than intermittent, and offers the console-owning
 *   host as a user-side option `#8313` measured working.
 * - **The native-init death** (`native-init`) is the one whose remedy is **split**:
 *   the *class* is not the model's to fix, but one of its producers is. A confined
 *   child that died with `STATUS_DLL_INIT_FAILED` never ran
 *   anything, so retrying the same call is pure waste — but if the program that
 *   could not start was an MSYS2/Git-Bash one, the same work expressed with
 *   PowerShell or `cmd` runs fine under the identical mode, and the model *can*
 *   make that change because the model is the one that wrote the command. So the
 *   advice carries a stop instruction, the one in-session conversion, and the
 *   user-side remedy for the others. What it deliberately does **not** do
 *   is guess which producer this is: the code alone cannot say, and the checks it
 *   hands over are facts the reader holds (what program they ran; whether this is
 *   the packaged desktop app, which the plugin reports rather than assumes;
 *   whether the same command runs under `read-only`).
 *   Since `0.16.0` there are **three** producers, and the third arrived with the
 *   discriminator the first two lacked: `#9186` isolated it to a single input by
 *   driving the sandbox API with the DACLs untouched, and the input is the
 *   restricted token's own restricting list — a capability SID in it kills every
 *   program, `whoami.exe` and `cmd.exe` included, while the `read-only` list
 *   (no capability SID) starts them normally. That is a one-setting comparison
 *   rather than a debugging session, and it is the answer to the one thing the
 *   status code cannot tell: the same `0xC0000142` is also produced by a token
 *   built **without** the logon-SID/EVERYONE keep-alive pair, so the code cannot
 *   name its own direction. The control arm also retires the `.NET self-contained`
 *   cause the earlier reports converged on, because pure-native programs die
 *   identically.
 *   That Electron host was shipped as **two measurements**; since
 *   0.8.0 it is **one mechanism, named**: the runner must own a *console* for the
 *   confined child to inherit, and when it owns none the child's own console
 *   request is denied under the restricted token (`#8208` traced it to
 *   `conhost.exe` created by the restricted child, exiting `STATUS_ACCESS_DENIED`).
 *   The two measured console-less shapes are a GUI-subsystem host image (the
 *   packaged desktop) and a `DETACHED_PROCESS` runner under a real `node.exe`
 *   host — the second reproducible on any machine, which is what makes it the
 *   check worth handing over. The shape 0.7.x led with, "the runner never started
 *   at all", is **withdrawn**: the desktop's own host child is started with
 *   `ELECTRON_RUN_AS_NODE=1` (`apps/desktop/src/host-process.ts` ->
 *   `desktopNodeEnvironment()`), so nothing on the runner path fails to start for
 *   want of that variable. A withdrawn cause earns its sentence because this
 *   advisory shipped it twice; a confidently wrong cause is worse than two named
 *   ones with one shared remedy.
 * - **The workspace-internal denial** (`workspace-denial`, #423) is the fourth,
 *   and it is the first whose remedy is **withheld on purpose**. The failure is
 *   not that a command failed but that the workspace's own grant does not cover
 *   part of the workspace: the grant is written once on the root and depends on
 *   ACE inheritance, so an already-existing object whose DACL the caller could
 *   not write kept its older DACL, and the backend's root-only `hasExactGrant`
 *   check means it is never revisited. Retrying is therefore provably useless,
 *   which is what the text leads with. What it does **not** do is print a repair
 *   command: the obvious one (`icacls` recursing the capability SID) is refused
 *   by Windows itself with `ERROR_NONE_MAPPED` (1332), because that SID has no
 *   name to map, and the line that would work needs the right that is missing —
 *   so the advisory states the mechanism, names the ceiling, and says out loud
 *   that it prints no command because this project has no Windows host to verify
 *   one on. That is the same standard the standing-grant section is held to, and
 *   it is the reason this family can be useful without being prescriptive.
 *   Its discriminator is the **two-sided** one, which is not obvious and which a
 *   reader checking only the ACE would get wrong: reading and listing use the
 *   normal token while writing and deleting use the restricted one, so an object
 *   whose DACL names only `Administrators`/`SYSTEM` plus the capability SID is
 *   refused on the read side too and looks granted to a grep for the SID
 *   (#423 measured it). And the second branch is now **first-class rather than a
 *   sentence**: the same root-only short-circuit on the *label* half, where the
 *   DACL reaches every object and the mandatory-integrity label reaches none of
 *   the subdirectories, so nothing below the root is writable at all (`#8383`,
 *   measured against `0.2.0-rc.2` with the decisive control of a directory
 *   created *after* the grant). The two branches are indistinguishable from
 *   inside a session and permanent for the same reason, so the text forks them
 *   on **breadth** — the one fact the reader already owns — before it hands over
 *   any check, and separates them from outside by the repository's own
 *   `diagnose-windows-sandbox-acl` and its `LOW_LABEL` report.
 * - **The private temp root inside the workspace** (`temp-root-inside-workspace`,
 *   #9175) is the fifth, and it is the one whose failure is not a failure of
 *   anything the session asked for: the sandbox refuses to **start** a command —
 *   `echo test` included, with no subprocess output at all — because the temp ROOT
 *   it would create its private, revocable temp capability under lies inside the
 *   workspace it grants the standing capability to. Its remedy is asymmetric with
 *   every earlier family in one way that decides the whole text: **nothing inside
 *   the session can carry it out**. The ACL remedy is a command the user runs while
 *   the session continues; here there is no session to run a command in. So the fix
 *   is an environment fact on the process that *launches* the harness (`%TMP%` /
 *   `%TEMP%`, which `GetTempPathW` reads in that order) or a different workspace,
 *   and the text says so rather than offering a line the model cannot execute.
 *   It is also the family that carries **two producers of one sentence** — the
 *   session-scoped provider while it assembles the runner argv (no child ever
 *   existed) and the runner itself before it spawns (stderr behind
 *   `windows-acl-run: `, exit 127, reclassified by the seam as a runner failure)
 *   — which the advisory names, because a change to the rule has to satisfy both.
 *   And it is the only family whose text is delivered **twice by design**: once as
 *   a pre-flight report of the standing condition, before anything has failed, and
 *   once beside the refusal itself if it does happen. The pre-flight half is the
 *   only place in this module that *predicts* rather than reads, so it is written
 *   to be falsifiable — it prints the three facts it computed (host, mode, both
 *   paths) and says that a command which runs anyway is evidence the prediction did
 *   not apply. Nothing is granted, escalated or moved by this plugin in either half.
 * - **The CIM/WMI boundary** (`cim-wmi-denial`, #9272) is the sixth, and it is the
 *   only one whose mechanism **the harness already documents**: the Windows ACL
 *   backend's own README says Authenticated Users is absent from both of its token
 *   lists, so the WMI namespace security check fails with `0x80041003` and CIM is
 *   unavailable in every confined mode. Carrying it anyway is the posture the ACL
 *   family already takes with {@link PREREQUISITE} — a documented limitation that
 *   the *error* does not name is exactly what this module exists to deliver at the
 *   moment it happens. It is a **value-read** family like `native-init`: a cmdlet
 *   error inside a command that ran is a nonzero exit, which the shipped shell
 *   tools report without marking the result an error, so the code lives in the
 *   settled value's own `stderr`. What the advisory adds beyond upstream's
 *   sentence is what the reporter asked for first and the README does not supply:
 *   the **native substitute for each command that stops working**, and the two
 *   shapes in which this boundary answers with a **wrong value and no error at
 *   all** — `Get-PSDrive`'s usage columns falling back to `0`, and any CIM call
 *   under `-ErrorAction SilentlyContinue` returning an empty result, which a
 *   caller reads as "nothing is there" when the query never ran. That second shape
 *   is why the family exists for agents and not only for humans: an empty CIM
 *   result has no failure signal at all, and the next action it invites is
 *   destructive.
 *
 *   Its remedy is deliberately **not** a permission grant, and the text says why
 *   rather than only what: no ACE names CIM, no elevation reaches it, and the one
 *   repair a reader naturally proposes — admitting read access to `root/cimv2` —
 *   is a change to the restricted token rather than to a file, priced against the
 *   escape that dropping Authenticated Users from those lists closes. Because the
 *   plugin cannot say whether that trade is worth making, and because nobody has
 *   measured which of the token's checks refuses the namespace, the advisory
 *   quotes upstream's own sentence for the mechanism and declines to price a
 *   narrower fix from its own evidence.
 *
 * Both give a **discriminator, not just a remedy**: applying a fix without
 * confirming the cause teaches nothing when the fix does not work. For the ACL
 * family that is `icacls <dir>`, looking for an ACE that names the caller's own
 * SID and grants `(F)` — which separates "Modify-only directory" from "the
 * documented prerequisite is wrong", the open question upstream. For the PTY
 * family it is the **effective sandbox mode**, which is why that advisory is
 * only ever built with the mode the call actually ran under. For the native-init
 * family it is two checks the reader performs — which program could not start,
 * and whether this host is the packaged desktop app — because the code alone
 * cannot separate the producers and a guess would send half its readers to the
 * wrong remedy. Inside that Electron answer there is a third thing the code
 * cannot separate, and the advisory deliberately does not try: it names both
 * measurements and says the remedy does not depend on choosing between them.
 * For the workspace-denial family the discriminator is the **path**, which is
 * why the advisory prints the path it keyed on beside the root it tested it
 * against: the reader can audit the plugin's own reasoning instead of taking a
 * claim about two strings on faith. That family's check is also the one place
 * where a single fact is not enough — reachability has two sides, and the text
 * says which one a check on the ACE alone would miss — and it is the one family
 * with a **second cut before the check**: which half is missing is settled by how
 * MUCH of the tree is affected, because a reader who repairs the DACL of a
 * label-starved workspace has spent a privilege for nothing. The temp-root family
 * is the only one whose discriminator the *plugin* supplies rather than the reader
 * finding: it prints both operands it computed, and — since no command can be run
 * in the session to check anything — it states that a command which runs anyway
 * falsifies the report, which is the one verification available without a shell.
 * The CIM/WMI family is the one whose discriminator is **shared with upstream**:
 * the reason it can be named at all is a sentence the backend's own README
 * carries, so the advisory quotes it as the authority and states what it adds on
 * top (the substitutes and the silent-value rules) instead of presenting a
 * documented boundary as a discovery.
 *
 * @module
 */

import type { FailureFamily, ProvisioningFailure, PtyStartupFailure, NativeInitFailure, TempRootFailure, WorkspaceDenialFailure, CimDenialFailure, RecognizedFailure } from './signature.js'
import { failureLine, STATUS_DLL_INIT_FAILED } from './signature.js'
import type { SandboxModeName } from './mode.js'

/**
 * The upstream threads the ACL advisory is a stopgap for.
 *
 * The first twelve report the provisioning failure itself (the merged DACL +
 * label write being refused). `#8312` and `#8314` report the other end of the
 * same backend — what its grant leaves behind once it *succeeds* — which the
 * advisory states because it is the fact a reader needs at the moment it hands
 * them the command that applies that grant. The last three arrived later and
 * are all inside the same advisory: `#8426` is the independent, unelevated
 * measurement of the missing `WRITE_OWNER` the diagnosis above had only ever
 * argued for, and `#8412` is a second instance of what the grant leaves behind
 * (the standing Low label reaching programs the user launches themselves).
 * `#8409` is the same backend once more and belongs to both lists: one of its
 * three defects is the provisioning failure this family explains, and another
 * is the fourth family's third branch.
 */
export const ACL_DISCUSSIONS = '#7538 / #7622 / #7646 / #7720 / #7750 / #7735 / #7771 / #7804 / #7816 / #8232 / #8272 / #8275 / #8312 / #8314 / #8426 / #8412 / #8409'

/**
 * The upstream threads the persistent-shell advisory is a stopgap for.
 *
 * `#7638` is the failure and its three-arm control (the mode is the
 * discriminator); `#8322` is the one that separated the arms inside a confining
 * mode and found the sandbox runner's host binary — same runner, same ConPTY,
 * console-subsystem `node.exe` host works where a GUI-subsystem one dies
 * silently — which is why the advisory names the host as well as the mode; and
 * `#9170` supplies that comparison from the user's own side: the same confined
 * command works under the console-owning host the Web UI provides and fails
 * under the packaged desktop app, with the mode and the command held fixed.
 */
export const PTY_DISCUSSIONS = '#7638 / #8322 / #9170'

/**
 * The upstream threads the native-init-death advisory is a stopgap for.
 *
 * `#8313` is the fifth report of the same code and the one that states the host
 * difference from the outside: the desktop build fails where the same version
 * launched from a terminal does not, which is the same variable the PTY family
 * now names. `#8336` and `#8334` measured the creation-flag list and answered the
 * `windowsHide` suspicion for that producer.
 *
 * The three later threads are the second producer's opposite number, and they
 * arrived as a cluster on three different Windows builds: `#8990` and `#8991`
 * (the same code, with no dependence on the PowerShell version or the install
 * layout) whose producers nobody had identified, then `#9186`, which isolated it
 * to a single input — the restricted token's own restricting list — and is the
 * reason the advisory carries a third producer at all. Its control arm also
 * retires the `.NET self-contained` cause the earlier threads attracted: a
 * pure-native `whoami.exe` and `cmd.exe` die exactly as `pwsh` does.
 */
export const NATIVE_INIT_DISCUSSIONS = '#7876 / #7877 / #8193 / #8208 / #8313 / #8336 / #8334 / #8990 / #8991 / #9186'

/**
 * The upstream threads the workspace-denial advisory is a stopgap for.
 *
 * `#423` is the failure and its first measurements: 170 of 729 objects missing
 * the grant, root-level files among them, and the two-sided reachability rule.
 * Its second comment named the mandatory-label variant of the same shape, which
 * `#8383` then measured on its own — the exact complement, with the DACL
 * present and inheriting correctly at every level while the label reaches none
 * of the subdirectories, so the variant stopped being a footnote and became the
 * second branch the discriminator forks into; `#8421` met it again, which is
 * why the branch reads as a shape rather than as one install. `#8409` is the
 * third branch's source and a report of the DACL half as well: the workspace
 * root's own standing grant can be gone, and the layer that would re-apply it
 * consults a per-lifetime map instead of the DACL, so nothing notices.
 */
export const WORKSPACE_DENIAL_DISCUSSIONS = '#423 / #8383 / #8421 / #8409'

/**
 * The upstream thread the temp-root advisory is a stopgap for.
 *
 * One report, because the shape is one sentence out of one invariant: `#9175`
 * has the failure, the platform, and — this is what makes it usable without a
 * Windows host — the two paths the assertion printed, which is exactly the pair
 * the pre-flight half has to reproduce to be worth anything.
 */
export const TEMP_ROOT_DISCUSSIONS = '#9175'

/**
 * The upstream threads the CIM/WMI advisory is a stopgap for.
 *
 * `#9272` is the report: all CIM/WMI access refused under a confining mode with
 * the native substitutes and the two silent-value shapes measured on one machine,
 * which is why the advisory can hand over a table instead of a suggestion. The
 * other four are the report's own neighbours and are named because the thread
 * presents itself as the fourth face of one boundary: `#1157` (no outbound
 * network under the same restricted token), `#4163` and `#997` (Schannel TLS
 * failing with `SEC_E_NO_CREDENTIALS`), and `#1847` (external processes dying
 * with `0xC0000142`) are already covered by this plugin's other families or are
 * outside them, but a reader who has just hit a fourth manifestation is better
 * served by seeing that the boundary is one and not four puzzles. Naming them is
 * also the honest scope statement: this advisory explains the CIM face only.
 */
export const CIM_WMI_DISCUSSIONS = '#1157 / #4163 / #997 / #1847 / #9272'

/**
 * The thread list each family's withholding note cites.
 *
 * A withheld recognition is a decision the host log has to account for, and the
 * note a maintainer reads is only useful if it points at *that* family's
 * report — a withheld native-init death and a withheld workspace denial are
 * different reports, and a note that cites the wrong one is its own small
 * misdiagnosis. Kept beside the constants it assembles rather than at the
 * withholding site, so a family added without a thread is a type error instead
 * of a note that quietly cites another family's.
 */
export const DISCUSSIONS_OF: Record<FailureFamily, string> = {
  'acl-provisioning': ACL_DISCUSSIONS,
  'pty-startup': PTY_DISCUSSIONS,
  'native-init': NATIVE_INIT_DISCUSSIONS,
  'workspace-denial': WORKSPACE_DENIAL_DISCUSSIONS,
  'temp-root-inside-workspace': TEMP_ROOT_DISCUSSIONS,
  'cim-wmi-denial': CIM_WMI_DISCUSSIONS,
}

/** The documented prerequisite, quoted from the backend's README. */
export const PREREQUISITE = 'granted directories must be caller-owned and grant `WRITE_OWNER`'

/**
 * Where a user's own preset changes actually live.
 *
 * This is deliberately **not** the legacy `$DSH_HOME/.agent-presets/<id>/`
 * directory: that shape predates declarative presets and **nothing reads it any
 * more** (the registry "neither scans directories nor accepts preset paths").
 * A preset is a `@deepseek-ai/dsh-agent-preset` row, and changing one means
 * overriding or inserting that row in a patch layer, which is what this path
 * names. Advising a folder the harness stopped reading would be the same defect
 * this plugin exists to answer — a remedy that does not work, delivered
 * confidently.
 */
export const PROFILE_PATCH = '$DSH_HOME/profiles/<profile>/cordis.patch.yml'

/** The machine-wide patch layer, for a change that should hold in every profile. */
export const GLOBAL_PATCH = '$DSH_HOME/cordis.patch.yml'

/** The row id the shipped `minimal` preset is declared under. */
export const MINIMAL_PRESET_ROW = 'preset-minimal'

/** The one-shot shell tool the `standard` preset mounts on Windows. */
export const ONE_SHOT_SHELL = '@deepseek-ai/dsh-tool-pwsh'

/**
 * The two remedies that look like the fix and are not.
 *
 * Both were applied by the reporter of `#7720` before finding the one that
 * works, and both are the *natural* reach: making yourself the owner and
 * resetting the directory's ACL are how one normally repairs a Windows
 * permission problem. They fail here for two different reasons, and naming the
 * reason is what makes this section worth its lines — a reader who already
 * tried them learns why, and a reader who has not is spared the attempt. See
 * {@link nonFixes} for when this is emitted.
 */
export const NOT_FIXES = [
  'takeown /F "<dir>" /R /D Y',
  'icacls "<dir>" /reset /T /C',
] as const

/** Placeholder the user replaces with the directory the error named. */
const PLACEHOLDER = '<the directory from the error line above>'

/** What the caller knows about the failing call, beyond the failure text. */
export interface AdvisoryContext {
  /** URL quoted in place of the discussions list; optional. */
  readonly href?: string
  /** The tool whose call failed, quoted back so the advice is about that call. */
  readonly tool?: string
  /**
   * The sandbox mode the failing call ran under. Required by the
   * `pty-startup` family — the whole diagnosis is the mode — and by the
   * `native-init` family, whose gate is the same question; unused by the ACL
   * family. The `cim-wmi-denial` family requires it too, and for a third
   * reason: the condition holds under BOTH confining modes, so the text names
   * the mode to keep the two halves of that claim auditable rather than
   * asserting a mode the caller never resolved.
   */
  readonly mode?: SandboxModeName
  /**
   * Whether this process is an Electron binary (`process.versions.electron`).
   * Used by the `native-init` family to report — not to assume — which of its
   * producers this host can have; absent means "ask the live process", so a
   * caller cannot accidentally state a fact it did not measure.
   */
  readonly electronHost?: boolean
}

/**
 * Whether this process is running on an Electron binary.
 *
 * In the packaged desktop the harness host *is* Electron, started with
 * `ELECTRON_RUN_AS_NODE=1` so it behaves as Node — which is why the variable is
 * defined here and why its presence is the discriminator the `#7876` producer
 * turns on: `sandbox-local` launches the sandbox runner as `process.execPath`,
 * and in that build the exec path is the Electron executable.
 * @returns true when `process.versions.electron` is set.
 */
function electronHost(): boolean {
  return process.versions.electron !== undefined
}

/**
 * The diagnosis paragraph for one class of failure.
 * @param failure - the recognized failure.
 * @returns one paragraph, honest about what is and is not known.
 */
function diagnosis(failure: ProvisioningFailure): string {
  switch (failure.klass) {
    case 'apply-denied':
      return [
        'Why it is refused while the directory looks writable: that call is a MERGED write — the DACL and the',
        'mandatory-integrity label go out as one `SetNamedSecurityInfoW`. The label lives in the SACL, and the',
        "owner's implicit rights cover only READ_CONTROL and WRITE_DAC, so the label half additionally needs",
        'WRITE_OWNER on the directory. A workspace created with `mkdir` normally inherits',
        '"Authenticated Users: Modify" (`0x1301bf`) from the drive root — and that mask has neither right; on a data',
        'volume there may be no ACE naming you at all, so that inherited entry is the whole of your access. The two',
        'halves go out as one call, so a refused label discards the write grant with it, and the sandbox then',
        'refuses to start any command in the workspace instead of running it unconfined.',
        'This is a directory ACL fact, not a token privilege: `whoami /priv` will not show it, and',
        'SeSecurityPrivilege is the wrong lever here.',
      ].join('\n')
    case 'read-denied':
      return [
        'Why it is refused: the harness could not even read the directory\'s security descriptor, so the grant',
        'never got as far as writing one. That read wants READ_CONTROL, which the directory is not granting this',
        'account either.',
      ].join('\n')
    case 'apply-other':
      return [
        'Why it is refused: this is the same merged write, but the Win32 code is not ERROR_ACCESS_DENIED (5), so',
        'the missing-rights story above does not apply verbatim — a missing path, a non-directory target, or a',
        'filesystem that does not carry ACLs are all possibilities. The commands below are safe to try; if the',
        'code persists, it is a different failure and worth reporting with the code.',
      ].join('\n')
  }
}

/**
 * The "this is not the fix" lines for one class of failure.
 *
 * Emitted only for `apply-denied`, the class whose whole diagnosis is the
 * missing `WRITE_OWNER` right — because only there is the claim true:
 *
 * - `read-denied` wants `READ_CONTROL`, and taking ownership *does* carry it,
 *   so calling `takeown` a non-fix there would be false.
 * - `apply-other` already says the missing-rights story does not apply
 *   verbatim, so a section that presupposes it would contradict its own
 *   diagnosis.
 *
 * A negative claim still has to be earned: the failure to avoid is advice that
 * is confidently wrong in the other direction. That is why the `takeown` line
 * claims only what is true in **both** ownership branches: it supplies the DACL
 * half and never `WRITE_OWNER`, so it is not the fix by itself — while still
 * being a legitimate first step (with elevation) where the caller is not the
 * owner. Calling it useless outright would have been the mirror-image error.
 * @param failure - the recognized provisioning failure.
 * @param path - the directory the error named, or the placeholder.
 * @returns the section's lines, or an empty array for a class it does not fit.
 */
function nonFixes(failure: ProvisioningFailure, path: string): string[] {
  if (failure.klass !== 'apply-denied') return []
  return [
    'What will NOT fix it on its own — both look like the right move, and both were tried and reported:',
    `  takeown /F "${path}" /R /D Y`,
    "    makes you the owner, and ownership's implicit rights are READ_CONTROL and WRITE_DAC only — so it",
    '    supplies the DACL half and still not WRITE_OWNER, the right this call needs. In the second branch above',
    '    it is a legitimate first step with elevation; it is never the fix by itself.',
    `  icacls "${path}" /reset /T /C`,
    '    restores inheritance, and inheritance is what supplied the Modify-only ACE above. Where it strips the last',
    '    entry naming you, the directory ends up in exactly the state the diagnosis above describes — its only access',
    '    the inherited `Authenticated Users:(M)` (#8314 measured that follow-on failure).',
    '',
  ]
}

/**
 * When the label half arrived, and why an older build is not the remedy.
 *
 * Emitted for every class: the boundary is a fact about the package
 * `sandbox-windows-acl` (whose `DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION`
 * flag is what needs `WRITE_OWNER`), not about which of its two calls failed, so
 * it is true wherever this module is willing to speak at all. It is also the one
 * fact neither report could get from the error: the failure looks identical on a
 * line where the label does not exist yet, and the build that introduced it is
 * the natural thing to reach for and the wrong one to reach for.
 * @returns the section's lines.
 */
function versionBoundary(): string {
  return [
    'A version boundary worth knowing before reaching for an older build: the label half is new to this package.',
    'Up to `0.1.6-alpha.x` the backend touched the DACL only (flag 4), so a Modify-only workspace provisioned',
    'fine; `0.1.7-alpha.1` is where the mandatory label — and with it the SACL, flag 20 — arrives. On a',
    '`0.1.6-alpha.x`-or-older line this exact failure therefore belongs to a different cause space, while on any',
    '`0.1.7-*` line it is this one. Rolling back is not the fix either: the label is what confines deletes to the',
    'workspace, and reverting it reintroduces the escape it closed.',
    '',
    'The other boundary on that last line, for a reader who goes looking for the built-in repair: the',
    '`diagnose-windows-sandbox-acl` skill is not part of `0.1.7-*` at all — it arrives with `0.2.0`, which is where',
    'the backend starts shipping it under `assets/`. A `0.1.7-rc.2` install that found the skill named in a README',
    'was reading a `0.2.0`-era document: that release\'s own README names it zero times, and no file in its tree',
    'carries the registration symbol. The reach that works is the upgrade, not a packaging fix — nothing was',
    'dropped from the `0.1.7` file list, because there was nothing in `0.1.7` to drop.',
  ].join('\n')
}

/**
 * Why a "weaker grant" is not a smaller version of the same thing.
 *
 * The natural next question after "this needs `WRITE_OWNER`" is whether the
 * label can simply be declined — the label is what makes the apply a SACL write,
 * so dropping it looks like dropping the expensive half. The answer is that the
 * two halves are one mechanism, and the shape of the answer matters more than
 * the verdict: a reader who is told only "no" reaches for the community workaround
 * without knowing what else it has to change.
 *
 * Everything here is read off the shipped source rather than inferred: the label
 * rides the **same** `SetNamedSecurityInfoW` as the grant (`acl.ts`: the
 * security-information flags are `DACL_SECURITY_INFORMATION` alone only when the
 * label edit is `keep`, and `grantWrite`'s apply branch always passes `apply`),
 * and the confined token is lowered to Low before any child starts
 * (`token.ts`'s `restrictTokenIntegrity`, whose own comment calls Low "the level
 * the mandatory labels `grantWrite` applies are matched against"). The directory's
 * Low label is therefore what lets the Low child write there at all under
 * no-write-up — so "sandbox works, workspace unlabelled" is not a configuration
 * this backend can express.
 *
 * Emitted only for `apply-denied`, the class whose diagnosis is the missing
 * `WRITE_OWNER`: that is the one where the label is what gets refused, and so the
 * only one where declining it is an idea a reader could have.
 * @returns the section's lines.
 */
function degradedGrant(): string[] {
  return [
    'One thing to know before asking for a weaker grant, because that is the next idea after this diagnosis —',
    'and it is not a smaller version of the same grant:',
    '  The label rides the SAME `SetNamedSecurityInfoW` as the DACL (one call, two security-information flags), so',
    '  there is no DACL-only path to fall back to — it would have to be built. And dropping the label alone would',
    '  not leave a working workspace: the backend lowers the confined token to Low before any child starts, and its',
    '  own comment calls Low "the level the mandatory labels `grantWrite` applies are matched against". The',
    '  directory\'s Low label is what lets that Low child write here at all; a workspace that keeps the token',
    '  lowering but not the label is one the sandbox can start a command in and the command then cannot write to.',
    '  Declining the label usefully means declining the token\'s Low level with it — which gives up half the',
    '  confinement rather than one of two independent layers, and is a different proposal from dropping a layer',
    '  that was never load-bearing.',
    'This is not offered here as a fix, and neither is `danger-full-access`.',
  ]
}

/**
 * The independent measurement of the missing right, from `#8426`.
 *
 * Everything above is argued from the backend's own source — the merged
 * security-information flags, the owner's implicit rights, the mask an inherited
 * `Authenticated Users` entry carries. A reader is entitled to a measurement
 * taken by someone who had none of that, and `#8426` is one: on a directory
 * whose ACL named the account only through that inherited Modify entry, asking
 * the directory for a Low mandatory-integrity label — the label half alone, no
 * DACL write, so it isolates the right the merged call wants — was refused, and
 * the same operation succeeded the moment that account granted itself
 * `(OI)(CI)F`, whose mask carries `WRITE_OWNER`. Unelevated throughout, and
 * reversible afterwards (the level moved back to Medium just as easily). That is
 * the missing right demonstrated from outside this project's reading, and it is
 * a right on the **directory**: no `SeRelabelPrivilege`, no token privilege, no
 * elevation.
 *
 * The command itself is deliberately **not** printed here, and that is a
 * decision rather than an omission — the same one the `#8272` paragraph of the
 * README records. A label write is not a check: where the caller holds Full
 * control it SUCCEEDS, and then the label and its inheritance are already
 * written. This module hands over only operations that are safe to run when they
 * succeed, which is why the two checks above are reads. The evidence is what the
 * report measured; the probe stays in the report.
 *
 * The same report then repaired two real trees the same way — object right
 * first, integrity label second, 9521 and 5592 objects, no failures. The order
 * is not interchangeable and is worth stating: the second step is the one that
 * needs what the first supplies. Both halves are already in the advisory's own
 * remedy, in the same order.
 *
 * The contrast with the workspace-denial family is deliberate. There the
 * recursive grant cannot be hand-written at all, because the SID it must name
 * has no name to map (`ERROR_NONE_MAPPED`, 1332), which is why that advisory
 * forks on breadth instead of handing over a line.
 * @returns the section's lines.
 */
function writeOwnerEvidence(): string[] {
  return [
    'A second confirmation, measured by a reporter who had none of the reasoning above (#8426) — unelevated, on a',
    'directory whose ACL named the account only through the inherited `Authenticated Users:(M)` entry: asking that',
    'directory for a Low mandatory-integrity label — the LABEL half on its own, with no DACL write, so it isolates',
    'the one right this call wants — was refused, and the identical operation stopped being refused the moment the',
    'same account granted itself `(OI)(CI)F`, whose mask carries WRITE_OWNER: same account, same elevation,',
    'succeeding at once, and reversible from there (the level moves back to Medium just as easily).',
    'So the missing right is a right on this DIRECTORY, exactly as the diagnosis above reads it: no',
    'SeRelabelPrivilege, no token privilege, no elevation anywhere in that measurement. (That probe is not printed',
    'here and is not offered as a check: a label write is not a read — where the caller already holds Full control',
    'it succeeds, and then the label and its inheritance are written. This module hands over only the two reads',
    'above.) The same report repaired two real trees that way — object right first, integrity label second, 9521',
    'and 5592 objects, no failures — an order that cannot be swapped, since the second step is the one that needs',
    'what the first supplies; which is why the remedy below grants first and lets the backend write the label.',
    '',
  ]
}

/**
 * What the grant leaves behind once it applies, and how far its label travels.
 *
 * The advisory hands the reader a command that makes the backend's workspace
 * grant succeed. This section says what that grant *is* from the other side —
 * not as a warning against running it (without it nothing sandboxed runs at
 * all) but because the effect outlives the session and reaches outside the
 * workspace, and a reader who learns that from a broken build three projects
 * later has learned it too late. `#8312` collected those far-away symptoms;
 * `#8314` measured how the label gets there.
 *
 * Every claim is read off the shipped source rather than repeated from the
 * reports: the standing edits and the dispose path that leaves them
 * (`src/grant.ts`, whose `dispose` doc says the standing edits are skipped by
 * design, and `src/index.ts`, whose fail-closed cleanup says the same in
 * plainer words); the label's `(OI|CI)` inheritance and its home in the SACL
 * (`src/acl.ts`, the merged security-information flags); and the hard-link
 * boundary, which the backend's own suite pins as a known reach
 * (`tests/runner.spec.ts`, "a workspace hard link lets the grant reach an
 * external file object").
 *
 * Two things it deliberately does **not** do. It does not offer a removal
 * command: the maintainers' own diagnosis skill reports the label and leaves it,
 * removing one needs `WRITE_OWNER`, and this project has no Windows host to
 * verify a line on — shipping an unverified removal command would be the same
 * defect the rest of this module exists to answer. And it does not present the
 * out-of-tree reach as universally true: it is what happens when the workspace
 * contains hard links into a store on the same volume, which is what a pnpm
 * install produces and what the report measured.
 *
 * Emitted for every class, like {@link versionBoundary} and for the same reason:
 * the fact is about the package's grant (and the remedy the advisory hands over
 * in every class is that grant), not about which of its two calls failed.
 * @returns the section's lines, ending with the blank separator line.
 */
function standingEdits(): string[] {
  return [
    'What the grant leaves behind, once it applies — worth knowing before you run the command above, because the',
    'backend does not take it back:',
    '  The three entries are STANDING, deliberately, and nothing revokes them. The workspace grant is a reuse cache:',
    '  the dispose path is documented to revoke the revocable (temp) grants and leave "the standing workspace edits',
    '  in place", and the failure-cleanup path says it in plainer words — standing ACEs "are NOT revoked — they are',
    '  the intended end state (the reuse cache), not an error artifact". They outlive the session and the harness',
    '  exiting (`sandbox-windows-acl/src/grant.ts`, `src/index.ts`).',
    '  The Low integrity label is INHERITABLE (`(OI|CI)`) and it lives in the SACL — which is why the `icacls',
    '  /reset` above does not take it off: that command rebuilds the DACL. Windows starts a process at the minimum',
    '  of the user\'s and the program\'s integrity, so anything started from a tree the harness has written to runs at',
    '  LOW integrity, and none of the symptoms names DSH (#8312 collects them): an Electron/Chromium app exiting',
    '  `0x80000003` at startup with no output (#7709), msbuild / dotnet / npm refusing or warning about the files as',
    '  if they came from the Internet when no `Zone.Identifier` exists (#8175), a double-clicked `.exe` / `.cmd`',
    '  reporting "publisher could not be verified" (#7735).',
    '  It can also leave the workspace. An NTFS hard link is a SECOND NAME for one file object, so both names share',
    '  one security descriptor — and a pnpm workspace is largely hard links (`node_modules` pointing into a',
    '  content-addressed store on the same volume). An inheritable label written inside the tree therefore lands on',
    '  the STORE\'s objects and stays there, after which every project using that store builds with executables that',
    '  start at Low integrity, and the failure surfaces as the build tool rather than the sandbox: `vite build` unable',
    '  to remove its own temp file, `pnpm install` unable to replace a hook (#8314 measured the whole chain). The',
    '  backend\'s own suite pins the link reach as a known boundary — "a workspace hard link lets the grant reach an',
    '  external file object" — and its README calls refusing multiply-linked files unviable for ordinary pnpm',
    '  installs, which leaves the out-of-tree reach open rather than unknown.',
    '  It is also why the label is not simply removable here: the built-in `diagnose-windows-sandbox-acl` skill',
    '  (0.2.0 and later) reports `LOW_LABEL` and by design does not remove it, and removing an integrity label needs',
    '  WRITE_OWNER — the same right this whole failure is about. This advisory hands over no removal command: the',
    '  maintainers\' own skill does not, and an unverified one would be the defect this plugin exists to answer.',
    'None of this makes the command above the wrong move — without it, nothing sandboxed runs in this workspace. It',
    'is what the harness does to a directory it has been pointed at, and it is worth knowing before rather than',
    'discovering it as a broken build in some other project later.',
    '',
  ]
}

/**
 * Build the advisory attached to the failing tool result.
 *
 * The family decides everything: one function so a caller does not have to
 * remember which family needs which fact, and so the mode requirement of the
 * two gated families is enforced by construction rather than by convention.
 * @param failure - the recognized failure.
 * @param context - what the caller knows about the failing call.
 * @returns the user-role notice text, with any remedy ready to paste.
 * @throws when a mode-gated failure is advised without its resolved sandbox mode.
 */
export function advisoryText(failure: RecognizedFailure, context: AdvisoryContext = {}): string {
  if (failure.family === 'pty-startup') {
    if (context.mode === undefined) {
      throw new Error('sandbox-grant-advisor: the persistent-shell advisory requires the resolved sandbox mode')
    }
    return ptyAdvisory(failure, context.mode, context.tool, context.href)
  }
  if (failure.family === 'native-init') {
    if (context.mode === undefined) {
      throw new Error('sandbox-grant-advisor: the native-init advisory requires the resolved sandbox mode')
    }
    return nativeInitAdvisory(failure, context.mode, context.electronHost ?? electronHost(), context.href)
  }
  if (failure.family === 'workspace-denial') return workspaceDenialAdvisory(failure, context.tool, context.href)
  if (failure.family === 'temp-root-inside-workspace') return tempRootAdvisory(failure, context.tool, context.href)
  if (failure.family === 'cim-wmi-denial') {
    if (context.mode === undefined) {
      throw new Error('sandbox-grant-advisor: the CIM/WMI advisory requires the resolved sandbox mode')
    }
    return cimWmiAdvisory(failure, context.mode, context.href)
  }
  return aclAdvisory(failure, context.href)
}

/**
 * Build the advisory for a workspace-provisioning failure.
 * @param failure - the recognized failure.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text, with the fix commands ready to paste.
 */
function aclAdvisory(failure: ProvisioningFailure, href?: string): string {
  const path = failure.path ?? PLACEHOLDER
  const where = href === undefined ? `tracked upstream (discussions ${ACL_DISCUSSIONS})` : `tracked upstream: ${href}`
  return [
    'Sandbox provisioning failed — no sandboxed command can run in this workspace until its ACL applies.',
    'The failure belongs to the WORKSPACE, not to the command: under this mode a command that only reads',
    'fails identically, so trying a different or more harmless command is not a retry that can succeed.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    '',
    diagnosis(failure),
    '',
    versionBoundary(),
    '',
    'Confirm the cause (unelevated) — `icacls` is a normal user command:',
    `  icacls "${path}"`,
    'Look for an ACE that names YOUR OWN account (run `whoami` if unsure) with (F) / Full control or',
    '(WO) / Write owner. If the strongest entry naming you is (M) / Modify — or no entry names you at all and',
    'your access comes from an inherited `Authenticated Users:(M)` — that is this failure.',
    '',
    ...(failure.klass === 'apply-denied' ? writeOwnerEvidence() : []),
    'Ownership decides which of the two commands below can work, so read it first — PowerShell 5.1 or later:',
    `  (Get-Acl "${path}").Owner      # compare with: whoami`,
    'If that is not your own account, take the second branch: the first one is refused before it runs.',
    '',
    'IF YOU OWN THE DIRECTORY — the usual workspace, whether on the system drive or a data volume:',
    '  one unelevated line, then run the command again:',
    `  PowerShell: icacls "${path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,
    `  cmd:        icacls "${path}" /grant "%USERNAME%:(OI)(CI)(WO)"`,
    'WRITE_OWNER is exactly the right the prerequisite names, so this grants nothing the harness did not ask for,',
    'and (OI)(CI) makes the ACE inheritable, so one command reaches the workspace\'s existing subdirectories.',
    'The grant is still scoped to THIS directory and its children: another workspace root on the same volume is',
    'a sibling rather than a child, so it needs the same line once — which is why a second workspace fails on a',
    'machine where the first one was already repaired.',
    'Full control works just as well — the same line with `F` in place of `(WO)`:',
    `  icacls "${path}" /grant "$env:USERNAME:(OI)(CI)F"`,
    'Why `(WO)` is the whole of what is missing there: an owner holds READ_CONTROL and WRITE_DAC implicitly,',
    'and WRITE_DAC is what `icacls /grant` itself needs — so the DACL half of the merged write already has what',
    'it wants, and WRITE_OWNER is the single missing piece.',
    '',
    'IF YOU DO NOT OWN IT — a directory an installer or another account created, e.g. owner',
    '`BUILTIN\\Administrators`:',
    '  the line above cannot run at all. Changing a DACL takes WRITE_DAC, which you hold neither as owner nor',
    '  through any ACE, so `icacls /grant` is refused with `Access is denied` — for the very command that would',
    '  fix it. The merged write wants WRITE_DAC and WRITE_OWNER together, so `(WO)` alone would not be enough',
    '  here even if it went through. Run the grant once from an account that already holds both — that is, from an',
    '  ELEVATED prompt:',
    `  icacls "${path}" /grant "<your-account>:(OI)(CI)F"`,
    'Full control is used because it is the rights set covering both halves; the other reach both reports name is',
    'to take ownership first, which also needs elevation (it wants SeTakeOwnership), after which the unelevated',
    '`(WO)` line above applies:',
    `  icacls "${path}" /setowner "<your-account>"`,
    'Or sidestep the ACL entirely: create the workspace under `%USERPROFILE%` — a directory created there',
    'inherits Full control for you — and open the session on that one.',
    '',
    ...nonFixes(failure, path),
    ...standingEdits(),
    ...(failure.klass === 'apply-denied' ? [...degradedGrant(), ''] : []),
    'How to read this: the harness documents the prerequisite (' + PREREQUISITE + ') and this',
    'error does not name it yet, so the advice is delivered here instead. This is a stopgap, ' + where + '.',
    'It arrives through the session rather than through a shell, which is the thing this failure has just taken',
    'away — the reason a repair script cannot be the answer at the moment it is needed.',
    'What it is NOT: this plugin neither edits ACLs nor elevates — the command above is yours to run.',
    'Your file read/write tools still work; only sandboxed command execution is blocked.',
  ].join('\n')
}

/**
 * Build the advisory for a confined Windows child that never reached its entry
 * point.
 *
 * Three things this text must not do: retry silently (the identical call cannot
 * start), hand the model a command to run (there may be no working shell to run
 * it in — that is what died), or assert which producer this is. The code is a
 * loader status and says nothing about the sandbox by itself, so the diagnosis
 * is the *class* ("the process never started") plus the producers that have
 * been measured under this harness, each with the check that distinguishes it.
 * One of those checks the plugin answers itself and reports as a fact — whether
 * this process is an Electron binary — rather than assuming, because a reader
 * told "this is the packaged desktop" without evidence would be reading a guess
 * dressed as a finding.
 * @param failure - the recognized failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @param onElectron - whether this process is an Electron binary.
 * @param href - optional URL shown for the upstream threads.
 * @returns the user-role notice text.
 */
function nativeInitAdvisory(
  failure: NativeInitFailure,
  mode: SandboxModeName,
  onElectron: boolean,
  href?: string,
): string {
  const where = href === undefined ? `tracked upstream (discussions ${NATIVE_INIT_DISCUSSIONS})` : `tracked upstream: ${href}`
  return [
    'Sandboxed command never started — the process died while its native libraries were loading.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}        (0xC0000142 STATUS_DLL_INIT_FAILED)`,
    `The call ran under sandbox mode \`${mode}\`, where the harness starts every command through its`,
    'restricted-token runner.',
    '',
    `0x${failure.exitCode.toString(16).toUpperCase()} is STATUS_DLL_INIT_FAILED: the Windows loader terminated the process while it was`,
    'initializing its DLLs and C runtime, which is BEFORE the program\'s entry point. A command that ran and',
    'then failed exits with its own status and prints its own output; this one produced neither. The number',
    'is also not a portable exit status — those are 0-255, and this is a 32-bit NTSTATUS. Nothing in the code',
    'says "sandbox" by itself; what makes the sandbox a candidate is the mode above, under which every',
    'command is spawned through the ACL runner.',
    '',
    'Why the conversation got only a number: upstream admits a failure as the RUNNER\'s own only at exit 127 with',
    'a `windows-acl-run: <detail>` line on stderr. This failure is not that — the runner returns normally and the',
    'CHILD is killed by the loader — so the code passes through as an ordinary nonzero exit status, which the',
    'renderer reports without marking the result an error. It is therefore not a swallowed sandbox diagnostic:',
    'it never enters that classification at all. On the persistent-PTY path it is thinner still — the shell layer',
    'throws a fixed sentence with no status in it, so the code does not reach the conversation even as a number.',
    '',
    'Three producers have been measured under a confining Windows mode. Check which one this is:',
    '  1. An MSYS2 / Git-Bash program — `bash.exe`, `sh.exe`, or anything from a Git for Windows or MSYS2',
    '     distribution. Under the restricted token its runtime cannot create the pipe it uses for signals,',
    '     and it aborts in the loader phase (`couldn\'t create signal pipe, Win32 error 5`), while `cmd.exe`',
    '     and PowerShell run fine in the same workspace under the same mode (#7877).',
    '     If that is what could not start: write the same work as a PowerShell or `cmd` command instead and',
    '     continue — do not retry the MSYS2 program.',
    '  2. The packaged desktop application\'s sandbox runner. `dsh-sandbox-local` starts the runner as',
    '     `[process.execPath, runner.js]`, and in the packaged build `process.execPath` is the Electron',
    '     executable. The mechanism behind this one is the runner\'s CONSOLE, not its token: the confined',
    '     child inherits a console from the runner, and a runner that owns none leaves the child to ask for one',
    '     of its own — which a restricted token is not allowed to have. #8208 captured the sequence: `conhost.exe`',
    '     is created BY the restricted child, exits `0xC0000022 STATUS_ACCESS_DENIED`, and the child then dies',
    '     with the code above. Both console-less configurations are measured:',
    '     (a) the host binary is a GUI-subsystem program, which never owns a console — the packaged desktop,',
    '         where every confined command dies this way (#8193);',
    '     (b) the host binary is a real console-subsystem `node.exe` and the runner was still spawned without a',
    '         console, because `DETACHED_PROCESS` was set: `spawnSync(node, [runner, …], { detached: true })`',
    '         returns `0xC0000142` while the same call without that flag returns `0` (#8208). That arm needs no',
    '         desktop and no particular machine, so it is the check worth running here.',
    '     What is NOT the discriminator here: this token\'s GROUPS, PRIVILEGES and INTEGRITY LEVEL. #8208 compared',
    '     `whoami /groups` and `/priv` from children of a working node host and of the failing Electron host —',
    '     identical, down to the group count and session — and a low-integrity `cmd.exe` runs fine on that machine,',
    '     so neither the token\'s groups nor low integrity alone explains this. That says nothing about which SIDs',
    '     the token was RESTRICTED to, which is a different member of the same object and producer 3 below.',
    ...(onElectron
      ? [
          '     This process IS an Electron binary (`process.versions.electron` is set), so a GUI-subsystem host',
          '     applies here. The way out is a real node host — the packaged desktop ships one at',
          '     `resources/runtime/primary-runtime/dependencies/node/bin/node.exe`, and the same runtime installed',
          '     for workspace dependencies lands at',
          '     `%USERPROFILE%\\.dsh\\dsh-runtimes\\dsh-primary-runtime\\dependencies\\node\\bin\\node.exe` (present',
          '     once `load_workspace_dependencies` has run) — and the unpacked `node apps/cli/lib/bin.js web` host',
          '     works for the same reason: the same confined `pwsh`/`cmd` calls start there (#8193 measured exit',
          '     81/82; #8208 measured exit 0 with the command\'s own stdout intact, with and without `windowsHide`).',
          '     ONE CONDITION RIDES WITH THAT: the runner must be spawned WITH a console, i.e. not with',
          '     `DETACHED_PROCESS`. A real host alone is not enough if that flag is set (#8208) — the host binary is',
          '     what supplies the console, and the spawn flag is what can take it away again.',
          '     If no real node host can be put in front of the runner, the same effect fits inside it: `AllocConsole`',
          '     before the restricted spawn, with the three standard handles restored afterwards, in',
          '     `dsh-win32-process`\'s `createRestrictedProcess` — the funnel every restricted child goes through.',
          '     #8208 measured `cmd /c exit` and `pwsh -c "Write-Output …"` both reaching 0 with stdout intact under',
          '     that change, and as a no-op on a runner that already owns a console; it costs a `user32` binding and',
          '     one console host per runner process.',
          '     `danger-full-access` only CONFIRMS the diagnosis: on this platform it silently removes the sandbox',
          '     from every shell call. Do not unset `ELECTRON_RUN_AS_NODE` instead either — the desktop runner IS',
          '     that Electron binary, so dropping the variable would take `runner.js` down with it (#8193 records',
          '     this interaction with #8174).',
        ]
      : [
          '     This process is NOT an Electron binary (`process.versions.electron` is unset), so the runner is a real',
          '     Node binary here and a GUI-subsystem host cannot be the cause. One measured shape is still open: a',
          '     runner that owns no console because it was spawned with `DETACHED_PROCESS` fails exactly this way on a',
          '     real node host too (#8208) — that is a property of how this host was launched, not of the build. If the',
          '     program was not an MSYS2 one either, and the runner was not spawned detached, producer 2 does not',
          '     apply here: run producer 3\'s mode switch below, and if that does not separate it either, stop and',
          '     hand it to the user.',
        ]),
    '  3. A capability SID inside the restricted token\'s own restricting list (#9186). It isolated this to that',
    '     single input by driving the sandbox API directly, with the runner hosted by a real node binary and the',
    '     DACLs left untouched: with the `workspace-write` restricting list — `[logon SID, EVERYONE]` plus one',
    '     capability SID — EVERY program died this way (`whoami.exe` and `cmd.exe` as well as `pwsh`), while the',
    '     `read-only` list, which carries no capability SID, started the same program normally in both stdio',
    '     shapes (piped and inherited). The capability SIDs are derived per workspace and per private temp',
    '     directory, and they join the list only under `workspace-write`; `read-only` carries none by design.',
    '     CHECK: hold the command and the tool fixed and change only the MODE. If `read-only` starts the command',
    '     that `workspace-write` kills, this is the producer — one switch, no debugging tools, and it is the only',
    '     discriminator this status code does not already give you (see the boundary below). If both modes fail,',
    '     the difference is elsewhere and this is producer 2 (the host) or a cause outside the list entirely.',
    '     One thing this is NOT: `.NET`. Pure-native programs die here identically, so the "self-contained .NET',
    '     runtime" cause the earlier reports attracted is retired by that control arm.',
    '',
    'Do not retry this call: the environment has not changed, and the identical call produces the identical',
    'code. Convert the work only in case 1; otherwise stop and hand it to the user.',
    '',
    'Honest boundary — 0xC0000142 has producers this list does not have: a program that cannot load one of',
    'its own DLLs dies this way too, and the backend\'s own source records the console case as an inherent',
    'limit of the backend (`CREATE_NO_WINDOW` / `CREATE_NEW_CONSOLE` children die with `STATUS_DLL_INIT_FAILED`',
    'under the restriction). #8208 explains that limit instead of repeating it, and the explanation is a single',
    'rule: in a restricted token a console can be INHERITED but not CREATED. Both shapes above follow from it —',
    'the child needs a console it did not create, and anything that forces it to CREATE one is fatal on its own.',
    '#8336 measured that side directly, on one machine, with a console-owning host, a restricted token and the',
    'Low integrity level, varying only the creation flags: `0`, `DETACHED_PROCESS` and `CREATE_NEW_PROCESS_GROUP`',
    'all reached the program, while `CREATE_NO_WINDOW` and `CREATE_NEW_CONSOLE` both died with the code above.',
    '`STARTF_USESHOWWINDOW` with `SW_HIDE` — how a window is hidden without isolating a console — was harmless,',
    'and so was `CREATE_NO_WINDOW` on an UNRESTRICTED token, which is what makes the two a pair rather than a',
    'list of forbidden flags.',
    'The same code runs in BOTH directions, which is why it cannot name its own cause: the restricted-token',
    'layer records that a token built WITHOUT the logon-SID + EVERYONE keep-alive pair also dies in early DLL',
    'init with exactly this status (and `pwsh` earlier still, in its CNG path, as `0xE0434352`). Too few entries',
    'in the restricting list and too many — producer 3 — land on the same `0xC0000142`, so the status alone',
    'cannot tell you which mistake was made. Only a comparison can, and the cheapest one is producer 3\'s mode',
    'switch.',
    'The creation flags this harness actually passes are three sets and none of them is `CREATE_NO_WINDOW` —',
    '`0` on the piped path, `CREATE_SUSPENDED` on the inherited-job path, and',
    '`CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT` on the ordinary path (that constant is not defined anywhere',
    'in the process source). Those three are fatal under a console-less host and harmless under a host that owns',
    'a console, so there the console decides. A flag that forces creation is a different animal: it decides even',
    'when a console is there to be inherited.',
    '',
    'One thing that gets suspected and is not the cause: `windowsHide`. It is named here because it is the',
    'first thing a search turns up, and it points at the wrong component — the flag is not set anywhere on the',
    'confined path above. It appears on the ORDINARY subprocess path (`dsh-subprocess-local`: `windowsHide:`',
    '`platform === \'win32\'`), which starts the runner rather than the confined child, and the restricted spawn',
    'in `dsh-win32-process` passes the three flag sets just listed and defines no `CREATE_NO_WINDOW` constant at',
    'all. Where it IS set — on the host — #8208 measured it both ways on a host that works: with and without',
    '`windowsHide`, the confined `pwsh` reached exit 0 with its own stdout intact. The reason is the rule again:',
    'a windowless console is still a console, and that is what the child inherits. What decides is whether the',
    'host owns a console OBJECT, not whether it owns a window.',
    '',
    'One arm of this family was applied, measured, and rejected — named so a reader does not reach for it:',
    'putting `DETACHED_PROCESS` on the RESTRICTED CHILD removes its console request and does stop the crash,',
    'but `pwsh` then exits 0 with zero bytes on stdout AND stderr, while `cmd.exe` keeps its output (#8208).',
    'That trades a loud failure for a silent one on the interpreter most likely to be used, so the runner-side',
    'remedies above — which keep the output — are the ones to take.',
    '',
    'This is not a claim that the sandbox caused the failure — the code cannot say that. What is claimed is',
    'narrower and checkable: the process never reached its entry point, and under this mode these producers are',
    'known.',
    '',
    'This is a stopgap, ' + where + '. What it is NOT: this plugin neither changes an environment nor',
    'widens the sandbox — the checks above are yours to make, and `danger-full-access` is not offered as a fix.',
  ].join('\n')
}

/**
 * Build the advisory for a persistent-shell startup failure.
 *
 * The one thing this text must never do is hand the model a command to run:
 * there is no shell to run it in. That is why the remedy is addressed to the
 * user (preset choice), while the model's instruction is to stop — the
 * alternative, naming a one-shot shell tool, would be advice to call a tool the
 * failing composition does not mount (`minimal` mounts exactly one platform
 * shell, the persistent PTY: the design note
 * `.agents/notes/implemented/simplification/2026-09-03-minimal-profiles-persistent-shell-only.md`).
 * @param failure - the recognized failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @param tool - the tool whose call failed, when the caller knows it.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text.
 */
function ptyAdvisory(failure: PtyStartupFailure, mode: SandboxModeName, tool?: string, href?: string): string {
  const where = href === undefined ? `tracked upstream (discussions ${PTY_DISCUSSIONS})` : `tracked upstream: ${href}`
  const call = tool === undefined ? 'This tool' : `The \`${tool}\` tool`
  return [
    'Persistent shell failed to start — command execution is unavailable in this session, and retrying cannot fix it.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    '',
    `${call} is a PERSISTENT PTY session (a shell that stays alive between calls), and this session's sandbox mode is`,
    `\`${mode}\` — not \`danger-full-access\`. A confining mode spawns the shell through the sandbox, and there the`,
    'terminal backend cannot create the pseudo-console at all, so the child exits before its first prompt. The same',
    'shell works under `danger-full-access`, and the one-shot shell tool works under the same confining mode:',
    'persistent PTY × confining sandbox is the combination that fails.',
    '',
    'Which sessions fail inside that combination is not chance — it is deterministic per (session mode × the host',
    'binary carrying the sandbox runner), so a "working now" attempt in the same session is not evidence of flakiness.',
    'Measured against the desktop build with the same runner and the same ConPTY in every arm (#8322):',
    '  - runner hosted by a plain console-subsystem `node.exe` → the confined shell starts, prompt and shell-integration',
    '    marks correct;',
    '  - runner hosted by the packaged desktop\'s GUI-subsystem Electron executable (started with',
    '    `ELECTRON_RUN_AS_NODE=1`) → the child dies silently: zero bytes on stdout AND stderr, and the non-interactive',
    '    arm exits 0 with everything it printed lost.',
    'The rule behind both this and the `0xC0000142` family is the one stated there for its own case: under the',
    'restricted token a console can be INHERITED but not CREATED — so the host binary, the thing that owns a console',
    'or owns none, is what the arms above turn on. It is also why the same build behaves differently depending on how',
    'it was started: the same version run as the desktop app fails, while the Web UI started from a terminal —',
    'whose `process.execPath` is a real `node.exe` — is reported working under the same confining mode (#8313).',
    'And the mode that decides is the one the SESSION records, not the one the environment now holds: a session',
    'whose stream recorded the confining mode keeps failing',
    'after the app is restarted with a different mode in the environment, while switching it inside that session',
    'takes effect immediately (#8322).',
    '',
    'There is a second, cheaper split when the host is already a real `node.exe`, and it costs one setting: change',
    'only the MODE. A machine where the same console-owning host dies under `workspace-write` and starts the shell',
    'under `read-only` is the restricting-list arm the `0xC0000142` advisory describes as its producer 3 (#9186); a',
    'machine where the packaged desktop app fails while the Web UI works under the same confining mode is the host',
    'arm above (#9170). Neither comparison needs a debugger, a second machine, or a reading of any log — and',
    '`read-only` is a control here rather than a remedy, since it takes the workspace write access away with it.',
    '',
    'Do NOT retry, and do not look for a command that fixes it: every attempt will fail identically, and there is no',
    'shell to run a command in. Use your file read/write tools instead, and hand the choice below to the user.',
    '',
    'What unblocks the session — the user\'s decision, not the model\'s:',
    '  1. switch the agent preset to `standard`, whose shell tool is a one-shot subprocess (no PTY) and works',
    '     under the sandbox; or',
    `  2. override the \`${MINIMAL_PRESET_ROW}\` row in your profile patch — \`${PROFILE_PATCH}\`, or`,
    `     \`${GLOBAL_PATCH}\` for every profile — replacing its \`persistent-shell\` group with`,
    `     \`${ONE_SHOT_SHELL}\` (a one-shot subprocess, no PTY); the patch layer is yours, so an upgrade`,
    '     will not overwrite it; or',
    '  3. run the session from a host that owns a console instead of the packaged desktop app — the Web UI started',
    '     from a terminal (`process.execPath` is a real `node.exe` there) was reported working under the same',
    '     confining mode and the same version (#8313); or',
    '  4. run the session with `danger-full-access`, which drops the very confinement the sandbox exists to give.',
    '     Prefer 1 to 3.',
    '',
    'How to read this: the failure names no cause and points at no remedy, so the diagnosis is delivered here instead.',
    'This is a stopgap, ' + where + '. Unless the mode is `danger-full-access`, this plugin stays silent, because a',
    'shell can fail to start for other reasons and a confident wrong cause is worse than no answer.',
  ].join('\n')
}

/**
 * Build the advisory for a confined command that was denied a path inside its
 * own workspace.
 *
 * Four things this text must do, and one it must not. It must lead with the
 * fact that **retrying is provably useless** (the backend's provisioning check
 * short-circuits on the root, so the object that missed the propagation is never
 * revisited) — that is the whole reason the model needs telling rather than
 * discovering. It must show the **path it keyed on and the root it tested it
 * against**, because the family's claim is a statement about two strings and the
 * reader is entitled to audit it. It must give the **two-sided** reachability
 * rule, since a check that only looks for the capability ACE reports an object
 * as granted when the read side is refused as well. And it must split the
 * diagnosis into its **two branches** — the DACL entry that did not arrive, and
 * the mandatory-integrity LABEL that did not (#8383) — because from inside a
 * session they are indistinguishable, both are permanent for the same
 * root-only-short-circuit reason, and a reader who repairs the wrong half has
 * learned nothing. The fork is placed on **breadth**, which is the one fact the
 * reader already has: a handful of stubborn objects is the DACL branch, and
 * nothing below the root writable at all is the label branch.
 *
 * What it must not do is print a repair command. For the DACL branch the obvious
 * one is refused by Windows with `ERROR_NONE_MAPPED` (1332) — a capability SID
 * has no name for `icacls` to map — and the one that would work needs
 * `WRITE_DAC` on the object, which is the right in question. For the label
 * branch the shape of the move is a SACL write on the whole subtree, which needs
 * the same class of object right and is not verified here either. This project
 * has no Windows host to verify a line on, and the standing-grant section of the
 * ACL advisory is held to the same standard for the same reason: an unverified
 * remedy delivered confidently is the defect this plugin exists to answer. The
 * mechanism is stated instead, and the reader is told why the command is absent.
 * @param failure - the recognized failure.
 * @param tool - the tool whose call was denied, when the caller knows it.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text.
 */
function workspaceDenialAdvisory(failure: WorkspaceDenialFailure, tool?: string, href?: string): string {
  const where = href === undefined
    ? `tracked upstream (discussion ${WORKSPACE_DENIAL_DISCUSSIONS})`
    : `tracked upstream: ${href}`
  const call = tool === undefined ? 'This command' : `The \`${tool}\` command`
  const subject = failure.paths[0] ?? '<the path from the error line above>'
  return [
    'Denied inside your own workspace — the access the workspace is supposed to carry does not cover that part of',
    'the tree, and retrying cannot repair it.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    `${call} ran under sandbox mode \`${failure.mode}\`, where a write INSIDE the workspace is supposed to succeed, and every`,
    'path it named is inside this session\'s workspace:',
    ...failure.paths.map(path => `  ${path}`),
    `  (workspace root: ${failure.workspaceRoot})`,
    'So this is not the sandbox declining work that belongs outside the workspace. It is the workspace\'s own access',
    'setup failing to cover an object inside it, which is why every command touching that object fails the same way.',
    '',
    'Why — and why retrying cannot fix it:',
    '  The host-side grant is written ONCE, on the workspace ROOT, and relies on Windows ACE inheritance to reach',
    '  everything beneath it. Writing an inherited ACE into an ALREADY-EXISTING child needs WRITE_DAC on that child;',
    '  where the caller does not hold it, Windows skips the child silently — no error, no return value, no log line.',
    '  The backend then checks only the root (`hasExactGrant(workspaceRoot)`) and returns early when the grant is',
    '  already there, which it is from the first call onwards. The descendants that missed the propagation are',
    '  therefore never revisited — not later in this session, not in any later one — so the identical command keeps',
    '  failing and there is no number of attempts that changes that',
    '  (`packages/sandbox/sandbox-windows-acl/src/acl.ts`).',
    '  There is a second, higher skip, and it is the one the third branch below turns on: on a session-scoped',
    '  workspace the layer that ASKS for the grant keeps its own per-lifetime map of the roots it has already',
    '  provisioned and consults that map instead of the DACL, so for those roots the check above is not even reached',
    '  again (`packages/sandbox/sandbox-local/src/index.ts`: the map guard at :403-421, "materializes once per',
    '  workspace per server lifetime").',
    '  WHICH objects miss it is a fact about who created them: objects the harness itself creates inherit the ACE,',
    '  while objects that already existed or that another account or tool created (an installer, an editor, another',
    '  agent harness running under its own account) are the ones the propagation skipped. #423 measured 170 of 729',
    '  objects missing it, INCLUDING root-level files — so it is not only subdirectories, and "write it at the',
    '  workspace root instead" is not a safe move either.',
    '  The same call also writes the mandatory-integrity LABEL, and that half can fail to reach the tree while the',
    '  ACE half arrives — that is the second branch below, and it produces this identical denial. Both halves are',
    '  permanent for the same reason, so settling WHICH one you are looking at comes before anything else.',
    '',
    'Confirm it — and settle FIRST which of the three is missing, because all three produce this same denial and a',
    'reader who repairs the wrong one has learned nothing:',
    `  icacls "${subject}"`,
    `  icacls "${failure.workspaceRoot}"`,
    'BREADTH IS THE FIRST CUT, and it needs no tool — it is what your own attempts have already shown:',
    '  - A HANDFUL of stubborn objects while the rest of the tree writes normally → the DACL half. The capability ACE',
    '    did not arrive at those objects; the workspace is otherwise usable. This is the #423 measurement.',
    '  - NOTHING below the root is writable at all, with the root itself the only writable place → the LABEL half',
    '    (#8383). A Low-integrity child may write to a directory only when that directory\'s own mandatory-integrity',
    '    label is Low as well; the kernel runs its no-write-up check IN ADDITION to the access check, so a DACL that',
    '    is perfect everywhere changes nothing.',
    '  - THE ROOT ITSELF IS REFUSED — nothing writes, the root included, and work that used to succeed here now',
    '    does not → NEITHER half above (#8409). The standing grant is gone from the root\'s own DACL, and the layer',
    '    that would put it back has stopped looking. Two things about this branch are different in kind from the',
    '    other two: no command reaches it, and it is the one branch of this family with a recovery inside the',
    '    product — both are in half three below.',
    '',
    'Half one — the DACL ACE did not reach the object:',
    '  The root carries an inheritable ACE for the workspace capability SID — a `S-1-4-…` that `icacls` prints as an',
    '  unresolved SID rather than a name — with Modify or Full control; the failing object does not have it. Check each',
    '  path listed above the same way; the first is shown here.',
    '  THE TRAP: reading and listing go through the NORMAL token, writing and deleting through the RESTRICTED',
    '  (low-integrity) one, and both sides must pass. An object whose DACL names only Administrators/SYSTEM plus the',
    '  capability SID is refused on the read side as well, so it looks granted to a check that only searches for the',
    '  capability SID — #423 measured exactly that on a `.cache` directory. A check that asks only "is the SID there?"',
    '  reports those objects as fine while LIST and WRITE are both denied.',
    '  TEST: does the object show the capability ACE at all, inherited or not? Absent → this half, and the object is',
    '  the thing to repair.',
    '',
    'Half two — the DACL arrived and the LABEL did not (#8383, measured 2026-09-30):',
    '  Measured on a `0.2.0-rc.2` install (Windows 11, 26200 family, NTFS): the workspace root writable, EVERY',
    '  subdirectory denied, and — this is what makes it the label half — the capability ACE present and correctly',
    '  inherited on every one of them. The label, meanwhile, exists on the root alone:',
    '    icacls "<root>"        → Mandatory Label\\Low Mandatory Level:(OI)(CI)(NW)',
    '    icacls "<subdir>"      → no Mandatory Label line at all',
    '  The decisive form of that measurement is a directory created AFTER the grant was materialized: it inherits the',
    '  capability ACE (marked `(I)`) and still receives no label. That is what rules out "these objects simply predate',
    '  the grant" and isolates the failure to the label layer. One caveat the report itself is careful about and worth',
    '  keeping: a GRANDCHILD directory having no label proves nothing on its own, because inheritance is per-parent and',
    '  the intermediate directory carries none — only a DIRECT child of the labelled root is evidence.',
    '  Why it is permanent: the label goes out in the same single security-descriptor write that carries the grant,',
    '  with the inheritance flag set, but only on the paths the backend enumerates — the workspace root (plus the',
    '  session\'s private temp directory), with no descendant walk. The root-only idempotency check then requires the',
    '  grant, the world delete-child deny AND the exact label (`hasExactGrant()` + `hasExactDeny()` + `hasExactLabel()`',
    '  all matching) before it returns early, so once the root is labelled the propagation is never attempted again and',
    '  the children that missed it are never revisited — the same root-only short-circuit as the DACL half, on the',
    '  other half of the same call (`packages/sandbox/sandbox-windows-acl/src/acl.ts`: the guard at :386-388, the',
    '  label read at :198-204). A second report met this same half afterwards (#8421): the label written on the root',
    '  alone, the pre-existing subdirectories carrying none of it. That is why this branch is stated as a shape this',
    '  backend produces rather than as one machine\'s result.',
    '  The package README describes that label as inheritable and covering the tree, and its grant materialization as',
    '  an eager full-tree propagation. Read it as a statement about the ACE that is written, not about what the',
    '  children ended up carrying: the inheritance flag is declared on the root, the propagation to the children is',
    '  what is missing. From outside a session the repository\'s own diagnosis skill separates the two halves —',
    '  `diagnose-windows-sandbox-acl` (0.2.0 and later) prints the directory\'s owner, the caller\'s rights and',
    '  `WRITE_DAC`/`WRITE_OWNER` — the facts the DACL half turns on — and `LOW_LABEL` (`S-1-16-4096`) for this one.',
    '  TEST: does a subdirectory show the capability ACE WITHOUT a Mandatory Label line? Yes → this half.',
    '',
    'Half three — the standing grant is gone from the ROOT itself (#8409, reported 2026-09-30):',
    '  Reported as a control beside two other defects on the same install (Windows 11, NTFS) rather than as a',
    '  theory: after the workspace root\'s own security descriptor is rewritten from OUTSIDE the harness — an ACL',
    '  reset, a restored descriptor, a tool that re-applies one — every write inside the workspace is refused, the',
    '  root\'s own directory included. What is missing is the ACE the harness itself wrote, not a descendant\'s',
    '  inheritance of it:',
    '    icacls "<root>"        → no ACE for the workspace capability SID in its own DACL',
    '  The discriminator is what the SAME machine does on the other path, and the reporter measured both: the',
    '  agentless/runner invocation recovered by itself with no restart, while the desktop session did not. That',
    '  asymmetry is not one path being more careful — it is where the cache lives. The session-scoped provider',
    '  materializes the root ACE ONCE PER PROVIDER LIFETIME and keeps that root in its own in-memory map; every later',
    '  call consults the map and never reads the DACL again, so the exact-ACE check the two halves above turn on is',
    '  not even reached (`packages/sandbox/sandbox-local/src/index.ts`: the guard at :403-421, "materializes once per',
    '  workspace per server lifetime" at :359, and the standing edits it skips are called the "cross-session reuse',
    '  cache" in `packages/sandbox/sandbox-windows-acl/src/grant.ts:22-31`). The runner path used by agentless',
    '  sessions passes no session id (`windowsAclRunnerArgv()`, :365-380), so the runner owns the DACLs there and',
    '  re-applies the grant on every spawn — which really does read the DACL, and that is why that path heals and',
    '  this one does not.',
    '  RECOVERY: this is the only branch of this family a user can leave behind, and the move is the PROVIDER rather',
    '  than a command. RESTART IT — quit and reopen the desktop app, or open the workspace in a fresh one. That',
    '  empties the map, so the next provision reads the DACL, finds the ACE absent and writes it again; the reporter',
    '  measured exactly that ("restarting the desktop brings it back"). Nothing reachable from inside this session',
    '  gets there: the map is what is being consulted, and no command you can run here changes what it holds. Do not',
    '  reach for either repair above either — both are about propagating a grant to DESCENDANTS, and this branch has',
    '  lost the grant the propagation starts from.',
    '  TEST: is the workspace ROOT itself denied — no capability ACE in its own DACL? Yes → this branch.',
    '',
    'Why the natural repair is closed — this is a Windows ceiling, not a mistake in the command:',
    '  The grant the root carries is written for a capability SID, and a recursive `icacls /grant "*S-1-4-…:…" /T /C`',
    '  is refused with ERROR_NONE_MAPPED (1332): the tool cannot map that SID to a name, so a grant that needs to name',
    '  it never reaches the child. Widening the grant to a nameable account is a different grant with different',
    '  consequences, not this one restored. For the label half the same ceiling applies one layer over: re-labelling a',
    '  subtree is a SACL write, which needs the object right the merged call already needed, and a manually widened',
    '  DACL does NOT clear the failure — #8383 confirmed that adding an explicit FullControl entry for the user on a',
    '  subdirectory still left the write denied, because the refusal happens before the ACL is ever consulted.',
    '  The third branch is not closed by this ceiling and does not need to be: there is nothing to write by hand',
    '  there — the grant that went missing is the harness\'s own, and all that has to happen is for the layer holding',
    '  the map to look at the DACL again, which the restart in half three is what makes it do.',
    '',
    'What helps:',
    '  - The move that is yours, and the only one available inside the session: write new files under a directory the',
    '    harness itself created in this workspace. Those carry the grant, because their inheritance did apply — the',
    '    reporter\'s own measurement, that objects DSH created are complete here and externally created ones are not.',
    '    Treat this as a workaround and not a repair, and on the LABEL half expect even this to be unreliable: the',
    '    directories the harness creates in a fresh workspace are children of a root whose label did not propagate, so',
    '    whether any given one works is a fact about the host you have in front of you rather than something this text',
    '    can promise.',
    '  - The user\'s move, per half: for the DACL half, repair the specific object from an account that already holds',
    '    WRITE_DAC on it, by writing the ACE the root carries into the child\'s own DACL. For the label half, the',
    '    corresponding move is on the integrity label rather than the DACL, and it has to cover the tree, not one',
    '    object; it is the same class of object write, so it is not something an unelevated prompt can do either.',
    '    For the third branch there is no object to repair at all: the move is the restart named in half three.',
    '  - The route that costs no rights at all, and the honest recommendation while the halves remain unrepairable from',
    '    inside: build and run where the confinement is not the thing under test — which is a decision about what you',
    '    are doing, not a sandbox tier to reach for silently.',
    '  No repair command is printed here on purpose. This project has no Windows host to verify one on, and shipping',
    '  an unverified line would be the same defect this plugin exists to answer. The mechanism above is what is known;',
    '  the line is yours to choose.',
    '',
    'The retry you are about to be offered: the denial surface offers one retry of this exact command under a wider',
    'mode. That retry can only succeed by removing the confinement itself — it repairs nothing in the workspace, and',
    'the next session meets the same gap. Take it only if that is what you mean to buy.',
    '',
    'Do NOT retry this call unchanged: the provisioning path short-circuits on the root — on the grant AND on the',
    'label — so the object that missed the propagation is never revisited; and in the third branch the layer still',
    'being consulted is the provider\'s own map, which nothing inside this session can change.',
    '',
    'How to read this: the denial names no cause and points at no repair, so the diagnosis is delivered here instead.',
    'This is a stopgap, ' + where + '. This plugin speaks only when the mode is `workspace-write`, the host is',
    'Windows, and every path the command names lies inside the workspace — a denial anywhere else is the sandbox',
    'working as designed, and a confident wrong cause is worse than no answer.',
    'What it is NOT: this plugin does not edit an ACL, does not elevate, and does not offer `danger-full-access` as a',
    'fix.',
  ].join('\n')
}

/**
 * Why the temp-root invariant exists, and what makes it a pre-spawn refusal.
 *
 * Shared by both halves of the family — the failure advisory and the standing
 * (pre-flight) one — because it is a fact about the backend rather than about
 * the call that hit it, and because the two texts must not drift apart: a reader
 * told "your commands cannot start" in the pre-flight and something subtler here
 * would have to reconcile the two themselves.
 *
 * Everything is read off the shipped source: the assertion and its reason
 * (`sandbox-windows-acl/src/path-boundary.ts`: "every child created below it
 * would inherit the standing workspace capability"), the canonical comparison
 * (`realpathSync.native` on both operands, then `relative`), and the fact that
 * the refusal precedes any process (`sandbox-local/src/index.ts`, whose grant
 * is materialized while the runner argv is assembled). Stating that last part is
 * what stops the reader reaching for a permission fix: nothing was denied, so
 * there is nothing to grant.
 * @returns the section's lines.
 */
function tempRootMechanism(): string[] {
  return [
    'Why the rule exists — it is a capability-disjointness invariant, not a verdict on your workspace:',
    '  A `workspace-write` session is given two capabilities that must not contain one another: a STANDING',
    '  write grant on the workspace ROOT, and a REVOCABLE private temp capability under a random child',
    '  directory created beneath the temp root. The check is `assertTempRootOutsideWorkspace(workspaceRoot,',
    '  tempRoot)`, and its own comment states the reason: "every child created below it would inherit the',
    '  standing workspace capability" (`packages/sandbox/sandbox-windows-acl/src/path-boundary.ts`). A temp',
    '  root under the workspace root puts the revocable half inside the standing one, where it stops being',
    '  revocable — so the backend refuses instead of materializing it.',
    '  It compares the two directories CANONICALLY (`realpathSync.native` on both, then `path.relative`), so',
    '  containment is a filesystem fact rather than a spelling: `AppData\\Local\\Temp` under a workspace of',
    '  `C:\\Users\\<you>` is a violation however either path happens to be written.',
    '  This is not an ACL problem and no `icacls` grant fixes it: the refusal happens while the sandbox is',
    '  deciding whether it can set up its own capabilities, before any process is created.',
  ]
}

/**
 * The two environment changes that actually move the temp root.
 *
 * This section is the family's whole value, and it is written for the *user*
 * because nothing in the session can carry it out — the failure it explains took
 * command execution away. Both levers are facts about `os.tmpdir()`
 * (`GetTempPathW` reads `%TMP%`, then `%TEMP%`, then `%USERPROFILE%`) and about
 * which directory the session was opened on, and neither touches the workspace:
 * the two directories stop overlapping, which is the whole of what the invariant
 * asks for. Deliberately **not** a grant command — see {@link tempRootMechanism}
 * — and deliberately not `danger-full-access`, which is refused in
 * {@link tempRootBoundaries}.
 * @returns the section's lines.
 */
function tempRootFix(): string[] {
  return [
    'What actually moves the temp root — two ways, and the first is the least invasive:',
    '  1. Point the harness\'s temp directory outside the workspace BEFORE it starts. `os.tmpdir()` on',
    '     Windows is `GetTempPathW`, which reads `%TMP%` first, then `%TEMP%`, then `%USERPROFILE%` — so',
    '     setting `%TMP%` is enough. Create the directory first (the check resolves both paths, so it has to',
    '     exist), and set the variable in the process that LAUNCHES the harness:',
    '       cmd:         set TMP=C:\\dsh-temp        (then start the harness from that same prompt)',
    '       PowerShell:  $env:TMP = \'C:\\dsh-temp\'; <start the harness>',
    '     A variable set inside this session cannot help: setting one needs a shell, and that is the thing',
    '     that cannot start.',
    '  2. Or open the session on a workspace that is not an ancestor of the temp root — `C:\\work\\project`',
    '     rather than `C:\\Users\\<you>`. Where the workspace IS the profile directory or a drive root, the',
    '     first option is the only one left.',
    'Either way the change is in the environment rather than in the workspace: nothing is repaired and no',
    'ACL is touched — the two directories simply stop overlapping.',
  ]
}

/**
 * What the family's refusal does *not* implicate, so a reader does not reach for
 * it.
 *
 * Three mistakes are available and all three were reachable from the reports.
 * The first two are other modes: `read-only` never materializes a private temp
 * capability (and the runner leaves the ambient temp entries untouched there),
 * and `danger-full-access` does not spawn through the sandbox at all — so
 * neither ever consults the rule, and passing under the second is consistency
 * rather than a workaround. The third is the session's own reach: the file tools
 * do not spawn this runner, so they keep working, which is exactly why no
 * experiment inside the session can repair the environment.
 * @returns the section's lines.
 */
function tempRootBoundaries(): string[] {
  return [
    'Three things this does not change, so a reader does not reach for them:',
    '  - A `read-only` session is unaffected. No private temp capability is materialized in that mode, so the',
    '    assertion is never reached — the runner passes the ambient temp root straight through.',
    '  - `danger-full-access` does not hit it either, and that is consistency rather than a workaround: that',
    '    mode never spawns through the sandbox, so the rule is never consulted. Switching to it would not',
    '    move the temp root; it would remove the confinement the rule exists to protect.',
    '  - Your file read/write tools keep working, because they never spawn the sandbox runner. Only command',
    '    execution is gone — which is also why no experiment inside this session can repair it.',
  ]
}

/**
 * Build the advisory for a refusal whose cause is the temp root's position.
 *
 * Two things this text must do beyond the shared sections. It must name **which
 * of the two producers refused**, because the sentence has two of them, they fire
 * at different moments, and a fix has to satisfy both — the provider refuses
 * while the runner argv is being assembled (no child ever existed, which is why
 * the call shows no output at all), and the runner refuses again for
 * `workspace-write` before it spawns (stderr behind `windows-acl-run: `, exit
 * 127, reclassified by the seam into a `SandboxUnavailableError`). And it must
 * print **both operands the producer itself printed** rather than re-deriving
 * them, because the family's claim is a statement about that pair of paths.
 * @param failure - the recognized failure.
 * @param tool - the tool whose call was refused, when the caller knows it.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text.
 */
function tempRootAdvisory(failure: TempRootFailure, tool?: string, href?: string): string {
  const where = href === undefined
    ? `tracked upstream (discussion ${TEMP_ROOT_DISCUSSIONS})`
    : `tracked upstream: ${href}`
  const call = tool === undefined ? 'This command' : `The \`${tool}\` command`
  return [
    'Sandbox command execution is unavailable — the sandbox\'s private temp root lies inside this session\'s',
    'workspace, and it refuses to start any command until the two are disjoint.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    `${call} runs under sandbox mode \`workspace-write\`, the only mode this rule applies to, and the producer`,
    'named the two directories it compared:',
    `  workspace root: ${failure.workspaceRoot}`,
    `  temp root:      ${failure.tempRoot}`,
    'Those two values are the producer\'s own, quoted rather than recovered here, so they are the pair the',
    'executor actually tested.',
    '',
    'One sentence, two producers, and any fix has to satisfy both — the session-scoped provider asserts it while',
    'it assembles the sandbox runner\'s argv, and the runner asserts the same pair again for `workspace-write`',
    'before it spawns the confined child. Which one this was:',
    ...(failure.carrier === 'pre-spawn'
      ? [
          '  - the PROVIDER, before any child existed — which is why this call reports no subprocess output at',
          '    all: nothing ran.',
        ]
      : [
          '  - the RUNNER, whose line is written to stderr behind the `windows-acl-run: ` marker with exit 127',
          '    — the signature the seam reads as a runner failure — and therefore reaches the session as the',
          '    `Runner failure: ` detail of a `SandboxUnavailableError` rather than as a library assertion.',
        ]),
    '',
    ...tempRootMechanism(),
    '',
    ...tempRootFix(),
    '',
    ...tempRootBoundaries(),
    '',
    'Do NOT retry and do not look for a command that fixes it: every attempt fails identically, and there is no',
    'shell to run a remedy in. Use your file tools, and hand the environment change above to the user.',
    '',
    'How to read this: the assertion names neither the operand a user can move nor the lever that moves it, so',
    'the diagnosis is delivered here instead. This is a stopgap, ' + where + '. What it is NOT: this plugin',
    'changes no environment, moves no directory and widens no sandbox — the change above is the user\'s.',
  ].join('\n')
}

/**
 * Build the pre-flight report of the standing temp-root condition.
 *
 * This is the one place in this module that **predicts** where every other reads
 * what a producer wrote, and the text is shaped by that difference. It prints the
 * facts it computed — host, mode, and both directories — so the reader can audit
 * the claim, and it says plainly how the claim is falsified (a command that runs
 * at all is evidence this composition is not the one the rule governs), because
 * the session has no shell in which to test it. That is also why it is a
 * *separate* report rather than a substitute for the failure advisory: if the
 * refusal does happen, the producer's own line and the carrier it came from are
 * facts this half cannot have, and they follow.
 * @param workspaceRoot - the root the policy resolver reported for this session.
 * @param tempRoot - the temp root the executor would use (`os.tmpdir()`).
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text.
 */
export function tempRootPreflightAdvisory(workspaceRoot: string, tempRoot: string, href?: string): string {
  const where = href === undefined
    ? `tracked upstream (discussion ${TEMP_ROOT_DISCUSSIONS})`
    : `tracked upstream: ${href}`
  return [
    'Standing condition, before anything has failed: this session\'s sandbox has its private temp root inside',
    'the workspace it grants against. Three facts put it there:',
    '  host        win32 — the ACL runner is the only backend with this rule',
    '  mode        workspace-write — the only mode that materializes a private temp capability',
    `  workspace   ${workspaceRoot}`,
    `  temp root   ${tempRoot}`,
    'and the last two overlap: the temp root is that directory or a directory beneath it. Under this mode the',
    'harness refuses to start ANY process whose private temp root lies inside the workspace — not only a command',
    'that writes there, every command, `echo test` included, with no subprocess output at all. File read/write',
    'tools are unaffected: they never spawn that runner.',
    '',
    'How to read this, given that no command can be run here to check it: the two paths above are this plugin\'s',
    'own resolution of the pair the backend compares, and the rule is the backend\'s own',
    '(`assertTempRootOutsideWorkspace`, applied to `realpathSync.native` of both). That also makes the report',
    'falsifiable in one step — if a command does run in this session, this condition does not apply to your',
    'composition and this message can be ignored.',
    '',
    ...tempRootMechanism(),
    '',
    ...tempRootFix(),
    '',
    ...tempRootBoundaries(),
    '',
    'This warning is not a substitute for the refusal\'s own report: if a command is refused, a second advisory',
    'carries the producer\'s line and names which of the two carriers refused. This is a stopgap, ' + where + '.',
  ].join('\n')
}

/**
 * The upstream statement of this boundary, quoted from the backend's own README.
 *
 * It is quoted rather than paraphrased for two reasons. It is the authority for
 * the mechanism — this plugin has no Windows host and did not measure which of
 * the token's checks refuses the namespace — and its presence in the advisory is
 * what keeps the plugin honest about what it is adding: the substitutes for the
 * commands that stop working, and the two shapes that produce a wrong value with
 * no error at all. A reader told "this is documented" is better served than one
 * told a mechanism as if it were a finding.
 *
 * Source: `packages/sandbox/sandbox-windows-acl/README.md`, repeated in the same
 * package's `src/token.ts` doc comment and pinned by two arms of
 * `tests/runner.spec.ts` that assert `CIM: DENIED` under both confined modes.
 */
export const CIM_DOCUMENTED_LIMIT = 'Authenticated Users is absent from both lists — the WMI namespace security check '
  + 'fails (0x80041003), so CIM cmdlets and Get-ComputerInfo are unavailable in every confined mode, '
  + 'and the C:\\-root tree-creation escape is closed'

/**
 * The measured native substitutes, one pair per fact the reader may need.
 *
 * Every pair is the reporter's own measurement on one machine under a
 * workspace-write session (`#9272`), which is what makes this a table this
 * plugin can hand over rather than a suggestion: the failing command and the
 * working replacement were run at the same moment and both results are recorded.
 * Two entries are files what the report lists as *unaffected controls* rather than
 * replacements — `Get-Process` and `Get-Service` never went through CIM — and they
 * are carried because "which of my usual commands still work" is the question a
 * reader arrives with. The one thing the table must not do is fill a gap it did
 * not measure, so `Get-NetIPAddress` and `Get-NetAdapter` are absent from it and
 * the advisory says so out loud.
 */
export const CIM_SUBSTITUTES = [
  '  listening ports        netstat -ano                          (parse the LISTENING rows)',
  '  processes              Get-Process',
  '  services               Get-Service',
  '  free disk space        [System.IO.DriveInfo]::new(\'C\').AvailableFreeSpace',
  '  memory                 Get-Counter \'\\Memory\\Available MBytes\'',
  '  OS version             registry: HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
] as const

/**
 * Build the advisory for the CIM/WMI boundary of a restricted-token sandbox.
 *
 * Four things this text is responsible for, in the order a reader needs them:
 * identify the code and say the command was not at fault; quote upstream's own
 * sentence as the mechanism instead of presenting it as a discovery; name the two
 * shapes that produce a wrong answer with **no error at all**, because those are
 * the ones an agent will act on; and hand over the measured substitutes plus the
 * gaps, which is the part the documentation upstream does not supply.
 *
 * What it deliberately does not do: hand over a repair. No ACE closes this, no
 * elevation reaches it, and the one narrow repair a reader reaches for — read
 * access to `root/cimv2` — is a change to the token's own list, priced against
 * the escape that removing Authenticated Users from that list closes. None of
 * that is this plugin's to decide, so it says what upstream documented and what
 * nobody has measured.
 * @param failure - the recognized failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @param href - optional URL shown for the upstream threads.
 * @returns the user-role notice text.
 */
function cimWmiAdvisory(failure: CimDenialFailure, mode: SandboxModeName, href?: string): string {
  const where = href === undefined
    ? `tracked upstream (discussions ${CIM_WMI_DISCUSSIONS})`
    : `tracked upstream: ${href}`
  return [
    'CIM/WMI is unavailable in this session — every WMI query, and every cmdlet built on one, is refused.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    `The call ran under sandbox mode \`${mode}\`, where the harness starts every command through its`,
    'restricted-token runner.',
    '',
    'The command is not at fault and the query is not malformed. 0x80041003 is WBEM_E_ACCESS_DENIED, the',
    'status the WMI namespace security check returns to a token whose restricted list does not carry the',
    'SIDs that check wants. The sentence beside the code is localized — "Access denied", "拒绝访问", and so',
    'on — while the code is not, which is why the code is what identifies this.',
    '',
    'This boundary is DOCUMENTED by the harness, and here is its own statement of it:',
    '  "' + CIM_DOCUMENTED_LIMIT + '"',
    'It holds under BOTH confining modes — `read-only` carries no write SIDs, so the namespace fails either',
    'way; `danger-full-access` is not a mode this happens under, because nothing is spawned through the',
    'sandbox there at all. Passing under `danger-full-access` confirms the diagnosis and does not fix it.',
    '',
    'Do not retry this call: the environment has not changed, and the identical call is refused identically.',
    '',
    'TWO TRAPS — these return a WRONG ANSWER with NO ERROR AT ALL, which is the part that matters for an',
    'automation or an agent:',
    '  1. `-ErrorAction SilentlyContinue` (or a script that sets `$ErrorActionPreference =\'SilentlyContinue\'`)',
    '     turns every refusal on this page into an EMPTY RESULT. Measured:',
    '       (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).Count   ->  0',
    '     A caller reads that as "nothing is listening" when the query never ran. In this session, never',
    '     treat a CIM-derived empty result, zero or missing value as evidence of absence.',
    '  2. `Get-PSDrive -PSProvider FileSystem` raises no error at all and reports Used/Free as `0` for EVERY',
    '     drive, because PowerShell 5.1 fills those columns from a WMI query — while',
    '     `[System.IO.DriveInfo]::new(\'C\').AvailableFreeSpace` is correct at the same moment. Never read',
    '     free space from `Get-PSDrive` here: "0 bytes free" is a value an agent will act on.',
    '',
    'WHAT STILL WORKS — every line below was measured on the same machine, in the same session, as the',
    'refusals above:',
    ...CIM_SUBSTITUTES,
    'None of these goes through WMI, so all of them work at full fidelity under this mode.',
    '',
    'TWO COMMANDS IN THAT FAMILY HAVE NO MEASURED SUBSTITUTE, and the gap is stated rather than filled:',
    '  Get-NetIPAddress / Get-NetAdapter — the report supplies no native replacement for either, and',
    '  `ipconfig /all` is a plausible candidate that was NOT measured under a confining mode. Do not hand',
    '  a substitute over as verified when it is not: say the query is unavailable in this session and, if',
    '  the fact is needed, ask the user for it.',
    '',
    'WHAT IS NOT THE FIX:',
    '  - No `icacls` line and no elevation. This refusal names no path and is not about a file, so no ACE',
    '    closes it — the rights the property tools speak in do not reach a namespace.',
    '  - `danger-full-access` is not a fix: it removes the sandbox, and with it the reason this session was',
    '    confined. It only confirms the diagnosis.',
    '  - The narrow repair a reader naturally proposes — admitting read-only access to the `root/cimv2`',
    '    namespace — is a change to the restricted token\'s own lists rather than to anything on disk, and it',
    '    is the other side of a trade the backend made deliberately: the same absence of Authenticated Users',
    '    from those lists is listed as what closes the C:\\-root tree-creation escape. No one has measured',
    '    which of the token\'s checks refuses the namespace, so this advisory cannot price a narrower',
    '    allowance, and it does not pretend to.',
    '',
    'Honest boundary — this is recognized only on Windows, only under a confining mode, and only from a',
    'shell call\'s own settled value (a cmdlet error is a nonzero exit, which the shipped shell tools report',
    'without marking the result an error, so it never reaches `error.message`). The read is the captured',
    'stderr of that value, not assembled text, which is what keeps a command that merely prints a quoted',
    'copy of such a record from being read as this. The family covers the CIM/WMI face of the restricted',
    'token only: the same boundary also refuses outbound network, TLS and some process creation, and those',
    'are separate diagnoses with their own remedies.',
    '',
    'This is a stopgap, ' + where + '. What it is NOT: this plugin neither grants anything nor widens the',
    'sandbox — the substitutes above are yours to run, and your file tools are unaffected.',
  ].join('\n')
}

/**
 * Build the pre-dispatch denial for the optional fail-fast half.
 *
 * The blocking half is deliberately **ACL-only**, and this function's parameter
 * type is where that is enforced. The two mode-gated families get an advisory
 * and nothing else, for a reason that is about the remedy rather than about the
 * failure:
 * the ACL remedy is a command the user can run *while the session continues*,
 * so refusing further identical calls cannot make the session unfinishable —
 * spending the budget always lets the call through, and a repaired environment
 * is discovered by exactly that. The PTY remedy is a preset swap, which happens
 * between sessions, and the native-init remedy is a launch fix on the user's
 * side (the one in-session part — rewriting an MSYS2 command — the model does by
 * calling a different tool invocation, which has a different call key and is
 * therefore never the call being refused); refusing calls could only pad a
 * session that is already unable to do the thing being refused.
 * @param failure - the recognized failure.
 * @param observed - how many provisioning failures this agent has produced.
 * @param denial - this denial's 1-based ordinal.
 * @param maxDenials - the denial budget.
 * @returns the corrective text the model receives in place of a tool result.
 */
export function denialText(
  failure: ProvisioningFailure,
  observed: number,
  denial: number,
  maxDenials: number,
): string {
  const suffix = maxDenials - denial
  return [
    `Blocked by sandbox-grant-advisor: this exact call has already failed ${String(observed)} times with the`,
    'same workspace-provisioning error, and the environment has not changed since:',
    `  ${failureLine(failure)}`,
    '',
    'Retrying cannot succeed — the sandbox cannot start a command until the directory grant applies.',
    'Stop, and either apply the fix or hand the problem to the user:',
    failure.path === undefined ? '' : `  icacls "${failure.path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,
    '',
    suffix > 0
      ? `This is automatic block ${String(denial)} of ${String(maxDenials)}; after that the call is allowed again.`
      : `This is automatic block ${String(denial)} of ${String(maxDenials)} — the last one; further identical calls are allowed again.`,
  ].filter(line => line !== '').join('\n')
}
