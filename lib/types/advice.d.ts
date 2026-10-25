/**
 * What the model — and through it the user — is told about a recognized
 * environment failure, and what is deliberately withheld.
 *
 * The text is assembled here as pure functions so every sentence can be pinned
 * by a test, one family at a time. The seven families are shaped by the same
 * question — is this the sandbox's doing, and what can the reader do about it —
 * and they answer it differently:
 *
 * - **The ACL failure** (`acl-provisioning`) *is* fixable by the caller, so its
 *   advice names the right the caller is missing and gives the command.
 *   The reported failures are `ERROR_ACCESS_DENIED` from a *merged* DACL + SACL
 *   write; the missing right is `WRITE_OWNER` on the directory — an object right
 *   the caller can grant itself with `icacls`, unelevated. It is **not**
 *   `SeSecurityPrivilege`, the token privilege the reports naturally reach for,
 *   and the section 0.27.0 added says why an elevated run that works does not
 *   confirm it: on a UAC-filtered Administrators token, elevation ALSO enables the
 *   deny-only `Administrators` group, whose inherited `(F)` entry carries
 *   `WRITE_OWNER` — two variables move at once, and `whoami /priv` shows neither
 *   of them separately.
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
 *   out of the tree and leave it on objects other projects build from. It ships
 *   no removal command of its **own** — the maintainers' own diagnosis skill
 *   reports the label and leaves it, removing one needs `WRITE_OWNER`, and this
 *   project has no Windows host on which to verify a line — and hands over the
 *   procedure a reporter measured end to end instead (`#7846`), attributed with
 *   its boundaries, together with the direction that was never priced: the label
 *   was evaluated as *loosening* the tree, and what that report measured is the
 *   user's own Medium-integrity toolchain losing it. It also states that
 *   `read-only` writes no label, so a label found after such a session is
 *   inheritance from an earlier `workspace-write` period rather than evidence
 *   about the session in front of the reader.
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
 *   Since `0.18.0` that comparison carries a second axis and a second candidate.
 *   The axis is the one the mode switch cannot see: `#9336` filed its own
 *   counterexample — from the packaged desktop's chain every interpreter died
 *   under `workspace-write` and every one reached exit 0 under `read-only`, while
 *   the same runner under the same argv, started from an ordinary console-bearing
 *   chain, returned 0 in **both** modes. So the failing combination is
 *   *console-less host* **and** *confining token*, and a separating switch proves
 *   the sandbox without naming the mechanism inside it; the check therefore runs
 *   in two steps, and `#9238` supplies the second one as a measured matrix rather
 *   than as a build-specific suspicion. The candidate is the token's **default
 *   DACL**, which `setTokenDefaultDaclGrant` extends with a full-access ACE naming
 *   `tempWriteSid ?? writeSid ?? Everyone` — which makes `workspace-write` the only
 *   mode whose default DACL names a synthetic identity at all. What the switch
 *   costs is stated too, because the report asked for it: under `read-only`
 *   PowerShell enters ConstrainedLanguage, so a command that "works" there may no
 *   longer run.
 *   Since `0.23.0` that candidate is a **measurement**, and the measurement moved
 *   the input one step: a user held the token recipe, the grants, the stdio and the
 *   command fixed and rewrote only the SID that single call names — a Node
 *   module-loading hook over the shipped runner, so the ACE stayed where it was and
 *   only its trustee changed. Naming `Everyone` recovers, naming the capability SID
 *   fails, and the arm that decides it is the one that names **both**: the
 *   capability ACE left in place with `Everyone` beside it also recovers. So the
 *   failing input is not "an ACE with a synthetic name was merged", and it is not
 *   one property either: `0.24.0` carries the **conjunction of three** the same
 *   reporter measured next, because each part alone predicts rows that die. The SID
 *   the merged ACE names must be an **enabled group** of the restricted token (the
 *   ambient `Administrators` entry is `SE_GROUP_USE_FOR_DENY_ONLY` — `0x10`, with no
 *   `0x4` — and dies even on the arm that carries it in the list); that SID must
 *   **also be carried in the restricting list** (`S-1-5-4` and `S-1-5-11` are
 *   enabled groups of this token and die when named alone, and the same arm recovers
 *   the moment the SID is added to the list); and that list must **still carry the
 *   logon SID and `Everyone`** (three removal arms die, including one whose named
 *   trustee is enabled *and* in the list). The one-part form this file carried until
 *   `0.24.0` — "the absence of a trustee the restricted token itself holds" — is
 *   therefore necessary and not sufficient, and `Everyone` is not the only trustee
 *   measured recovering.
 *   The second part reopens an argument this file used to set a write-restricted
 *   reading aside: it said that if the failing check were write-restricted,
 *   `INTERACTIVE` would fail too, and it runs. It runs only *once the same SID is in
 *   the restricting list*, and dies when it is not — the correspondence the reporter
 *   draws between their first two parts and the pass-2 predicate, which they mark as
 *   their reading rather than a measurement. Nobody has traced `AccessCheck` on this
 *   path; what is measured is the conjunction, and the withdrawn argument is not
 *   replaced by a traced one.
 *   Two further arms bound it: removing the write SIDs from the restricting
 *   list does **not** recover (a different input, which is why this is not producer
 *   3 again), and the console axis is a **conjunction** with this one — on the
 *   machine that was measured the failure is *(no console) AND (no SID named by the
 *   merged ACE satisfying those three parts)*, and either alone recovers. The
 *   keep-alive property the removal arms test is now **measured** rather than
 *   untested: naming `Everyone` while removing the logon SID dies, naming `Everyone`
 *   while removing `Everyone` from the list dies, and naming `S-1-5-4` — enabled and
 *   in the list — while removing `Everyone` dies as well. The measurement dumps
 *   `TokenDefaultDacl` from inside the confined child too: the merge EXTENDS the
 *   default DACL (three ambient trustees survive it), so the "merge dropped the
 *   ambient half" reading does not apply there. It was measured on ONE build and the
 *   build axis is **not** measured to be the same, so the text names
 *   `(mode × host × build)` and leaves the build open; and the warning not to delete
 *   that ACE survives intact, because the arm that works is the one that keeps it.
 *   Since `0.23.0` producer 2 carries a second, narrower isolation as well: the same
 *   runner recipe with only the hosting process IMAGE varied — the packaged
 *   Electron binary against a real `node.exe` — which is the arm that says the
 *   token's own origin, and nothing about the outer runner's launch, is what decides
 *   it. Where that image is chosen is named for the reader: the runner argv is built
 *   as `[process.execPath, runner.js]` and its own docstring and test both assert the
 *   prefix is `node`, an invariant the packaged build falsifies because it is the one
 *   form where `process.execPath` is not a Node binary.
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
 *   Since `0.20.0` this file carried a **rule** for this producer's input, derived in `#9467` by
 *   changing only the third entry of the restricting list inside one host: a confined child dies
 *   exactly when the list carries a SID that is not an enabled group of the token being
 *   restricted — 16 of 16 arms, a count whose comment is no longer in that thread. `0.24.0`
 *   **withdraws** the rule: its own reporter retracted it in that thread before this advisory
 *   published it, and the retraction is the measurement that separates the parts — the two
 *   inputs are a conjunction rather than a sole condition. Two rows already in this issue's arm
 *   set falsify the sentence instead of trimming it: `read-only` with the synthetic non-group
 *   SID *inside the list* starts the child, and `workspace-write` with the capability SID inside
 *   the list *and* named by the merged ACE dies. List membership is therefore neither sufficient
 *   nor necessary, and the input is the trustee of the ACE the default-DACL call merges — the
 *   conjunction of three above.
 *   What does not rest on the retracted rule is where that call's SID comes from: the write SIDs
 *   are DERIVED FROM A PATH — `S-1-4-x-y`, and its temp sibling `S-1-4-x-y-1`
 *   (`sandbox-windows-acl/src/workspace-sid.ts`) — and a path-derived SID can never be an
 *   enabled group of a token, so the shipped `workspace-write` call names a trustee that fails
 *   part (a) whenever a temp directory exists. That is what the `baseline` arm sees, and making
 *   it recover means naming an enabled group in that call — a change to the backend rather than
 *   a knob a user has.
 *   Two reports in that wave are carried as SCOPE, and only as scope. `#9463` shows the same
 *   backend STALLING before any child is spawned at all (no `approval/request`, no process) —
 *   a third shape of one backend rather than this family. `#9471` shows a child that DOES
 *   start and then dies loading a library at runtime, carrying a message (`E_ACCESSDENIED
 *   0x80070005`, exit `0x80008082`) instead of a bare status; that shape is deliberately NOT
 *   claimed, because it is message-bearing and its code is not this family's — the same
 *   fail-closed rule that keeps `0xC0000409` and `0xC0000135` out of the classifier.
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
 * - **The self-withholding refusal** (`acl-aggregate-failure`, #9460) is the
 *   seventh and the only family whose *line* is the finding rather than a clue to
 *   it. The producer throws an `AggregateError` when the fail-closed cleanup fails
 *   with the grant that had just failed, and Node's message comes from the
 *   argument the thrower passed rather than from `errors`, so the Win32 code, the
 *   API name and the directory are absent by construction. Its advisory therefore
 *   names **no cause**: it says which half refused, gives the candidates in the
 *   order a probe can separate them, and puts the one that needs no ACL at all —
 *   the per-path lock both the grant and its cleanup take, whose file is created
 *   before any descriptor is read — first, because it is also the only candidate a
 *   directory listing can rule out. It ships no grant aimed at the **failed**
 *   directory, on purpose: the ACL family can hand over one because its line names
 *   the directory, and nothing here does, so what is handed over is the probe that
 *   names it. What 0.27.0 adds is the one object this family can name without that
 *   line — the temp root, which is not the object that failed but the parent every
 *   per-session object is created under, and where a fix has to be inheritable to
 *   outlive the session that needed it. It says so together with the trap in the
 *   tool it otherwise recommends: the repair skill's ACE is explicit
 *   (`FileSystemAccessRule`'s three-argument constructor, `InheritanceFlags.None`),
 *   so aiming the skill at the temp root repairs the temp root alone. This is
 *   also the family whose `layer` discriminator exists because the producer has
 *   two sentences and the difference is real — the workspace half keeps its
 *   standing ACE and frees only SIDs, the temp half revokes and removes.
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
import type { FailureFamily, ProvisioningFailure, RecognizedFailure } from './signature.js';
import type { SandboxModeName } from './mode.js';
/**
 * The upstream threads the ACL advisory is a stopgap for.
 *
 * The first twelve report the provisioning failure itself (the merged DACL +
 * label write being refused). `#8312` and `#8314` report the other end of the
 * same backend — what its grant leaves behind once it *succeeds* — which the
 * advisory states because it is the fact a reader needs at the moment it hands
 * them the command that applies that grant. The last four arrived later and
 * are all inside the same advisory: `#8426` is the independent, unelevated
 * measurement of the missing `WRITE_OWNER` the diagnosis above had only ever
 * argued for, and `#8412` is a second instance of what the grant leaves behind
 * (the standing Low label reaching programs the user launches themselves).
 * `#8409` is the same backend once more and belongs to both lists: one of its
 * three defects is the provisioning failure this family explains, and another
 * is the fourth family's third branch. `#7846` is the same subject from the
 * user's side — the standing entries outliving the session on a project
 * directory, the recovery measured by hand, and the direction the design never
 * priced.
 */
export declare const ACL_DISCUSSIONS = "#7538 / #7622 / #7646 / #7720 / #7750 / #7735 / #7771 / #7804 / #7816 / #8232 / #8272 / #8275 / #8312 / #8314 / #8426 / #8412 / #8409 / #7846";
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
export declare const PTY_DISCUSSIONS = "#7638 / #8322 / #9170";
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
 *
 * The last two threads are the console axis measured from outside, and they are
 * why the third producer's check is now two steps rather than one. `#9238` did
 * what no earlier report had: a launcher that varies only the runner's CONSOLE
 * TOPOLOGY, six arms on one machine, with `DETACHED_PROCESS` the single failing
 * one — so "does the runner own a console" stopped being a suspicion about a
 * build and became a check anyone can run. It also states this family's CI
 * blind spot plainly: the repository's own Windows checks run inside a
 * console-bearing chain, which is the one configuration that works. `#9336`
 * then filed the combination a bare mode switch mis-attributes — the packaged
 * desktop's chain kills every interpreter under `workspace-write` and starts
 * them all under `read-only`, while the same runner under the same argv returns
 * 0 in BOTH modes from a console-bearing chain. That report is also the source
 * of the `read-only` cost the advisory now states (ConstrainedLanguage) and of
 * the default-DACL candidate — which `0.23.0` promotes out of candidacy, because a
 * user measured it and the measurement named which half of it was the input.
 * `0.24.0` narrows that half once more, on the same reporter's next arms: the
 * statement is a conjunction of three parts (an enabled group of the token, carried
 * in the restricting list as well, and a list that still carries the logon SID and
 * `Everyone`), and the restricting-list rule this plugin announced in `0.20.0` is
 * withdrawn — its reporter retracted it in `#9467` before the publish, and the
 * comment that derived it is no longer there.
 * `0.25.0` moves the instruments those arms were run with into the repository's
 * `tools/` — the module-loading hook over the shipped runner, the default-DACL
 * dump, the bootstrap that can allocate a console first, and the
 * materialiser that lets a plain `node.exe` host the runner — and points the
 * advisory at them instead of at a comment inside a thread, so an arm can be
 * re-run by a reader who was not in the conversation. The scripts are their
 * author's, copied unedited with a provenance header naming the comment each came
 * from, and `tools/README.md` says what each arm is for and which number it
 * reproduces; the count of packages the materialiser copies is read out of that
 * script's own output rather than written down, because the one figure that
 * circulated for it was written without tallying the closure.
 * `0.26.0` carries three corrections the reporter of this issue supplied, each one a
 * statement previously published in a form the measurements do not support. The ambient
 * default-DACL dump's fourth entry carries `0xA0000000` rather than the `0x10000000`
 * that the two trustees beside it carry — the mask belongs to the entry, and setting
 * both masks beside "all three ambient" is how the logon entry came to be read as
 * sharing theirs. The three-part statement is credited to this issue and to discussion
 * `#8497`, where the default-DACL candidate was filed; the thread number it used to
 * carry belongs to a different producer's isolation and holds none of its rows, so a
 * reader sent there finds nothing the sentence rests on. And the
 * `SetTokenInformation(TokenGroups)` refusal returns with the scope its measurement has
 * — `87` whatever the buffer holds, in the unrestricted process and the `read-only`
 * confinement alike, on one build, reason not traced — because a refusal that a
 * byte-identical write-back also meets is not a statement about the capability SID,
 * which is the reading the sentence it rode beside had given it. `tools/hook.mjs` is
 * replaced in the same release: the file shipped in `0.25.0` switches on eight arms,
 * while the version its author ran has twenty, so twelve arms his own later rows report
 * had no file here that could run them.
 *
 * `#9626` is the fourth wave's second isolation of producer 2, and it is narrower
 * than the ones before it: the token recipe, the grants, the stdio shapes, the
 * workspace and the command all held fixed, with only the process IMAGE hosting the
 * runner varied — the packaged Electron binary against a real `node.exe`. It is the
 * arm that says the token's own origin decides, and it names the place the product
 * still assumes otherwise: the runner argv is built as `[process.execPath,
 * runner.js]`, whose docstring promises "the prefix stays `[node, runner, ...]`" and
 * whose own test asserts it holds in product — which the packaged build falsifies,
 * being the one form where `process.execPath` is not a Node binary. A sibling report
 * of the same shape (a second author, twenty seconds later) is not tracked
 * separately.
 *
 * `#9467` and `#9463` are the third wave, filed on Windows 10 19044 and Windows 11
 * 26200 on one day. `#9467` is the thread whose restricting-list rule this advisory
 * carried from `0.20.0` and **withdraws** in `0.24.0`: the reporter retracted it there
 * before the publish, and its two inputs are a conjunction rather than a sole
 * condition — the rule's own figures (16 of 16 arms, and the `SetTokenInformation` /
 * error 87 refusal beside it) come from a comment that is no longer in the thread.
 * What the wave does settle is independent of the rule: this family had only ever
 * been measured on 26200, and the same structure reproduces on 19044, so the build
 * number is not the variable. `#9463` is the
 * scope half — the same backend stalling before any child is spawned at all (no
 * `approval/request`, no process), which is neither this family nor any of the
 * others, and is carried so a reader knows the shape exists without this advisory
 * claiming it. `#9471`'s message-bearing runtime-load denial is named as scope for
 * the same reason and is likewise not classified.
 */
export declare const NATIVE_INIT_DISCUSSIONS = "#7876 / #7877 / #8193 / #8208 / #8313 / #8336 / #8334 / #8990 / #8991 / #9186 / #9238 / #9336 / #9463 / #9467 / #9626 / #8721";
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
 *
 * `#9559` is the second branch's SECOND shape, and it is the report that makes
 * that branch wider than the label alone: on an existing project tree every
 * write below the root is denied while a write AT the root succeeds, and the
 * child carries **neither** half — no capability ACE and no Mandatory Label
 * line — so the propagation did not reach it at all rather than reaching it
 * with one of the two. That is the shape the DACL half's own explanation does
 * not cover, and it is why a single `icacls <root>\<sub>` read now separates
 * the branch's two shapes before any repair is attempted. The report also
 * supplies the measurement that explains the temporary relief a DACL write
 * gives: rewriting a child's DACL makes Windows recompute its inherited ACEs,
 * so the capability ACE appears in it — while the integrity label does not, and
 * the write stays denied. Its suggestion for a fix is recorded as a suggestion
 * and not as a measurement (this project has no Windows host), which is why no
 * line from it is printed.
 */
export declare const WORKSPACE_DENIAL_DISCUSSIONS = "#423 / #8383 / #8421 / #8409 / #9559";
/**
 * The upstream thread the temp-root advisory is a stopgap for.
 *
 * One report, because the shape is one sentence out of one invariant: `#9175`
 * has the failure, the platform, and — this is what makes it usable without a
 * Windows host — the two paths the assertion printed, which is exactly the pair
 * the pre-flight half has to reproduce to be worth anything.
 */
export declare const TEMP_ROOT_DISCUSSIONS = "#9175";
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
export declare const CIM_WMI_DISCUSSIONS = "#1157 / #4163 / #997 / #1847 / #9272";
/**
 * The upstream thread the aggregate-refusal advisory is a stopgap for.
 *
 * One report, `#9460`, and it is enough to carry the whole family because the
 * reporter measured the part that cannot be reasoned about from a source tree:
 * the two repairs that do not work (`takeown /A`, `icacls /reset /T`), the manual
 * ACL operation that DOES work when run by hand, and — the datum the advisory's
 * probe is built on — that a temp root redirected to an ASCII path afterwards
 * stayed completely empty, which is only possible if the running process never
 * resolved temp to it. The thread also demonstrates why the sentence needs a
 * family of its own: both the reporter and the first readers of the source
 * reached for mechanisms (a capability probe, an ACL refusal) that the backend
 * does not have or cannot be shown to have.
 */
export declare const ACL_AGGREGATE_DISCUSSIONS = "#9460";
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
export declare const DISCUSSIONS_OF: Record<FailureFamily, string>;
/** The documented prerequisite, quoted from the backend's README. */
export declare const PREREQUISITE = "granted directories must be caller-owned and grant `WRITE_OWNER`";
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
export declare const PROFILE_PATCH = "$DSH_HOME/profiles/<profile>/cordis.patch.yml";
/** The machine-wide patch layer, for a change that should hold in every profile. */
export declare const GLOBAL_PATCH = "$DSH_HOME/cordis.patch.yml";
/** The row id the shipped `minimal` preset is declared under. */
export declare const MINIMAL_PRESET_ROW = "preset-minimal";
/** The one-shot shell tool the `standard` preset mounts on Windows. */
export declare const ONE_SHOT_SHELL = "@deepseek-ai/dsh-tool-pwsh";
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
export declare const NOT_FIXES: readonly ["takeown /F \"<dir>\" /R /D Y", "icacls \"<dir>\" /reset /T /C"];
/** What the caller knows about the failing call, beyond the failure text. */
export interface AdvisoryContext {
    /** URL quoted in place of the discussions list; optional. */
    readonly href?: string;
    /** The tool whose call failed, quoted back so the advice is about that call. */
    readonly tool?: string;
    /**
     * The sandbox mode the failing call ran under. Required by the
     * `pty-startup` family — the whole diagnosis is the mode — and by the
     * `native-init` family, whose gate is the same question; unused by the ACL
     * family. The `cim-wmi-denial` family requires it too, and for a third
     * reason: the condition holds under BOTH confining modes, so the text names
     * the mode to keep the two halves of that claim auditable rather than
     * asserting a mode the caller never resolved.
     */
    readonly mode?: SandboxModeName;
    /**
     * Whether this process is an Electron binary (`process.versions.electron`).
     * Used by the `native-init` family to report — not to assume — which of its
     * producers this host can have; absent means "ask the live process", so a
     * caller cannot accidentally state a fact it did not measure.
     */
    readonly electronHost?: boolean;
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
export declare function advisoryText(failure: RecognizedFailure, context?: AdvisoryContext): string;
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
export declare function tempRootPreflightAdvisory(workspaceRoot: string, tempRoot: string, href?: string): string;
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
export declare const CIM_DOCUMENTED_LIMIT: string;
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
export declare const CIM_SUBSTITUTES: readonly ["  listening ports        netstat -ano                          (parse the LISTENING rows)", "  processes              Get-Process", "  services               Get-Service", "  free disk space        [System.IO.DriveInfo]::new('C').AvailableFreeSpace", "  memory                 Get-Counter '\\Memory\\Available MBytes'", "  OS version             registry: HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"];
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
export declare function denialText(failure: ProvisioningFailure, observed: number, denial: number, maxDenials: number): string;
