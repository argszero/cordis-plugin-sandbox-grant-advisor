# @argszero/cordis-plugin-sandbox-grant-advisor

Turns a sandbox environment failure that has **no path forward** into a
diagnosis the model — and the user reading the transcript — can act on. Six
signatures, one mechanism:

```
SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)   # Windows workspace ACL
PTY shell exited during startup                             # persistent shell × confining mode
[exit code: -1073741502]  (0xC0000142)                      # a confined child that never started
[exit code: 1]  sandbox: { mode: "workspace-write", denied: true }
                                                            # denied INSIDE the workspace
Windows ACL temp root must be outside the workspace: …      # the private temp root is inside the workspace
0x80041003 (WBEM_E_ACCESS_DENIED) in the command's stderr   # CIM/WMI refused to the restricted token
```

**This plugin is the stopgap for "the error does not name the outstanding
condition".** It repairs nothing: no ACL is written, no privilege is requested,
nothing is elevated, no environment variable is set for another process, no
preset is installed and no mode is changed.

## The six failures it recognizes

The first two are recognized on the public **`tools/post-execute`** waterfall
(`@deepseek-ai/dsh-tools`) from the failure text. That seam is the one that has
all three of what a diagnosis needs: the failure
(providers propagate their error unchanged and the tool pipeline settles it as an
`isError` result), an agent identity to attribute it to (`exec.agent`), and a
channel that speaks to the model in the same step (`PostToolDecision`'s
`additionalContexts`, which the agent loop turns into a durable user-role message
— `packages/core/agent-loop/src/tool-calls.ts`). The third, fourth and sixth are
recognized at the **same seam** from the canonical value of a result the pipeline
calls a *success*, for reasons §3, §4 and §6 give in full. The fifth is read from
a thrown error's own message like the second, and is the one family the plugin
also reports **before** anything fails, for reasons §5 gives in full.

That seam, not `ctx.sandbox.confine`: `confine(argv, policy, signal)` sees the
confinement failure too, but its signature carries no agent, so a wrapper could
detect the condition and never deliver a word about it to the session that is
stuck.

### 1. Workspace provisioning — the Windows ACL failure (`acl-provisioning`)

Twelve reports describe this exact line: [discussion #7538], [discussion #7622],
[discussion #7646], [discussion #7720], [discussion #7750], [discussion #7735],
[discussion #7771], [discussion #7804], [discussion #7816], [discussion #8232],
[discussion #8272] and [discussion #8275] (three of them — [#7750], [#7735],
[#8232] — on data-volume workspaces, where *no* ACE names the caller at all: the
inherited `Authenticated Users: Modify` is the whole of their access). In each one
every sandboxed command fails the same way, before it runs, and the error names
neither the missing right nor a remedy.

Two further reports — [discussion #8312] and [discussion #8314] — and a third,
[discussion #8412], describe the other end of the same backend: what its grant
leaves behind *after* it applies.
The advisory states that too (see [What the grant leaves behind](#what-the-grant-leaves-behind-added-in-0100)),
because the advisory is the thing handing over the command that applies the grant.

`#8232` contributes two facts about the *shape* of the failure rather than its
cause, and both are in the advisory now. One is that the failure belongs to the
**workspace, not the command**: there a `Get-Date` failed exactly like anything
that writes, because the grant is materialized before the command runs at all. The
other is the **scope of the repair**: the `(OI)(CI)(WO)` line covers *this*
directory and its children, so a second workspace root on the same volume is a
sibling rather than a child and needs the same line once more — which is why that
reporter saw a second workspace fail on a machine whose first one was already
repaired. The report also reaches the same root cause on its own (the merged write
wanting `WRITE_OWNER`, which owner-implicit rights do not carry), matching the
backend's documented prerequisite.

`#8272` and `#8275` add neither a cause nor a remedy — both land on the same
missing right — but each one closes a reading the diagnosis leaves open, and both
are in the advisory since 0.9.0.

`#8272` reached the same conclusion by a **better probe than the one above**: it
set a Low integrity level on a directory it owned, unelevated
(`icacls <dir> /setintegritylevel "(OI)(CI)Low"`), and was refused. That isolates
the label half of the merged call, which is the half that needs `WRITE_OWNER`, and
it does so without asking anyone to interpret a merged failure. It is quoted here
as evidence and deliberately **not** offered as a check: where the caller holds Full
control the same command *succeeds*, and then the label — and its inheritance — is
already written. A diagnostic that writes when it succeeds is not a diagnostic this
plugin hands out; the two read-only checks above are.

The report then went looking for the backend's own repair
(`diagnose-windows-sandbox-acl`) on a `0.1.7-rc.2` install and found it missing,
which it read as the package having dropped the skill from its `files` glob. It has
not: measured on the published tarballs (2026-09-29), `0.1.7-rc.2` names the skill
**zero times** in either README, ships no `assets/` directory at all, and carries no
file containing the registration symbol — while `0.2.0-rc.2` ships
`assets/diagnose-windows-sandbox-acl/{SKILL.md,scripts/diagnose-windows-sandbox-acl.ps1}`
and names it three times per README. The skill is **new in `0.2.0`**; a `0.1.7`
install that found the name was reading a `0.2.0`-era document. So the reach that
works is the upgrade, not a packaging fix, and the advisory says so — item 4 below.

`#8275` is the other direction: it had the skill, and the skill's own remedy
(Full control) *worked*, after which it noticed that the Low label the successful
apply writes is what regresses the two side effects it documents. Its proposal is to
**degrade provisioning to DACL-only** when the label is the half being refused,
which reads as though the label were one of two independent layers. It is not, and
the advisory answers that with the mechanism rather than with a refusal — item 6
below.

`#7720` is worth reading for where the failure lands: the grant is materialized
at sandbox **initialization**, so this is not one refused operation but *every*
shell tool at once — the reporter could not run `netstat` or even `icacls` to
diagnose the error they were staring at (on `0.1.5-rc.3` the same directory
worked, because confinement was skipped silently rather than failing closed).
They also report the two remedies that look right and are not
(`takeown /F <dir> /R /D Y`, `icacls <dir> /reset /T /C`), which is why the
advisory names them with the reason each fails instead of leaving the reader to
discover it.

The Windows backend provisions a workspace by writing the directory's DACL and
its mandatory-integrity label in **one** `SetNamedSecurityInfoW` call
(`packages/sandbox/sandbox-windows-acl/src/acl.ts`):

```ts
if (applyResult !== abi.ERROR_SUCCESS) throwWin32(api, 'SetNamedSecurityInfoW', applyResult, `${label}(${path})`)
```

Two consequences follow from that one line:

1. **The label lives in the SACL, and its half is what gets refused.** The
   owner's implicit rights cover only `READ_CONTROL` and `WRITE_DAC`, so the
   combined apply additionally needs **`WRITE_OWNER` on the directory** — an
   *object right*, which a Full-control directory (the normal workspace case)
   has and a `mkdir`-created one inheriting "Authenticated Users: Modify"
   (`0x1301bf`) does not. This is the backend's own documented prerequisite
   ("granted directories must be caller-owned and grant `WRITE_OWNER`").
2. **It is not `SeSecurityPrivilege`, and elevation is the wrong lever.** That
   is the token-privilege form of the same idea, and it is the hypothesis the
   reports naturally reach for — `whoami /priv` cannot tell the two apart,
   because `WRITE_OWNER` is an object right and never appears in that table.
   Granting `WRITE_OWNER` on the workspace root needs **no** elevation. `#7735`
   settles the gate with an isolation table on one machine and one unprivileged
   account: the label write succeeds with Full control *or with Take-ownership
   alone*, and fails with `ChangePermissions`, `ReadPermissions` or `Modify`
   alone — so the gate is `WRITE_OWNER` and nothing else.
3. **The remedy is the narrowest form of that right.** The advisory recommends
   `icacls <dir> /grant "<user>:(OI)(CI)(WO)"` — `WO` *is* `WRITE_OWNER`, i.e.
   literally the right the documented prerequisite names, so the one-liner grants
   nothing the harness did not ask for — and offers Full control second, as the
   same line with `F` in place of `(WO)`. Both assume the caller owns the
   directory: owner-implicit rights cover the DACL half of the merged write.
4. **The version boundary is stated, because the error cannot carry it.** Up to
   `0.1.6-alpha.x` the backend's `SetNamedSecurityInfoW` wrote the DACL only
   (flag 4) and a Modify-only workspace provisioned fine; the mandatory label —
   and with it the SACL, flag 20 — arrives in `0.1.7-alpha.1`. So the same string
   on an older line belongs to a different cause space, and the natural reach
   (downgrade to the build that "worked") is refused with its reason: the label is
   what confines deletes to the workspace, and reverting it reintroduces the
   escape it closed. `#7750` asks for exactly this and explains why it is a
   usability regression traded for a security fix.

   There is a **second boundary on that same line**, and `#8272` is what made it
   worth stating: the backend's own repair, `diagnose-windows-sandbox-acl`, is not
   part of `0.1.7-*` at all — it arrives with the **`0.2.0`** line, where the
   package starts shipping it under `assets/`. A reader who found the skill named
   in a README while running `0.1.7-rc.2` was reading a `0.2.0`-era document, not a
   package that dropped something: that release's own README names it zero times and
   no file in its tree carries the registration symbol. So the useful reach is the
   upgrade, and the unhelpful one — repairing a `files` glob in a release that has
   no such directory — is not offered.
5. **The repair is per-directory, and the report is what established that.** `#8232`
   applied the `(WO)` line, watched the workspace start working, and then hit the
   same error on a *second* workspace root on the same volume. `(OI)(CI)` carries
   the ACE into *children* of the directory that received it and nowhere else, so a
   sibling root is untouched by it. One line per workspace root is therefore the
   correct shape of the remedy, not one line per machine — and the advisory says so,
   because the natural reading of "it worked" is "it is fixed".
6. **A "weaker grant" is a mechanism this backend cannot express, not a policy it
   declines** (added in 0.9.0, from `#8275`). The label is what makes the apply a
   SACL write, so declining it looks like dropping the expensive half — but there is
   no DACL-only path to fall back to: the label rides the **same**
   `SetNamedSecurityInfoW` as the grant (`acl.ts`: the flags are
   `DACL_SECURITY_INFORMATION` alone only when the label edit is `keep`, and
   `grantWrite`'s apply branch always passes `apply`), and the idempotence fast path
   requires the exact label among its three conditions. And dropping the label alone
   would not leave a working workspace: the confined token is itself lowered to Low
   before any child starts (`token.ts`'s `restrictTokenIntegrity`, whose own comment
   calls Low "the level the mandatory labels `grantWrite` applies are matched
   against"), so the directory's Low label is what lets that Low child write there at
   all under no-write-up. A DACL-only mode that keeps the token lowering yields a
   workspace the sandbox can start a command in and the command then cannot write to;
   one that drops the token lowering too — which is what `#8275`'s own appendix
   records a community patch having to do — gives up half the confinement rather than
   one of two independent layers. The advisory says this instead of a bare "no",
   because a reader told only "no" reaches for the workaround without knowing what
   else it has to change.
7. **The missing right was confirmed from outside, unelevated** (added in 0.14.0,
   from `#8426`). Everything above is argued from the backend's source; `#8426`
   measured it with none of that. On a directory whose ACL named the account only
   through the inherited `Authenticated Users:(M)` entry, asking that directory
   for a Low mandatory-integrity label — the label half alone, no DACL write, so
   it isolates the right the merged call wants — was **refused**, and the
   identical operation **succeeded** the moment the same account granted itself
   `(OI)(CI)F`, whose mask carries `WRITE_OWNER`, and was reversible from there
   (back to Medium works just as well). No elevation anywhere in it. That makes the
   claim in item 2 a measurement rather than a reading: the missing right is an
   object right on the **directory**, not `SeRelabelPrivilege` and not a token
   privilege. The same report then repaired two real trees the same way — object
   right first, integrity label second, 9521 and 5592 objects, no failures — an
   order that cannot be swapped, since the second step is the one that needs what
   the first supplies, and it is the order the advisory's own remedy already
   follows. The probe itself is quoted here and **not** in the advisory, for the
   reason item 6 of the `#8272` paragraph above gives: a label write is not a
   check, because where the caller already holds Full control it succeeds and
   writes the label. The advisory hands over only the two read-only checks.

The grant is materialized lazily, on the first confined call, and **nothing is
cached when it throws** — so the same failure repeats per command (850 calls
across 39 sessions in #7622; 52,588 output tokens with no output in #7538),
which is why the loop cannot separate it from ordinary command noise.

On the first recognized failure, the result is enriched with:

```
Sandbox provisioning failed — no sandboxed command can run in this workspace until its ACL applies.

What was reported:
  SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)

Why it is refused while the directory looks writable: that call is a MERGED write ...
  ... the label half additionally needs WRITE_OWNER on the directory. ...

A version boundary worth knowing before reaching for an older build: the label half is new to this package.
Up to `0.1.6-alpha.x` the backend touched the DACL only (flag 4) ... `0.1.7-alpha.1` is where the mandatory
label — and with it the SACL, flag 20 — arrives. ... Rolling back is not the fix either: the label is what
confines deletes to the workspace, and reverting it reintroduces the escape it closed.

The other boundary on that last line: the `diagnose-windows-sandbox-acl` skill is not part of `0.1.7-*` at all
— it arrives with `0.2.0`, where the backend starts shipping it under `assets/`. The reach that works is the
upgrade, not a packaging fix.

Confirm the cause (unelevated) — `icacls` is a normal user command:
  icacls "D:\ws"

Ownership decides which of the two commands below can work, so read it first — PowerShell 5.1 or later:
  (Get-Acl "D:\ws").Owner      # compare with: whoami

IF YOU OWN THE DIRECTORY — the usual workspace, on a data volume as much as on C::
  one unelevated line, then run the command again:
  PowerShell: icacls "D:\ws" /grant "$env:USERNAME:(OI)(CI)(WO)"
  cmd:        icacls "D:\ws" /grant "%USERNAME%:(OI)(CI)(WO)"
  ... Full control works just as well — the same line with `F` in place of `(WO)`

IF YOU DO NOT OWN IT — a directory an installer or another account created, e.g. owner
`BUILTIN\Administrators`:
  the line above cannot run at all. Changing a DACL takes WRITE_DAC, which you hold neither as owner nor
  through any ACE, so `icacls /grant` is refused with `Access is denied` — for the very command that would
  fix it. ... Run the grant once from an account that already holds both — that is, from an ELEVATED prompt:
  icacls "D:\ws" /grant "<your-account>:(OI)(CI)F"
  ... or take ownership first (also elevated; it wants SeTakeOwnership), after which the unelevated `(WO)`
  line above applies: icacls "D:\ws" /setowner "<your-account>"
  ... or sidestep the ACL: create the workspace under `%USERPROFILE%`.

What will NOT fix it on its own — both look like the right move, and both were tried and reported:
  takeown /F "D:\ws" /R /D Y
    makes you the owner, and ownership's implicit rights are READ_CONTROL and WRITE_DAC only — so it
    supplies the DACL half and still not WRITE_OWNER, the right this call needs.
  icacls "D:\ws" /reset /T /C
    restores inheritance, and inheritance is what supplied the Modify-only ACE above. Where it strips the last
    entry naming you, the directory ends up in exactly the state the diagnosis above describes — its only access
    the inherited `Authenticated Users:(M)` (#8314 measured that follow-on failure).

What the grant leaves behind, once it applies — worth knowing before you run the command above, because the
backend does not take it back:
  The three entries are STANDING, deliberately, and nothing revokes them. ... They outlive the session and the
  harness exiting (`sandbox-windows-acl/src/grant.ts`, `src/index.ts`).
  The Low integrity label is INHERITABLE (`(OI|CI)`) and it lives in the SACL — which is why the `icacls /reset`
  above does not take it off: that command rebuilds the DACL. Windows starts a process at the minimum of the
  user's and the program's integrity, so anything started from a tree the harness has written to runs at LOW
  integrity, and none of the symptoms names DSH (#8312 collects them): ... (#7709), ... (#8175), ... (#7735).
  It can also leave the workspace. An NTFS hard link is a SECOND NAME for one file object, so both names share
  one security descriptor — and a pnpm workspace is largely hard links (`node_modules` pointing into a
  content-addressed store on the same volume). ... `vite build` unable to remove its own temp file, `pnpm
  install` unable to replace a hook (#8314 measured the whole chain). ...
  It is also why the label is not simply removable here: ... This advisory hands over no removal command: the
  maintainers' own skill does not, and an unverified one would be the defect this plugin exists to answer.
None of this makes the command above the wrong move — without it, nothing sandboxed runs in this workspace. It
is what the harness does to a directory it has been pointed at, and it is worth knowing before rather than
discovering it as a broken build in some other project later.

One thing to know before asking for a weaker grant, because that is the next idea after this diagnosis —
and it is not a smaller version of the same grant:
  The label rides the SAME `SetNamedSecurityInfoW` as the DACL, so there is no DACL-only path to fall back
  to — it would have to be built. And dropping the label alone would not leave a working workspace: the
  backend lowers the confined token to Low before any child starts, and the directory's Low label is what
  lets that Low child write here at all. Declining the label usefully means declining the token's Low level
  with it, which gives up half the confinement rather than one of two independent layers.
```

**Why the remedy forks** (added in 0.5.0). The same error covers two different
rights situations, and one command cannot serve both. Where the caller **owns**
the directory, the owner's implicit `WRITE_DAC` satisfies the DACL half of the
merged write, `WRITE_OWNER` is the single missing right, and the unelevated
`icacls /grant` that supplies it can itself run — [#7750] measured exactly that
fix working. Where the caller **does not own** it ([#7771]: owner
`BUILTIN\Administrators`, held deny-only for that token), `WRITE_DAC` is missing
too, so the very same command is refused before it does anything, and `(WO)`
alone would not be enough even if it went through. The failure text is identical
in both, so the classifier cannot pick a branch — the advisory hands over the
**ownership check** as the selector instead of guessing, which is also the
actionable-guidance half of what [#7771] asked for. Until 0.5.0 a single
unconditional one-liner was printed, with a sentence noting it assumed
ownership; that would have sent the second environment to a command that is
denied — the same defect this plugin exists to answer.

#### What the grant leaves behind (added in 0.10.0)

[Discussion #8312] and [discussion #8314] report the other half of this backend,
and the advisory now states it — before the reader runs the command it is being
handed, because that command is what makes the backend's grant apply:

- **The three entries are standing, by design, and nothing revokes them.** The
  workspace grant is a *reuse cache*: the backend's dispose path revokes the
  revocable (temp) grants and leaves the workspace edits, and its fail-closed
  cleanup says the same in plainer words — standing ACEs "are NOT revoked — they
  are the intended end state (the reuse cache), not an error artifact"
  (`src/grant.ts`, `src/index.ts`). They outlive the session and the harness
  exiting. ([#8312] arrived at this from the README's own description of the
  cache; the source is quoted in the advisory.)
- **The Low integrity label is inheritable, and it lives in the SACL.** That is
  why `icacls /reset` — already listed as a non-fix for a different reason — does
  not remove it: the command rebuilds the DACL. Windows starts a process at
  `min(user, image)` integrity, so anything started from a tree the harness has
  written to runs at Low integrity, and none of the symptoms points at DSH:
  an Electron/Chromium app exiting `0x80000003` with no output ([#7709]),
  msbuild / dotnet / npm refusing or warning about the files as if they came from
  the Internet when no `Zone.Identifier` exists ([#8175]), a double-clicked
  `.exe` / `.cmd` reporting "publisher could not be verified" ([#7735]).
- **It can leave the workspace.** An NTFS hard link is a second name for one
  file object, so both names share one security descriptor — and a pnpm workspace
  is largely hard links (`node_modules` pointing into a content-addressed store
  on the same volume). The inheritable label therefore lands on the *store's*
  objects and stays there, after which every project building from that store
  gets executables that start at Low integrity and failures that name the build
  tool ([#8314] measured the whole chain: `vite build` unable to remove its own
  temp file, `pnpm install` unable to replace a hook). The backend's own suite
  pins the reach as a known boundary — *"a workspace hard link lets the grant
  reach an external file object"* (`tests/runner.spec.ts`) — and its README calls
  refusing multiply-linked files unviable for ordinary pnpm installs, which
  leaves the out-of-tree reach open rather than unknown.
- **No removal command is shipped.** The maintainers' own
  `diagnose-windows-sandbox-acl` skill *reports* `LOW_LABEL` and by design does
  not remove it, and removing an integrity label needs `WRITE_OWNER` — the same
  right this whole failure is about. This project has no Windows host to verify a
  line on, so shipping one would be exactly the defect the rest of this module
  exists to answer; the section says where it stops instead.

The section is emitted for **every** ACL class, like the version boundary and for
the same reason: it is a fact about the package's grant, and that grant is the
remedy the advisory hands over in all three classes. It also closes with what the
fact does *not* mean — the command is still the right move, because without it
nothing sandboxed runs at all.

**What is deliberately *not* shipped**: `icacls ... /grant "<user>:(OI)(CI)(WD,WO)"`,
the two needed rights named explicitly. It is the tighter form and it is
plausibly correct syntax, but this project has no Windows host to run it on, and
shipping an unverified command in a remedy whose whole point is that it works is
the failure mode being fixed. `F` (verified by [#7804]'s reporter) and
`/setowner` (named by both reports) are given instead.

### 2. Persistent shell startup (`pty-startup`)

[Discussion #7638] reports the second shape: with the **`minimal` preset** on
Windows, and under a **confining** sandbox mode (`workspace-write` / `read-only`,
not `danger-full-access`), **every** shell call dies instantly with

```
PTY shell exited during startup
```

The terminal backend spawns the shell through the sandbox
(`packages/terminal/terminal-bash/src/index.ts`; the throw is in
`src/session.ts` and `src/index.ts`, both on the same `waitReason ===
'session_exit'` branch), and there the pseudo-console cannot be created at all,
so the child exits before its first prompt. Retrying never helps; the message
points at no cause.

The reporter's own three-arm control makes the sandbox mode the discriminator:
minimal × confining fails, minimal × `danger-full-access` succeeds, `standard`
(one-shot shell) × confining succeeds. That is why the advisory is only ever
built with the **resolved** mode the failing call actually ran under — from
`ctx.sandboxPolicy.resolve({ session })`, the same resolver the terminal layer
calls before spawning, with the same session.

**Inside a confining mode, the host binary decides** (added in 0.10.0).
[Discussion #8322] ran the control one level deeper — same runner, same ConPTY,
every arm — and separated what the mode alone does not: with the runner hosted by
a plain console-subsystem `node.exe`, the confined shell starts and its prompt and
shell-integration marks are correct; with the runner hosted by the packaged
desktop's GUI-subsystem Electron executable, the child dies **silently** — zero
bytes on stdout *and* stderr, and the non-interactive arm exits 0 with everything
it printed lost. It is the same rule the `0xC0000142` family states for its own
case: under the restricted token a console can be **inherited but not created**,
so the binary that owns one (or owns none) is what the arms turn on. That is also
why the same version behaves differently depending on how it was started: the
desktop app fails where the Web UI launched from a terminal — whose
`process.execPath` is a real `node.exe` — is reported working under the same
confining mode ([#8313], whose sibling report is the `0xC0000142` shape of the
same host difference). The advisory therefore names the host alongside the mode,
says the outcome is **deterministic per (session mode × host)** rather than
intermittent, and adds that the mode which counts is the one the **session
records**, not the one the environment now holds — a session that recorded the
confining mode keeps failing after the app is restarted with another mode in its
environment, while switching it inside the session takes effect at once.

**[Discussion #9170]** (added in 0.16.0) supplies that host split from the user's
own side: on one machine the identical confined command works under `dsh web`
and fails under the packaged `dsh desktop`, with the mode and the command held
fixed — the comparison the three most recent `0xC0000142` reports could not make,
because those machines only ever ran one app. It also corrects the conclusion
that comparison invites: switching the session to `read-only` is **not** a
reliable way out, because it goes through the same restricted runner started
from the same host binary — it changes what is *granted*, not who spawns the
child — and the one report where `read-only` succeeded while `workspace-write`
died was driven through the sandbox API from a real `node` host, not from the
packaged desktop app. Worth one try, not worth counting on; a host that owns a
console remains the first move.

The advisory that follows is addressed to **two different readers**:

```
Persistent shell failed to start — command execution is unavailable in this session, and retrying cannot fix it.

What was reported:
  PTY shell exited during startup

The `bash` tool is a PERSISTENT PTY session (a shell that stays alive between calls), and this session's sandbox mode is
`workspace-write` — not `danger-full-access`. A confining mode spawns the shell through the sandbox, and there the
terminal backend cannot create the pseudo-console at all, so the child exits before its first prompt. ...

Which sessions fail inside that combination is not chance — it is deterministic per (session mode × the host
binary carrying the sandbox runner) ... Measured against the desktop build with the same runner and the same
ConPTY in every arm (#8322):
  - runner hosted by a plain console-subsystem `node.exe` → the confined shell starts ...;
  - runner hosted by the packaged desktop's GUI-subsystem Electron executable ... → the child dies silently ...
The rule behind both this and the `0xC0000142` family ... is the one stated there for its own case: under the
restricted token a console can be INHERITED but not CREATED ... And the mode that decides is the one the SESSION
records, not the one the environment now holds ...

Do NOT retry, and do not look for a command that fixes it: every attempt will fail identically, and there is no
shell to run a command in. Use your file read/write tools instead, and hand the choice below to the user.

What unblocks the session — the user's decision, not the model's:
  1. switch the agent preset to `standard`, whose shell tool is a one-shot subprocess (no PTY) and works
     under the sandbox; or
  2. override the `preset-minimal` row in your profile patch — `$DSH_HOME/profiles/<profile>/cordis.patch.yml`, or
     `$DSH_HOME/cordis.patch.yml` for every profile — replacing its `persistent-shell` group with
     `@deepseek-ai/dsh-tool-pwsh` (a one-shot subprocess, no PTY); the patch layer is yours, so an upgrade
     will not overwrite it; or
  3. run the session from a host that owns a console instead of the packaged desktop app — the Web UI started
     from a terminal (`process.execPath` is a real `node.exe` there) was reported working under the same
     confining mode and the same version (#8313); or
  4. run the session with `danger-full-access`, which drops the very confinement the sandbox exists to give.
     Prefer 1 to 3.
```

The model's instruction is to **stop** — not to run a command (there is no shell
to run it in) and not to call a fallback shell tool (`minimal` mounts exactly
**one** platform-selected persistent shell and **no** one-shot shell, by design:
`.agents/notes/implemented/simplification/2026-09-03-minimal-profiles-persistent-shell-only.md`).
Naming a tool the failing composition does not mount would be a wrong remedy,
which is the main risk this family's text is written to avoid.

The remedy is a **patch layer**, not a directory. The pre-declarative
`$DSH_HOME/.agent-presets/<id>/` preset folder is a plausible-looking trap: it
still reads as the natural place to put a preset, and nothing in the harness
reads it any more (`@deepseek-ai/dsh-agent-preset-registry`: the registry
"neither scans directories nor accepts preset paths"). Preset changes are
`@deepseek-ai/dsh-agent-preset` rows — an `insert` for a new one, a patch keyed
by row id (`preset-minimal`) for a change to a shipped one. A test arm asserts
the advisory never names the dead directory.

### 3. A confined child that never started (`native-init`)

Twelve reports of one exit code: [`#7876`] and [`#8193`] (the packaged desktop
app), [`#8313`] (the same version and the same mode run as the desktop app versus
the Web UI launched from a terminal, which works), [`#8334`] (the same code with
the authorization side attached: the grant **succeeded** and every confined child
still died), [`#7877`] (MSYS2 / Git
Bash), [`#8990`] and [`#8991`] (the same code on two more Windows builds, with no
dependence on the PowerShell version or the install layout, and — for those
machines — no way to tell which producer it was) and [`#9186`], which isolated it
to a single input — and [`#8208`], which found the mechanism the console cases
share, [`#8336`], which measured the creation flags that mechanism turns on,
[`#9238`], which isolated the mechanism's *input* by varying only the runner's
console topology, and [`#9336`], which filed the combination a bare mode switch
mis-attributes and the two costs that go with it. All are `0xC0000142`
`STATUS_DLL_INIT_FAILED` — the Windows
loader terminated the process while it was initializing its native images, i.e.
**before the program's entry point**. A command that ran and then failed exits
with its own status and prints its own output; this one produced neither.

| what was run | what came out | exit code |
| --- | --- | --- |
| `cmd.exe /c "echo cmd-ok"` | `cmd-ok` | 0 |
| `pwsh -NoLogo -NoProfile -Command "Write-Output pwsh-ok"` | `pwsh-ok` | 0 |
| `D:\Git\bin\bash.exe -c "echo bash-ok"` | `couldn't create signal pipe, Win32 error 5` | `-1073741502` |

Three producers have been measured under a confining mode:

1. **An MSYS2 / Git-Bash program** ([`#7877`]). The restricted token's runtime
   cannot create the pipe it uses for signals, so bash aborts in the loader
   phase, while `cmd.exe` and `pwsh` run fine in the same workspace under the
   same mode. The plugin's own composition has no way around this: `tool-bash`
   and `bash-sandbox` are `disabled` on win32
   (`@deepseek-ai/dsh-base/cordis.patch.yml`), so the combination is likely
   never covered upstream. The **one conversion a model can make itself** is to
   write the same work as a PowerShell or `cmd` command.
2. **The packaged desktop app's sandbox runner** ([`#8193`], [`#8208`]).
   `dsh-sandbox-local` launches the runner as `[process.execPath, entry]`, and
   in the packaged build `process.execPath` is the Electron executable. **The
   mechanism is the runner's console, not its token** ([`#8208`]): the confined
   child inherits a console from the runner, and a runner that owns none leaves
   the child to ask for one of its own — which a restricted token may not have.
   The capture is three lines: `conhost.exe` is created *by the restricted child*,
   exits `0xC0000022 STATUS_ACCESS_DENIED`, and the child then dies with
   `0xC0000142`. Two console-less configurations are measured, and they share that
   mechanism: **(a)** the host binary is a GUI-subsystem program, which never owns
   a console — the packaged desktop, where every confined command dies this way
   ([`#8193`]); **(b)** the host binary is a real console-subsystem `node.exe` and
   the runner was still spawned without a console, because `DETACHED_PROCESS` was
   set — `spawnSync(node, [runner, …], { detached: true })` returns `0xC0000142`
   where the identical call without that flag returns `0` ([`#8208`]). Shape (b) is
   the one worth handing over, because it needs no desktop and no particular
   machine. **What is *not* the discriminator is the token**: [`#8208`] compared
   `whoami /groups` and `/priv` from children of a working node host and of the
   failing Electron host and found them identical, and a low-integrity `cmd.exe`
   runs fine on that machine. The plugin reports whether *this* process is an
   Electron binary (`process.versions.electron`) as a measured fact rather than
   assuming it.

   **Since `0.18.0` this axis has its own measurement, and it is the reason the
   third producer's check is two steps rather than one.** [`#9238`] built a ~90-line
   Win32 launcher that varies **only the runner's console topology**, held
   everything else — machine, workspace, temp directory, mode, argv, restricted
   token — constant, and ran six arms on one machine: `DETACHED_PROCESS` (no
   console at all) died with `0xC0000142` and zero output, while `CREATE_NO_WINDOW`
   (Windows allocates the runner an invisible console), `CREATE_NEW_CONSOLE`,
   inheriting an existing console, and a hidden-console `wscript → cmd` carrier all
   reached the program with its stdout intact, and the same `DETACHED_PROCESS`
   launch **without** the restricted token was fine. So the console is not an
   inference from two host binaries any more: it is a variable one launcher can
   turn on and off, which is what makes "does the runner own a console" a check
   rather than a suspicion about a build. The same report states this family's CI
   blind spot in one sentence and it is worth quoting in the plugin's own words:
   the repository's Windows checks run in a **console-bearing** chain — the one
   configuration the matrix shows working — so a green check there cannot falsify
   this producer. The clarification [`#9238`] adds to the backend's recording is
   the distinction the flag vocabulary below turns on: `CREATE_NO_WINDOW` on the
   **restricted child** is fatal, while `CREATE_NO_WINDOW` on the **runner** is the
   fix, because Windows then gives the runner an invisible console for the child to
   inherit.

   **`0.7.x` named two shapes and explained them with the wrong mechanism, and
   `0.8.0` withdraws one of the shapes outright.** The withdrawn shape is "the
   runner does not start at all, because `ELECTRON_RUN_AS_NODE=1` is missing": the
   desktop sets that variable on its own host child
   (`apps/desktop/src/host-process.ts` → `desktopNodeEnvironment()`,
   `apps/desktop/src/node-environment.ts:15`), so nothing on the runner path can
   fail to start for want of it — and [`#8208`] measured the variable present in
   *both* hosts, including the one that works. The token story goes with it, for
   the same measurement. A cause the advisory shipped twice earns its sentence
   when it is retracted, and test arms keep both retractions in place.

   **The remedy is a real node host — with one condition riding on it.** [`#8193`]
   measured the way out: hosted on the desktop's own bundled standalone node
   (`resources/runtime/primary-runtime/dependencies/node/bin/node.exe`, v24.21.0)
   the *same* confined `pwsh.exe` / `cmd.exe` spawns succeed (exit 81 / 82), with
   workspace, temp directory, mode, SIDs, target and runner `sha256` all held
   constant. [`#8208`] reproduced it (exit `0`, the command's own stdout intact)
   on the same runtime installed for workspace dependencies
   (`%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe`,
   present once `load_workspace_dependencies` has run) and with `windowsHide` both
   set and unset. **The condition is that the runner must be spawned *with* a
   console** — not with `DETACHED_PROCESS` — because a real host alone is not
   enough when that flag is set ([`#8208`]): the host binary supplies the console
   and the spawn flag is what can take it away again. Where no real host can be
   put in front of the runner, the same effect fits inside it: `AllocConsole`
   before the restricted spawn, with the three standard handles restored
   afterwards, in `dsh-win32-process`'s `createRestrictedProcess` — the funnel
   every restricted child goes through. [`#8208`] measured `cmd /c exit` and
   `pwsh -c "Write-Output …"` both reaching `0` with stdout intact under that
   change, and as a no-op on a runner that already owns a console; it costs a
   `user32` binding and one console host per runner process. `danger-full-access`
   is demoted to what it actually is — a way to **confirm** the diagnosis, not a
   fix, and on this platform one that silently removes the sandbox from every
   shell call. The reporter's own reason is the one the plugin repeats: *"the
   practical effect is that Windows Desktop users must escalate to full access for
   all shell work, which silently removes the sandbox on that platform"*, and they
   asked explicitly that this not be "fixed" with `--disable-sandbox` /
   `--disable-gpu-sandbox` — those disable Chromium's renderer sandbox, a
   different layer from the DSH file policy. The advisory also warns off the
   opposite-looking move: unsetting `ELECTRON_RUN_AS_NODE` does not help, because
   the desktop's runner **is** that Electron binary and dropping the variable
   would take `runner.js` down with it — the interaction [`#8193`] records with
   [`#8174`], where a fix that tombstones the variable in the shared child
   environment would take the ACL runner down with it, so the two changes have to
   land together.

   **What the flag vocabulary actually is.** The backend's own source records one
   inherent boundary: *"console isolation is unavailable — children share the host
   console (`CREATE_NO_WINDOW` / `CREATE_NEW_CONSOLE` children die with
   `STATUS_DLL_INIT_FAILED` under the restriction)"*
   (`packages/sandbox/sandbox-windows-acl/README.md:119`), echoed at
   `packages/subprocess/win32-process/src/process.ts:454`. [`#8208`] **explains**
   that recording instead of repeating it, and the explanation is the invariant
   the two shapes share: **in a restricted token a console can be inherited but
   not created.** The creation flags actually passed are three sets and none of
   them is `CREATE_NO_WINDOW` — `0` on the piped path (`process.ts:243`, the path a
   shell call takes), `CREATE_SUSPENDED` on the inherited-job path
   (`process.ts:542`) and `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT` on the
   ordinary path (`process.ts:567`, i.e. `0x404`); `CREATE_NO_WINDOW`
   (`0x08000000`) is **not a constant anywhere in that source**. Those flags are
   fatal under a console-less runner and harmless under one that owns a console —
   so **there** the console decides. `0.7.x` wrote the two-set version of that
   list and called the flags "a necessary ingredient ... the host process image is
   what turns it fatal"; both halves were wrong, and `0.8.0` replaces them.

   **`0.11.0` and earlier concluded too much from those three sets** — "it is the
   console and not the flag list that decides" — and [`#8336`] measured the case
   that falsifies it: with a console-owning host, a restricted token and the Low
   integrity level, varying only the creation flags, `CREATE_NO_WINDOW` and
   `CREATE_NEW_CONSOLE` both died with `0xC0000142`, while `0`, `DETACHED_PROCESS`
   and `CREATE_NEW_PROCESS_GROUP` reached the program. So the console decides
   **whether a flag that merely shares the inherited console is fatal**, and a
   flag that forces the child to create one of its own is fatal regardless. The
   pair inside that matrix is what makes it a rule rather than a list of forbidden
   flags: the same `CREATE_NO_WINDOW` on an *unrestricted* token reached the
   program, and `STARTF_USESHOWWINDOW` with `SW_HIDE` — how the harness hides a
   window without isolating a console — was harmless on the restricted one.
   `0.12.0` replaces the withdrawn sentence with the rule and that matrix.

   **The `windowsHide` suspicion, answered.** It is the first thing a search turns
   up for this failure, and it points at the wrong component: the flag appears
   once on the *ordinary* subprocess path
   (`packages/subprocess/subprocess-local/src/spawn.ts:472`,
   `windowsHide: platform === 'win32'`), which starts the runner rather than the
   confined child, and the restricted spawn defines no `CREATE_NO_WINDOW` constant
   at all. It is **not** set in `dsh-jobs` — a search there finds nothing, and
   every `windowsHide` in the tree sits on a host-side or ordinary spawn. And
   where it *is* set, [`#8208`] measured it both ways on a host that works: with
   and without `windowsHide`, the confined `pwsh` reached exit `0` with its own
   stdout intact. The reason is the rule again — a windowless console is still a
   console, and that is what the child inherits; what decides is whether the host
   owns a console **object**, not whether it owns a window.

   **One arm was applied, measured, and rejected.** Putting `DETACHED_PROCESS` on
   the *restricted child* removes its console request and does stop the crash —
   but `pwsh` then exits `0` with **zero bytes on stdout and stderr**, while
   `cmd.exe` keeps its output ([`#8208`]). That trades a loud failure for a silent
   one on the interpreter most likely to be used, so the advisory names it as a
   non-remedy instead of offering it; the runner-side remedies keep the output.

3. **A capability SID inside the restricted token's own restricting list**
   ([`#9186`], added in 0.16.0). The two producers above are properties of the
   *program* and of the *host*; this one is a property of the **token**, and that
   is why it is the hardest to see: the reporter drove the sandbox API directly,
   with the runner hosted by a real `node` binary and the DACLs left untouched,
   and held everything fixed but one input — the restricting list the restricted
   token is built from. With the `workspace-write` list — `[logon SID, EVERYONE]`
   plus **one capability SID** — *every* program died this way, `whoami.exe` and
   `cmd.exe` as well as `pwsh`; with the `read-only` list, which carries no
   capability SID, the same program started normally in both stdio shapes (piped
   and inherited). The capability SIDs are derived per workspace and per private
   temp directory and join the list only under `workspace-write`
   (`sandbox-windows-acl/src/token.ts`: `createRestrictedToken()` is verbatim
   `read-only ? [logonSid, world] : [logonSid, world, ...writeSids]`), so
   `read-only` carries none **by design**.

   **The check is a mode switch, and since `0.18.0` it is the FIRST of two steps
   rather than the whole answer.** Hold the command and the tool fixed and change
   only the mode: if `read-only` starts the command that `workspace-write` kills,
   the sandbox is the difference. That is one setting rather than a debugging
   session — and it is the answer to the one thing `0xC0000142` cannot say, because
   **the same code runs in both directions**: the restricted-token layer's own
   docstring records that a token built *without* the logon-SID + EVERYONE
   keep-alive pair also dies in early DLL init with exactly this status (and `pwsh`
   earlier still, in its CNG path, as `0xE0434352`). Too few entries in the
   restricting list and too many land on the same `0xC0000142`, so the code cannot
   name its own direction; only a comparison can.

   **What the switch cannot do is name the mechanism inside the sandbox, and
   [`#9336`] is the report that proves it.** That reporter ran the *packaged
   desktop's* chain and the *ordinary* `explorer → cmd → pwsh` chain against the
   same runner with the same argv: from the desktop chain `cmd`, PowerShell 7 and
   PowerShell 5.1 all died under `workspace-write` and all three reached exit `0`
   under `read-only`, while the console-bearing chain returned `0` in **both**
   modes (and still enforced the sandbox — an out-of-workspace write exited `1` with
   no file created). That is exactly what producer 3 looks like from the outside,
   and it is producer 2: **the failing combination is a console-less host AND a
   confining token**, and a mode switch made inside a console-less host separates
   for both reasons at once. So the second step is "does the runner own a console",
   it is answered by producer 2's own arm (start the runner from a
   `DETACHED_PROCESS` chain — no desktop, no particular machine), and this producer
   is the answer only when the runner **did** own one — the shape [`#9186`]
   measured, with a real node host and the DACLs untouched.

   **A second candidate rides the same token, and it is carried as a candidate.**
   [`#9336`] reasoned that adding SIDs to a restricting list only *widens* write
   access, so the more suspicious input is the ACE the backend merges into the
   token's **default DACL**. That reading is right about the asymmetry and
   unmeasured about the effect: `setTokenDefaultDaclGrant`
   (`sandbox-windows-acl/src/token.ts`) merges one full-access restricting-SID ACE
   into the **existing** default DACL — `SetEntriesInAclW`, `GRANT_ACCESS`,
   `FILE_ALL_ACCESS`, extended rather than replaced — and the SID it names is
   `tempWriteSid ?? writeSid ?? Everyone` (`src/index.ts:304`): the private temp
   SID under `workspace-write` when a temp directory exists, otherwise the
   workspace SID (a sha256 of the canonical workspace path, `S-1-4-x-y`), and
   Everybody under `read-only`. So `workspace-write` is the only mode whose default
   DACL names a synthetic identity at all — a real second difference between the
   modes — and nobody has measured that ACE. The merge is also load-bearing in a way
   that forbids the obvious experiment: every new object the confined process
   creates takes its DACL from there, so an ACE removed to test the theory takes
   every piped grandchild spawn down with it (`spawn EPERM`). The advisory names it,
   says it is unmeasured, and says not to delete it.

   **And the switch costs something, which the backend's README states.** Under
   `read-only` PowerShell cannot create its AppLocker probe files in temp and
   conservatively starts in **ConstrainedLanguage**, where `Add-Type`, non-core
   .NET static calls, COM and reflection fail — [`#9336`] adds
   `[System.IO.File]::*` and `Get-CimInstance` to that list — while the shipped
   `workspace-write` path lets the probe complete and keeps FullLanguage unless the
   machine carries a host-wide WDAC/AppLocker policy
   (`packages/sandbox/sandbox-windows-acl/README.md:192`). A command that "works"
   after the switch may therefore be a command that no longer runs at all: the
   switch is a diagnostic, not a repair. One thing this producer is **not**:
   `.NET`. Pure-native programs die here identically, which retires the
   "self-contained .NET runtime" cause the earlier reports converged on — that is
   the report's own control arm, not an assertion of ours.

**Why this family is read from a successful result.** The producer never marks
it an error, and that is a fact about upstream rather than a choice here:
`RUNNER_FAILURE_RULES['windows-acl']` admits exactly one code —
`[{ allowedExitCodes: [127], fatalSignatures: ['windows-acl-run: '] }]`
(`packages/sandbox/sandbox-local/src/index.ts`) — and `classifyRunnerFailure`
skips any other code before it looks at stderr
(`packages/sandbox/sandbox/src/diagnostics.ts`), so `0xC0000142` is never a
runner failure and `SandboxUnavailableError` is never thrown. The renderer then
reports it the way it reports any finished command — *"Non-zero exits are
reported, not errored … only infrastructure failures (spawn errors, aborts)
surface as isError results"* (`packages/shell/tool-pwsh/src/render.ts`) — as
`[exit code: …]`. **Every version of this plugin before 0.6.0 read error results
only and was structurally blind to it**, which is exactly why the model retries a
command that can never start.

The read is `ToolExecutionSuccess.value` — the tool's own canonical output,
documented as *"Execution-local canonical value; deliberately omitted from
durable events"* **and not carried on failure results at all** — so the code
arrives structurally rather than as a line of text. A command that prints
`[exit code: -1073741502]` is not this failure, and neither is a value some other
tool happens to build with an `exitCode` field: the classifier requires the
shipped shell projection (`kind: 'foreground'` plus an integer `exitCode`).

The advisory that follows:

```
Sandboxed command never started — the process died while its native libraries were loading.

What was reported:
  [exit code: -1073741502]        (0xC0000142 STATUS_DLL_INIT_FAILED)
The call ran under sandbox mode `workspace-write`, where the harness starts every command through its
restricted-token runner.

0xC0000142 is STATUS_DLL_INIT_FAILED: ... this is BEFORE the program's entry point. ...
Nothing in the code says "sandbox" by itself; what makes the sandbox a candidate is the mode above ...

Three producers have been measured under a confining Windows mode. Check which one this is:
  1. An MSYS2 / Git-Bash program ... (#7877)
     If that is what could not start: write the same work as a PowerShell or `cmd` command instead
  2. The packaged desktop application's sandbox runner ... (#8193, #8208)
     This process is NOT an Electron binary (`process.versions.electron` is unset), so producer 2 does not apply here.
  3. A capability SID inside the restricted token's own restricting list ... (#9186)
     CHECK, in TWO STEPS — the first alone does not settle it. Step 1: ... change only the MODE ...
     Step 2: establish whether the runner OWNS A CONSOLE, because producer 2 fails the very same switch ...

     A second candidate sits on the SAME token and is NOT the restricting list: the token's DEFAULT DACL ...
     it is a CANDIDATE and not an answer — nobody has measured it ...

Do not retry this call: the environment has not changed, and the identical call produces the identical code.

A `read-only` session is NOT a substitute for a working `workspace-write` one — the mode switch above is a
diagnostic, not a repair. ... under `read-only`, PowerShell ... starts in ConstrainedLanguage ...

Honest boundary — 0xC0000142 has producers this list does not have: a program that cannot load one of
its own DLLs dies this way too, and the sandbox backend's own source records that a child started with
a hidden console window does as well ... This is not a claim that the sandbox caused the failure.
```

**What it does not claim.** The code is a loader status, and the loader reports
the same status for causes that have nothing to do with the sandbox (a missing
DLL, a program's own initialization failure, the hidden-console child the
backend's own source avoids `CREATE_NO_WINDOW` for). So the advisory diagnoses
the **class** ("the process never reached its entry point") and enumerates the
producers measured under a confining mode, each with the check that separates
them — one of which the reader answers (what program failed to start) and one of
which the plugin answers (is this host the packaged desktop binary). Where a
producer has more than one measured shape, the advisory names all of them and
records which check separates them outside the session, rather than asserting
the single shape that happened to be measured first. It never
offers `danger-full-access` as a fix and never suggests a sandbox setting be
relaxed.

### 4. Denied inside the workspace (`workspace-denial`, added in 0.11.0; the branches it forks into in 0.13.0 and 0.14.0)

[#423] is one report and its own follow-up, and it is the **other end of the
backend §1 is about**. There the workspace grant could not be applied at all and
every command died before it ran; here the grant **was** applied — on the
workspace root, once — and part of the tree still refuses writes, forever. The
report's shape: under `workspace-write` on Windows, a command writing into a
subdirectory that was created or **moved in from outside** the session (an
installer, an editor, another harness running under its own account) is denied,
while the same command against a directory the harness itself created succeeds.

```
[exit code: 1]  sandbox: { mode: "workspace-write", denied: true }
```

**The signature is a value, not a message**, and this family is invisible from
the error path for the same structural reason §3 is: a denied command exits
nonzero, and the shipped shell tools report a nonzero exit as a finished run
rather than as `isError`
(`packages/shell/tool-pwsh/src/render.ts` reports `[exit code: N]` and drops a
denial marker). The fact therefore arrives in `ToolExecutionSuccess.value`,
where `tool-bash` / `tool-pwsh` project what the sandbox executor stamped
(`packages/shell/bash-sandbox/src/index.ts`, `pwsh-sandbox`): the mode the call
actually ran under, whether the backend's own refusal dialect appears in the
**captured stderr**, and the enforcement that applied. Reading the executors'
own stamp rather than a sentence means this plugin is reporting the harness's
reading of its own sandbox, not a guess about a line of output.

**What the advisory says.** Four things, and one it refuses:

- **That retrying is provably useless.** The host-side grant is written once, on
  the workspace **root**, and relies on Windows ACE inheritance to reach the
  tree beneath it. Writing an inherited ACE into an *already-existing* child
  needs `WRITE_DAC` on that child; where the caller does not hold it, Windows
  skips the child silently — no error, no return value, no log line. The backend
  then checks only the root (`hasExactGrant(workspaceRoot)` in
  `packages/sandbox/sandbox-windows-acl/src/acl.ts`) and returns early once the
  grant is there, which it is from the first call onwards. The descendants that
  missed the propagation are never revisited — not later in this session, not in
  any later one.
- **Which objects miss it, and how many.** It is a fact about *who created
  them*: objects the harness creates inherit the ACE, and objects that already
  existed do not. [#423] measured 170 of 729 objects missing it, **including
  root-level files** — so "write at the workspace root instead" is not a safe
  move either.
- **The discriminator, and its second half.** The advisory prints the path it
  keyed on beside the root it tested it against, so the reader can audit the
  claim instead of taking a statement about two strings on faith. Then the
  measurement a single check gets wrong: reading and listing use the **normal**
  token while writing and deleting use the **restricted** (low-integrity) one,
  and both sides must pass — so an object whose DACL names only
  `Administrators`/`SYSTEM` plus the capability SID is refused on the read side
  too, and looks fine to a check that merely greps for the capability SID.
  [#423] measured exactly that on a `.cache` directory.
- **The fork, and the other two branches** (the second added in 0.13.0 from
  [#8383] and its second instance [#8421]; the third in 0.14.0 from [#8409]). The
  grant and the mandatory-integrity **label** go out in the same single
  security-descriptor write, and that write lands on the workspace root (plus
  the session's private temp directory) with **no descendant walk** — so the
  label half can fail to reach the tree while the DACL half arrives at every
  level, and it produces the identical denial. The backend's root-only
  idempotency check then requires the grant, the world delete-child deny **and**
  the exact label (`hasExactGrant()` + `hasExactDeny()` + `hasExactLabel()` all
  matching, `acl.ts:386-388`, label read at `:198-204`) before it returns early,
  so once the root is labelled the propagation is never attempted again and an
  unlabelled child is never revisited — the same root-only short-circuit as the
  DACL half, on the other half of the same call. From inside a session the
  branches are indistinguishable, so the advisory forks them on **breadth**, the
  one fact the reader already owns: a **handful** of stubborn objects while the
  rest of the tree writes normally is the DACL branch, **nothing below the root
  writable at all** with the root itself the only writable place is the label
  branch, and **the root itself refused** — nothing writable, not even the root —
  is a third branch with a different cause and a different remedy (below). A
  Low-integrity child may write to a directory only if that directory's own label
  is Low — the kernel's no-write-up check runs *in addition to* the access check
  — so a DACL that is perfect everywhere changes nothing. [#8383] measured it on
  `0.2.0-rc.2` with the decisive control of a directory created **after** the
  grant: it inherits the capability ACE marked `(I)` and still gets no label.
  (The report's own care is worth keeping: a *grandchild* directory having no
  label proves nothing, because inheritance is per-parent and the intermediate
  directory carries none — only a **direct** child of the labelled root is
  evidence.) From outside a session the repository's own diagnosis skill
  separates the DACL half from the label half (`diagnose-windows-sandbox-acl`,
  0.2.0 and later, prints the owner, the caller's rights and
  `WRITE_DAC`/`WRITE_OWNER` for the one and `LOW_LABEL` — `S-1-16-4096` — for the
  other). And a widened DACL does not clear the label half either, because the
  refusal precedes the ACL: [#8383] confirmed that adding an explicit
  `FullControl` entry for the user on a subdirectory still left the write denied.
- **The third branch, and the one recovery this family has** (added in 0.14.0,
  from [#8409]). The root's own standing grant can be **gone**: the workspace
  root's security descriptor rewritten from outside the harness (an ACL reset, a
  restored descriptor, a tool that re-applies one) leaves nothing writable, the
  root included. It is not a descendant missing an inherited ACE — it is the ACE
  the harness itself wrote that is no longer there — and the reason no retry
  reaches it is one layer **above** the backend's own check: the session-scoped
  provider materializes the root ACE once per **provider lifetime** and keeps the
  root in its own in-memory map, consulting the map instead of the DACL
  thereafter (`sandbox-local/src/index.ts`: the guard at `:403-421`,
  "materializes once per workspace per server lifetime"), so the `hasExactGrant`
  check the other two branches turn on is not even reached again. The
  discriminator is measured on both paths and is a fact about where the cache
  lives, not about one path being more careful: the agentless/runner invocation
  passes no session id (`windowsAclRunnerArgv()`), so the runner owns the DACLs
  and re-applies the grant on **every** spawn — which really does read the DACL —
  and heals by itself, while the desktop session does not. The recovery is the
  only one this family has and it is the **user's**, not a command: restart the
  provider (quit and reopen the desktop app, or open the workspace in a fresh
  one), which empties the map and lets the next provision read the DACL, find the
  ACE absent and write it — the reporter measured exactly that ("restarting the
  desktop brings it back").
- **No repair command.** The obvious one, a recursive `icacls /grant` for the
  capability SID, is refused by Windows itself with `ERROR_NONE_MAPPED` (1332) —
  the tool cannot map that SID to a name, so a grant that must name it never
  reaches the child. The line that *would* work needs `WRITE_DAC` on the object,
  which is the right in question. The advisory states the mechanism, names the
  ceiling, and says out loud that it prints no command because this project has
  no Windows host to verify one on — the same standard §1's standing-grant
  section is held to, and for the same reason.

**What it refuses to explain, and why that is the design.** A denial is the
*sanctioned* outcome in three other situations, and advising about a missing
inherited grant in any of them would be a confidently wrong cause:

- **Outside the workspace** — a confining sandbox denying a path outside its
  writable roots is the whole point, and the denial surface's one-shot escalation
  offer is correct there.
- **Under `read-only`** — that mode denies every write by construction, so an
  in-workspace denial under it is the mode working.
- **A runner failure** — the executor refuses to call a run denied when the
  runner itself failed, and such a value is left alone for the same reason.

What is left is exactly the anomaly: a denial under `workspace-write` of a path
inside the session's own workspace. That is why the family reads the mode off
the **value** (the executor stamped the mode it actually ran under, so no policy
lookup can disagree with it), tests containment against the root the policy
resolver reports, and speaks only when **every** absolute path the command's own
arguments name lies under that root. A command that names an outside path as
well — an interpreter under `C:\Program Files`, an output directory on another
volume — is refused rather than guessed at, and so is a command naming only
relative paths: in both cases the plugin cannot say *which* path was denied, and
silence is the fail-closed direction. The platform gate is real here and cannot
be dropped: the mechanism is ACE inheritance, which no other backend has.

**On a denial it cannot finish placing** — a root the policy resolver does not
report, or no mounted policy service at all — the plugin withholds the advisory
and says so once on the host log. That is the disclosure rule §1's mode gate
follows as well: silence alone would make "the sandbox is not the cause"
indistinguishable from "this plugin could not tell".

[#423] is a Discussion (the repository has issues disabled), and the reply
covering this family is posted there.

### 5. The private temp root inside the workspace (`temp-root-inside-workspace`, added in 0.15.0)

[Discussion #9175] reports the one Windows state in which the sandbox cannot start
**any** process at all: a session opened on a workspace that *contains* the
system temp directory. On Windows the per-user temp root is
`C:\Users\<you>\AppData\Local\Temp`, so a session whose workspace is the profile
directory — or any ancestor of it — is in that state, and under `workspace-write`
every command fails, `echo test` included, with no subprocess output and an error
that names neither operand to move nor the lever that moves it. The file tools
keep working, because they never spawn the sandbox runner; only command execution
is gone.

The invariant is `assertTempRootOutsideWorkspace(workspaceRoot, tempRoot)`
(`packages/sandbox/sandbox-windows-acl/src/path-boundary.ts`), and its own comment
gives the reason: a `workspace-write` session is handed two capabilities that must
not contain one another — a **standing** write grant on the workspace root and a
**revocable** private temp capability under a random directory created beneath the
temp root — and "every child created below it would inherit the standing workspace
capability", which would make the revocable half permanent. So the backend refuses
instead of materializing it. The two directories are compared **canonically**
(`realpathSync.native` on both, then `path.relative`), which is why this is a
filesystem fact rather than a spelling.

**One sentence, two producers.** The same assertion is thrown twice on the way in,
and a fix has to satisfy both:

- the **session-scoped provider** (`sandbox-local`), while it assembles the runner
  argv and before any child exists — which is why the call reports no subprocess
  output at all;
- the **runner** (`sandbox-windows-acl`), which asserts the same pair again for
  `workspace-write` before it spawns, writing its line to stderr behind the
  `windows-acl-run: ` marker with exit 127 — the signature the seam reads as a
  runner failure, so *that* copy reaches the session as the `Runner failure: `
  detail of a `SandboxUnavailableError` rather than as a library assertion.

The family recognizes both spellings and **names which carrier refused**, because
the two fire at different moments and only one of them has anything on stderr.

**It is read from the error, never from text that merely mentions it.** The
signature is the assertion's own sentence *with its two operands*, and it is read
from `error.message` alone — not from a result's rendered content. A command whose
own output quotes the sentence is an ordinary successful run and is left alone
(this suite pins that arm), which is the same discipline §2's whole-line PTY match
follows.

**Why it ships no repair command.** There is nothing to repair: the refusal
happens while the sandbox is deciding whether it can set up its own capabilities,
before any process is created, and no `icacls` grant, no elevation and no
ownership change affects it. What moves the condition is the environment — the
temp root or the workspace — and it is the *user's* move, because the failure it
explains took command execution away and there is no shell left in the session to
run a remedy in:

1. Point the harness's temp directory outside the workspace before it starts.
   `os.tmpdir()` on Windows is `GetTempPathW`, which reads `%TMP%`, then `%TEMP%`,
   then `%USERPROFILE%` — so `set TMP=C:\dsh-temp` (with the directory created
   first, since the check resolves both paths) in the process that launches the
   harness is enough.
2. Or open the session on a workspace that is not an ancestor of the temp root —
   `C:\work\project` rather than `C:\Users\<you>`.

`read-only` is deliberately unaffected (no private temp capability is
materialized, so the assertion is never reached), and `danger-full-access` never
spawns through the sandbox at all — passing under it is consistency, not a
workaround. The advisory says so, because both are the next ideas the diagnosis
invites.

**The pre-flight half.** This is the plugin's only *prediction*, and the family's
second seat: on Windows, before the first tracked call, it asks the public
`ctx.sandboxPolicy.resolve({ session })` for the session's mode and workspace root
and compares the root against `os.tmpdir()` with the backend's own canonical
computation. A `workspace-write` session in the condition is told **before** its
first command fails — the model gets the environment change without first spending
a turn on an `echo` that cannot run. The two seats are separate on purpose: the
pre-flight reports the standing condition, and if a refusal does happen, the
producer's own line and the carrier that wrote it are facts only the failure half
can have, so a second advisory follows. The pre-flight prints the three facts it
computed (host, mode, both directories) so the claim can be audited, and states the
one verification available when no command can be run — *if a command does run in
this session, this condition does not apply and the message can be ignored*. A
Windows host that cannot answer at all (no policy service, no session, a resolver
that throws) is disclosed once on the host log rather than passed off as clear,
which is the disclosure rule every other family keeps.

[#9175] is a Discussion (the repository has issues disabled), and the reply
covering this family is posted there.

### 6. The CIM/WMI boundary of the restricted token (`cim-wmi-denial`, added in 0.17.0)

[discussion #9272] reports a boundary rather than a bug: under a confining Windows
mode **every WMI query, and every cmdlet built on one, is refused** with

```
Get-CimInstance : Access is denied
    + CategoryInfo          : PermissionDenied: (root\cimv2:Win32_OperatingSystem) [Get-CimInstance], CimException
    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
```

`0x80041003` is `WBEM_E_ACCESS_DENIED`, the status the WMI namespace security
check returns; `Get-CimInstance` fails for any class and takes `Get-NetTCPConnection`,
`Get-NetIPAddress`, `Get-NetAdapter`, `Get-Volume` and `Get-ComputerInfo` with it.

**This family's mechanism is documented by the harness itself**, and that is a fact
the advisory states rather than conceals: the Windows ACL backend's own README
says *"Authenticated Users is absent from both lists — the WMI namespace security
check fails (`0x80041003`), so CIM cmdlets and `Get-ComputerInfo` are unavailable
in every confined mode"*, the token builder's doc comment repeats it, and two arms
of that package's runner suite pin `CIM: DENIED` under both confining modes. The
plugin carries the family anyway, for the reason the ACL family carries a
documented prerequisite: **the error does not name it**, and the moment the
diagnosis is needed is the moment a CIM command has just failed for no visible
reason. So the advisory quotes upstream's sentence as the authority and says what
it adds on top, instead of presenting a documented boundary as a discovery.

**What it adds is the half the documentation does not supply.** First, a measured
**native substitute** for each command that stops working — [discussion #9272]'s
own measurements, taken in one session beside the refusals they replace:

| stops working | use instead |
|---|---|
| `Get-NetTCPConnection -State Listen` | `netstat -ano` (parse the `LISTENING` rows) |
| `Get-CimInstance Win32_LogicalDisk` (free space) | `[System.IO.DriveInfo]::new('C').AvailableFreeSpace` |
| memory | `Get-Counter '\Memory\Available MBytes'` |
| `Get-CimInstance Win32_OperatingSystem` (OS version) | registry: `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| `Get-Process` / `Get-Service` | unaffected — neither goes through CIM, which is why they are listed here as the measured controls |

Two commands in that family have **no measured substitute** — `Get-NetIPAddress`
and `Get-NetAdapter` — and the advisory states that gap rather than filling it:
`ipconfig /all` is a plausible candidate that was never measured under a confining
mode, so it is named as a candidate and not handed over as verified.

**And the half that matters most to an agent: two shapes that answer with a wrong
value and no error at all.**

1. `-ErrorAction SilentlyContinue` (or `$ErrorActionPreference = 'SilentlyContinue'`)
   turns every refusal into an **empty result**:
   `(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).Count` → `0`.
   A caller reads that as "nothing is listening" when the query never ran.
2. `Get-PSDrive -PSProvider FileSystem` raises **no error at all** while reporting
   `Used`/`Free` as `0` for every drive, because PowerShell 5.1 fills those columns
   from a WMI query — while `[System.IO.DriveInfo]::new('C').AvailableFreeSpace` is
   correct at the same moment. "0 bytes free" is a value an agent will act on.

Neither shape leaves anything for a classifier to key on, which is why the plugin
stays silent on them and delivers the **rule** inside the advisory attached to a
recognized refusal. That is stated rather than left implicit, so a later reader
does not mistake the silence for an oversight.

**Why it is read from a successful result, like §3 and §4.** A refused cmdlet is a
nonzero exit, and the shipped shell tools report those *without* marking the result
an error (`packages/shell/tool-pwsh/src/render.ts`: "Non-zero exits are reported,
not errored … only infrastructure failures (spawn errors, aborts) surface as
`isError` results"). So the code lives in the settled value's own `stderr` and
never in `error.message`, and a plugin reading only error results is structurally
blind to it. The read is the value's captured `stderr` field rather than assembled
text, so a command that merely *prints* such a record — a log being grepped, a
transcript being re-raised — is left alone by construction.

**The discriminator is the code, not the sentence**, because the sentence is
localized: the reporter's own install prints `拒绝访问` where an English one prints
"Access denied", while `0x80041003` is carried verbatim in the error record's
`FullyQualifiedErrorId` in every display language. The code alone is not enough
either — a quoted line must not make the plugin diagnose a working environment — so
the same stderr must also carry one of the product's own untranslated names
(`HRESULT 0x80041003`, `WBEM_E_ACCESS_DENIED`, `CimException`, `CimCmdlets`,
`cimv2`).

**It names no repair, and says why.** No `icacls` line and no elevation: this
refusal names no path and is not about a file, so no ACE closes it. Passing under
`danger-full-access` confirms the diagnosis and is not a fix — it removes the
sandbox, and with it the reason the session was confined. And the one narrow
allowance a reader naturally proposes — read access to the `root/cimv2` namespace
— is a change to the restricted token's own lists rather than to anything on disk,
priced against a deliberate trade: the same absence of Authenticated Users from
those lists is what upstream lists as closing the `C:\`-root tree-creation escape.
Nobody has measured *which* of the token's checks refuses the namespace (the
second access pass, the mandatory label, or the namespace's own mask), so the
advisory declines to price a narrower fix and says so.

The family is gated on the platform and on the resolved mode, like §3 and §4: the
condition is a property of one backend's restricted token, so a session on another
host — or one whose mode does not confine — is not this story and is withheld
rather than guessed at, with the host log accounting for the silence.

[#9272] is a Discussion (the repository has issues disabled), and the reply
covering this family is posted there, together with the four neighbours that make
the boundary visible as one thing rather than four puzzles: [#1157] (no outbound
network under the same restricted token), [#4163] and [#997] (Schannel TLS failing
with `SEC_E_NO_CREDENTIALS`) and [#1847] (external processes dying with
`0xC0000142`).

## What it does with a recognized failure

1. **One durable advisory per agent, per family.** An agent that hits two
   families is told about **both**, once each. The notice carries its own
   producer-owned `source.kind` (`sandbox-grant-advisor`) — not the retired
   `plugin` wrapper, which the current session format refuses — and a bounded
   one-line `summary` for the transcript row. The host log gets one matching
   `warn` line, so the fact survives outside the transcript too.
2. **A disclosure when it withholds.** The PTY and native-init advisories are
   only sent when the
   resolved mode actually confines, and the workspace-denial advisory only when
   the workspace root is resolvable — the fact its containment claim is tested
   against. If the mode is `danger-full-access`, or either fact cannot be
   resolved at all (no `sandboxPolicy` service mounted, no agent session, a
   resolver that throws, a policy without a root), the failure is left exactly as
   it was **and the host log says so once**. Silence alone would make "the sandbox is
   not the cause" and "this plugin could not tell" indistinguishable from the
   outside. Withholding is never a guess: an unresolvable mode is *not* an
   invitation to fall back to the deployment default.
3. **An optional, bounded fail-fast half** (`enforceAfter`, default **0** =
   off) — **ACL family only**. It refuses a call **before dispatch**
   (`tools/pre-execute`) only when both hold: the environment has failed
   provisioning at least `enforceAfter` times, **and** this exact call (tool +
   canonical arguments) is one this plugin watched fail. The budget is
   `maxDenials` (default 2), after which the call proceeds again. The budget is
   per **episode of brokenness**: a call that finally succeeds stops being a
   denial target and re-arms it, so an environment that breaks twice can be
   refused twice — while a session can always make progress by spending the
   budget it has.

   **Why the blocking half covers one family only** (it is ACL-only by
   construction, in the parameter type): the ACL remedy is a
   command
   the user can run *while the session continues*, so refusing further identical
   calls cannot make the session unfinishable — spending the budget always lets
   the call through, and a repaired environment is discovered by exactly that.
   The PTY remedy is a preset swap, which happens **between** sessions, and the
   native-init remedy is a launch fix on the user's side — whose one in-session
   part, rewriting an MSYS2 command, the model does by calling a *different*
   command, which has a different call key and is therefore never the call being
   refused. The workspace-internal denial is not covered either, and for a
   stronger version of the same reason: its remedy is not a command at all — the
   object was skipped when the grant was written and nothing revisited it — so
   refusing calls could only pad a session that is already unable to do the thing
   being refused.

## Install

```sh
npm install @argszero/cordis-plugin-sandbox-grant-advisor
```

Mount it by adding the patch to your profile, or apply the shipped
`cordis.patch.yml`:

```yaml
- insert:
    - id: sandbox-grant-advisor
      name: '@argszero/cordis-plugin-sandbox-grant-advisor'
```

## Configuration

| option | default | meaning |
| --- | --- | --- |
| `enforceAfter` | `0` | Provisioning failures in one agent after which an identical, already-failing call is refused before dispatch. `0` disables the blocking half entirely. |
| `maxDenials` | `2` | Denials one agent may spend per episode of brokenness. Bounded on purpose; re-armed when a watched call finally succeeds. |
| `include` | `[]` | Tool-name wildcard patterns to watch; empty means every tool. |
| `exclude` | `[]` | Tool-name wildcard patterns never watched. |
| `href` | — | URL quoted in the advisory as the upstream thread, instead of the discussion numbers. |

```yaml
- set:
    - id: sandbox-grant-advisor
      config:
        enforceAfter: 3
```

`include` / `exclude` narrow **both** families: an untracked call is
transparent to the plugin entirely, so a watched-out shell call produces no PTY
advisory (and no withholding note either — the configuration said "not our
story", which is different from "we could not tell").

## What it deliberately refuses to explain

Recognition is narrow, because a classifier that names the wrong cause is worse
than one that stays silent.

- **Only the two `...NamedSecurityInfoW` operations are classified.**
  `SetEntriesInAclW` merges access entries in process memory — there is no
  object and no rights involved — so its failure is *not* an ACL-permission
  problem, and neither are the `LocalFree`, `LockFileEx`,
  `SetConsoleCtrlHandler` or `SetEnvironmentVariableW` failures thrown by the
  same package.
- **The PTY family is matched on a whole line, not a substring.** The producer's
  message *is* the sentence (`PTY shell exited during startup`) with no detail
  field at all, so any longer line that merely contains it is something
  **quoting** it — a transcript, a log a failing command printed, a pasted issue
  body — and the harness is not the producer.
- **The sibling throw is not classified.** `PTY shell did not reach readiness
  before startup timeout` means the shell started and then did not reach a
  prompt: a different cause space (a slow or blocked shell) with a different
  remedy.
- **The Win32 code is kept, not flattened.** `ERROR_ACCESS_DENIED` (5) is the
  case the documented prerequisite explains; another code gets a different
  paragraph that says so instead of borrowing the same sentence.
- **A successful command whose *output* contains the line is not a failure.**
  The gate is the result's error state, not the presence of the text — reading a
  log file that quotes the error must not trigger advice.
- **Only `STATUS_DLL_INIT_FAILED` is classified, and only from the canonical
  value.** `0xC0000409` is the Cygwin/MSYS2 runtime's deliberate fast-fail (a
  different mechanism with a different story) and `0xC0000135` is a missing DLL
  (a packaging problem, not a sandbox one); both are refused, as is exit `127`,
  which upstream's runner-failure rule already owns. And because the code is
  compared as a number in `ToolExecutionSuccess.value`, a command printing
  `[exit code: -1073741502]`, or any value that is not the shipped shell
  projection (`kind: 'foreground'`), is not this family — a line of text can
  never be mistaken for a loader status.
- **A denial is not this family unless the plugin can place it.** A denial under
  `read-only`, under `danger-full-access`, or on a host that is not Windows; a
  value the executor marked as a runner failure (`denied` is not set when the
  runner itself failed); a command naming a path outside the workspace; a command
  naming an outside path as well as an inside one; and a command naming only
  relative paths — all six are refused, and the first three are the *sanctioned*
  outcomes rather than puzzles. The plugin reads the executors' own stamp rather
  than a sentence, so a command whose output contains `denied: true` is not this
  family either.
- **Only one advisory per agent, per family.** The environment is explained
  once; repeating it per failed command would be noise competing with the
  failure itself.

## Honest boundaries

- **The Windows path itself cannot be witnessed on macOS**, where this plugin
  was built. What the test suite proves is the decision layer — classification
  of all six families (the third from the producer's own canonical value,
  built by the suite with the reported `-1073741502` and the report's stderr
  line; the fourth from the executors' own stamp, built by the suite with the
  mode, the `denied` flag and the refusal dialect the executor matches; the fifth
  from the producer's own sentence with both operands, in both carrier spellings,
  plus the pre-flight containment computed on real directories; the sixth from
  the record #9272 pasted, in both display languages, with the silent shapes
  asserted *not* to be recognized), the
  once-per-agent-per-family rule, the sandbox-mode gate
  and its fail-closed behaviour, the fail-fast budget and its self-feeding
  guard, and the wiring to a real cordis `Context` and the real `ToolRuntime` —
  driven by fixtures that throw the producers' exact error shapes
  (`Win32Error`, `packages/subprocess/win32-process/src/errors.ts`; the
  terminal throws, `packages/terminal/terminal-bash/src/{index,session}.ts`). It
  does **not** prove that `icacls ... :(OI)(CI)F` fixes a given machine, nor that
  a given Windows host reproduces the PTY startup failure; those are the user's
  one-line experiment and the reporter's own control, and both advisories say
  where they stop. The native-init family is the one that needs no Windows to be
  faithful, because what it reads is a number inside a JSON value. The
  workspace-denial family is exercised the same way and **does** need the
  platform fact, which the suite supplies by stubbing `process.platform` for the
  arms that need `win32` and restoring it — the plugin reads the real fact rather
  than a config knob, because a knob would be a backdoor into a shipped decision.
  The temp-root family needs the same stub for its pre-flight half, and its
  containment claim is exercised on **real** directories (a real ancestor of this
  host's `os.tmpdir()`), so the `realpathSync.native` comparison the backend
  performs is really performed here rather than simulated on strings.
  The CIM/WMI family needs the stub too, and its fixtures are the record [#9272]
  pasted verbatim — the Chinese `拒绝访问` an English install renders as "Access
  denied" — so the reason recognition keys on the code rather than on the sentence
  is exercised rather than asserted. Its two silent shapes are asserted **not** to
  be recognized: there is nothing for a classifier to key on, and that is the
  disclosure rather than an omission.
  What that proves is the decision layer against the producers' stamped values;
  the ACE-inheritance path itself is still unwitnessed here, and the advisory
  says as much by shipping no repair command.
- **The standing-grant section is source-level, and the out-of-tree reach is the
  reporter's measurement.** What this section states about the backend's own
  behaviour — that the workspace grant is standing, that nothing in the dispose or
  fail-closed path revokes it, that the Low label is inheritable and lives in the
  SACL — is read off the shipped source and the backend's own suite, and is quoted
  as such. What it states about a hard link carrying the label onto a
  content-addressed store is [#8314]'s measurement on their machine, which is why
  the advisory attributes it instead of asserting it as a property of every
  workspace, and why **no removal command is shipped**: this project has no
  Windows host on which to verify one, and an unverified removal command is the
  same defect this plugin exists to answer.
- **It repairs nothing and elevates nothing.** If the directory really is
  Full-control for the caller, the remaining ACL hypothesis is
  `SeSecurityPrivilege` — i.e. the backend's documented prerequisite would be
  wrong. That is an upstream question; the advisory states the discriminator
  rather than assuming the answer.
- **Delivery to the model is the agent loop's.** `additionalContexts` are
  ferried on the settled result here and appended as durable user-role events by
  `agent-loop`; a direct `ctx.tools.execute()` caller with no agent gets no
  advisory (and no agent to explain anything to).
- **It complements `@argszero/cordis-plugin-repeat-guard-escalation`, it does not
  replace it.** That guard keys on **call identity** (identical arguments
  retried); this one keys on the **environment signature**, which is how several
  *different* commands share one cause. Mounting both is sensible.
- **The plugin cannot see the launcher half of `#7735`.** The Low label's other
  side effect — the shell's publisher confirmation before launching a
  Low-integrity `.bat`/`.cmd`/`.exe` — never appears in a tool result, so it is
  outside the seam this plugin subscribes to. The report and its proposed fix
  stay with the maintainers; all this plugin can do is explain the provisioning
  failure that shares its root.
- **The real fix is upstream, in all six families.** For the ACL failure,
  `grantWrite` already computes `hasExactGrant` / `hasExactDeny` /
  `hasExactLabel` and discards which one was false, so the diagnostic that turns
  a 52-minute detour into one line belongs at that site. For the PTY failure,
  the startup path should either report "this sandbox mode is incompatible with
  the PTY backend" or fall back to a one-shot shell. For the native-init death,
  the runner should be launched with the environment its own execution needs
  (`ELECTRON_RUN_AS_NODE=1` when `argv[0]` is an Electron binary — [`#7876`]'s
  three candidate fixes) or refuse, in a checkable way, an MSYS2 program under a
  restricted token. For the workspace-internal denial the site is the same
  `grantWrite`: its early return asks only whether the **root** already carries
  the ACE, so the descendants that missed the propagation are never repaired —
  the check would have to look past the root, or the denial surface would have to
  say *which* path was refused instead of only that one was. For the temp-root
  refusal the assertion is already exact and pre-spawn, so the upstream repair is
  not a better message but a *reachable* one: the provider and the runner both
  throw an internal assertion a session can neither read nor act on, and the two
  ways out — a warning at session start, or a refusal that names the environment
  lever — belong where the assertion is raised rather than in a plugin that has to
  guess the same pair back. For the CIM refusal the site is the restricted token's
  own lists, where the choice to leave Authenticated Users out is deliberate and
  priced (it is what closes the `C:\`-root tree-creation escape) — so the repair
  is not a wider grant but a measured statement of *which* check refuses the
  namespace, which no one has produced. This plugin is the stopgap for all six.

## Compatibility

Harness peers — all three carry the **same** range, quoted in full on purpose
(a partially quoted range admits fewer lines than the published one):

- `@deepseek-ai/dsh-llm@>=0.1.2-rc.1 <0.2.0 || >=0.1.3-alpha.2 <0.2.0 || >=0.1.5-alpha.1 <0.2.0 || >=0.1.6-alpha.1 <0.2.0 || >=0.1.7-alpha.1 <0.2.0` — the only **runtime**
  import: `createUserMessage` and `boundContextSummary`.
- `@deepseek-ai/dsh-agent@>=0.1.2-rc.1 <0.2.0 || >=0.1.3-alpha.2 <0.2.0 || >=0.1.5-alpha.1 <0.2.0 || >=0.1.6-alpha.1 <0.2.0 || >=0.1.7-alpha.1 <0.2.0` and
  `@deepseek-ai/dsh-tools@>=0.1.2-rc.1 <0.2.0 || >=0.1.3-alpha.2 <0.2.0 || >=0.1.5-alpha.1 <0.2.0 || >=0.1.6-alpha.1 <0.2.0 || >=0.1.7-alpha.1 <0.2.0` — imported for their **types** only (`Agent`,
  `ToolExecution`, `PostToolDecision`, …). Nothing is loaded from them at
  runtime, but the shipped `lib/types/index.d.ts` still names them, so a consumer
  on a line outside this range fails to typecheck against this package's own
  declarations; that is a compatibility claim, and it is declared as a peer for
  that reason.
- `@deepseek-ai/cordis@^4.0.2`.

`@deepseek-ai/dsh-sandbox-policy` is **not** a peer: the PTY family's mode
lookup is a guarded, structural one (`ctx.get('sandboxPolicy')`) precisely so a
composition that does not mount the service degrades to silence instead of
failing to load. See `src/mode.ts`.

Probed at the newest build of every line the range admits — `0.1.2-rc.1`,
`0.1.3-alpha.2`, `0.1.5-rc.3`, `0.1.6-alpha.2`, `0.1.7-rc.2` (the newest build of
the line the later Windows reports ran on) — with `npm run test:probe-lines`,
which derives those builds from this range, installs each one from the registry
into a scratch tree and runs the suite against it. `0.1.7-rc.1`, the build the
third report ran, is admitted by the same `||` segment and was probed while it was
the newest of that line.

The whole set is re-probed whenever this package's source changes rather than
carried over from an earlier version: the range is a claim about *this* build of
the plugin, so `0.7.1` re-ran all five lines above, `0.9.0` re-ran them again,
`0.16.0` re-ran them a third time, `0.17.0` a fourth and `0.18.0` a fifth — all
five `PASS` each time. A
line whose probe fails is removed from the range rather than left claimed. The
scratch tree's resolved versions are the ones to read back when a probe is quoted
as evidence — the probe script pins them by exact version, and `--keep` leaves the
tree in place to check.

**The next line's pre-releases are outside that range on purpose**, and the guard
in `test/packaging.spec.mjs` enforces it (a range that admits `0.2.0` fails the
suite). `0.2.0-rc.2` — the build the newest report in this family runs, including
its Desktop variant — was nevertheless probed by hand (`npm run test:probe-lines --
0.2.0-rc.2`) and the suite goes green there, which is the honest reason to expect
the plugin to work on it. It is a measurement, not a claim: the range widens when
the `0.2.0` line is the released one rather than its pre-release.

The mode lookup stays guarded through this version too: the native-init family
needs the same resolved mode as the PTY family, and it takes it from the same
`ctx.get('sandboxPolicy')` capability guard, so a composition without the service
degrades to a disclosed silence rather than failing to load.

## Development

```sh
npm install
npm test                 # tsc, then the suite (real cordis + real ToolRuntime)
npm run test:inject      # defect injection: mutate the source, rebuild, require the suite to go red
npm run test:probe-lines # install the newest build of each admitted line and run the suite against it
npm run test:probe-lines -- 0.1.7-rc.1  # one line only
```

The suite is mostly control arms: a guard that explains the wrong failure, or
refuses a call that would have worked, is worse than one that stays silent.

`test:inject` exists because an arm nobody has seen fail proves nothing. It
mutates the decision layer one defect at a time — the mode gate removed, the
PTY message matched as a substring, the preset remedy pointed back at the dead
legacy directory, two families collapsed into one bookkeeping slot, the advisory
delivered per call instead of per agent, the loader-status read moved onto the
error path, the family keyed on the rendered text, the third producer asserted
rather than handed over as a mode switch, the code said to name its own
direction, the `.NET` cause left standing, the CIM platform gate inverted, the
localized sentence keyed on instead of the status code, the CIM context marker
guard dropped, a CIM substitute pair removed — and requires that specific
arms fail. It reports `SILENT ARMS: none` when every arm bites, restores the
source in a `finally`, and prints `EQUIVALENT` (with the reason) for a mutation
the current runtime cannot distinguish rather than counting it as a pass.

[discussion #7538]: https://github.com/deepseek-ai/deepseek-harness/discussions/7538
[discussion #7622]: https://github.com/deepseek-ai/deepseek-harness/discussions/7622
[discussion #7646]: https://github.com/deepseek-ai/deepseek-harness/discussions/7646
[discussion #7720]: https://github.com/deepseek-ai/deepseek-harness/discussions/7720
[discussion #7750]: https://github.com/deepseek-ai/deepseek-harness/discussions/7750
[discussion #7735]: https://github.com/deepseek-ai/deepseek-harness/discussions/7735
[discussion #7771]: https://github.com/deepseek-ai/deepseek-harness/discussions/7771
[discussion #7804]: https://github.com/deepseek-ai/deepseek-harness/discussions/7804
[discussion #7816]: https://github.com/deepseek-ai/deepseek-harness/discussions/7816
[discussion #8232]: https://github.com/deepseek-ai/deepseek-harness/discussions/8232
[discussion #8272]: https://github.com/deepseek-ai/deepseek-harness/discussions/8272
[discussion #8275]: https://github.com/deepseek-ai/deepseek-harness/discussions/8275
[discussion #8412]: https://github.com/deepseek-ai/deepseek-harness/discussions/8412
[discussion #7638]: https://github.com/deepseek-ai/deepseek-harness/discussions/7638
[discussion #7876]: https://github.com/deepseek-ai/deepseek-harness/discussions/7876
[discussion #7877]: https://github.com/deepseek-ai/deepseek-harness/discussions/7877
[discussion #8208]: https://github.com/deepseek-ai/deepseek-harness/discussions/8208
[#423]: https://github.com/deepseek-ai/deepseek-harness/discussions/423
[#7750]: https://github.com/deepseek-ai/deepseek-harness/discussions/7750
[#7771]: https://github.com/deepseek-ai/deepseek-harness/discussions/7771
[#7804]: https://github.com/deepseek-ai/deepseek-harness/discussions/7804
[#7876]: https://github.com/deepseek-ai/deepseek-harness/discussions/7876
[#7877]: https://github.com/deepseek-ai/deepseek-harness/discussions/7877
[#8232]: https://github.com/deepseek-ai/deepseek-harness/discussions/8232
[#8272]: https://github.com/deepseek-ai/deepseek-harness/discussions/8272
[#8275]: https://github.com/deepseek-ai/deepseek-harness/discussions/8275
[#8193]: https://github.com/deepseek-ai/deepseek-harness/discussions/8193
[#8174]: https://github.com/deepseek-ai/deepseek-harness/discussions/8174
[#8208]: https://github.com/deepseek-ai/deepseek-harness/discussions/8208
[discussion #8312]: https://github.com/deepseek-ai/deepseek-harness/discussions/8312
[discussion #8314]: https://github.com/deepseek-ai/deepseek-harness/discussions/8314
[discussion #8322]: https://github.com/deepseek-ai/deepseek-harness/discussions/8322
[#7709]: https://github.com/deepseek-ai/deepseek-harness/discussions/7709
[#7735]: https://github.com/deepseek-ai/deepseek-harness/discussions/7735
[#8175]: https://github.com/deepseek-ai/deepseek-harness/discussions/8175
[#8312]: https://github.com/deepseek-ai/deepseek-harness/discussions/8312
[#8313]: https://github.com/deepseek-ai/deepseek-harness/discussions/8313
[#8314]: https://github.com/deepseek-ai/deepseek-harness/discussions/8314
[#8322]: https://github.com/deepseek-ai/deepseek-harness/discussions/8322
[#8334]: https://github.com/deepseek-ai/deepseek-harness/discussions/8334
[#8336]: https://github.com/deepseek-ai/deepseek-harness/discussions/8336
[#8383]: https://github.com/deepseek-ai/deepseek-harness/discussions/8383
[#8409]: https://github.com/deepseek-ai/deepseek-harness/discussions/8409
[#8412]: https://github.com/deepseek-ai/deepseek-harness/discussions/8412
[#8421]: https://github.com/deepseek-ai/deepseek-harness/discussions/8421
[#8426]: https://github.com/deepseek-ai/deepseek-harness/discussions/8426
[#9175]: https://github.com/deepseek-ai/deepseek-harness/discussions/9175
[#8990]: https://github.com/deepseek-ai/deepseek-harness/discussions/8990
[#8991]: https://github.com/deepseek-ai/deepseek-harness/discussions/8991
[#9186]: https://github.com/deepseek-ai/deepseek-harness/discussions/9186
[#9238]: https://github.com/deepseek-ai/deepseek-harness/discussions/9238
[#9336]: https://github.com/deepseek-ai/deepseek-harness/discussions/9336
[#9272]: https://github.com/deepseek-ai/deepseek-harness/discussions/9272
[#1157]: https://github.com/deepseek-ai/deepseek-harness/discussions/1157
[#4163]: https://github.com/deepseek-ai/deepseek-harness/discussions/4163
[#997]: https://github.com/deepseek-ai/deepseek-harness/discussions/997
[#1847]: https://github.com/deepseek-ai/deepseek-harness/discussions/1847
[Discussion #9170]: https://github.com/deepseek-ai/deepseek-harness/discussions/9170
