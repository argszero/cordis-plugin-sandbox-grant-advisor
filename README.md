# @argszero/cordis-plugin-sandbox-grant-advisor

Turns a sandbox environment failure that has **no path forward** into a
diagnosis the model — and the user reading the transcript — can act on. Three
signatures, one mechanism:

```
SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)   # Windows workspace ACL
PTY shell exited during startup                             # persistent shell × confining mode
[exit code: -1073741502]  (0xC0000142)                      # a confined child that never started
```

**This plugin is the stopgap for "the error does not name the outstanding
condition".** It repairs nothing: no ACL is written, no privilege is requested,
nothing is elevated, no environment variable is set for another process, no
preset is installed and no mode is changed.

## The three failures it recognizes

The first two are recognized on the public **`tools/post-execute`** waterfall
(`@deepseek-ai/dsh-tools`) from the failure text. That seam is the one that has
all three of what a diagnosis needs: the failure
(providers propagate their error unchanged and the tool pipeline settles it as an
`isError` result), an agent identity to attribute it to (`exec.agent`), and a
channel that speaks to the model in the same step (`PostToolDecision`'s
`additionalContexts`, which the agent loop turns into a durable user-role message
— `packages/core/agent-loop/src/tool-calls.ts`). The third is recognized at the
**same seam** from the canonical value of a result the pipeline calls a
*success*, for a reason §3 gives in full.

That seam, not `ctx.sandbox.confine`: `confine(argv, policy, signal)` sees the
confinement failure too, but its signature carries no agent, so a wrapper could
detect the condition and never deliver a word about it to the session that is
stuck.

### 1. Workspace provisioning — the Windows ACL failure (`acl-provisioning`)

Six reports describe this exact line: [discussion #7538], [discussion #7622],
[discussion #7646], [discussion #7720], [discussion #7750], [discussion #7735]
(the last two on data-volume workspaces, where *no* ACE names the caller at all —
the inherited `Authenticated Users: Modify` is the whole of their access). In each
one every sandboxed command fails the same way, before it runs, and the error names
neither the missing right nor a remedy.

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
    restores inheritance, and inheritance is what supplied the Modify-only ACE above.
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

The advisory that follows is addressed to **two different readers**:

```
Persistent shell failed to start — command execution is unavailable in this session, and retrying cannot fix it.

What was reported:
  PTY shell exited during startup

The `bash` tool is a PERSISTENT PTY session (a shell that stays alive between calls), and this session's sandbox mode is
`workspace-write` — not `danger-full-access`. A confining mode spawns the shell through the sandbox, and there the
terminal backend cannot create the pseudo-console at all, so the child exits before its first prompt. ...

Do NOT retry, and do not look for a command that fixes it: every attempt will fail identically, and there is no
shell to run a command in. Use your file read/write tools instead, and hand the choice below to the user.

What unblocks the session — the user's decision, not the model's:
  1. switch the agent preset to `standard`, whose shell tool is a one-shot subprocess (no PTY) and works
     under the sandbox; or
  2. override the `preset-minimal` row in your profile patch — `$DSH_HOME/profiles/<profile>/cordis.patch.yml`, or
     `$DSH_HOME/cordis.patch.yml` for every profile — replacing its `persistent-shell` group with
     `@deepseek-ai/dsh-tool-pwsh` (a one-shot subprocess, no PTY); the patch layer is yours, so an upgrade
     will not overwrite it; or
  3. run the session with `danger-full-access`, which drops the very confinement the sandbox exists to give.
     Prefer 1 or 2.
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

Two reports of one exit code: [`#7876`] (the packaged desktop app) and [`#7877`]
(MSYS2 / Git Bash). Both are `0xC0000142` `STATUS_DLL_INIT_FAILED` — the Windows
loader terminated the process while it was initializing its native images, i.e.
**before the program's entry point**. A command that ran and then failed exits
with its own status and prints its own output; this one produced neither.

| what was run | what came out | exit code |
| --- | --- | --- |
| `cmd.exe /c "echo cmd-ok"` | `cmd-ok` | 0 |
| `pwsh -NoLogo -NoProfile -Command "Write-Output pwsh-ok"` | `pwsh-ok` | 0 |
| `D:\Git\bin\bash.exe -c "echo bash-ok"` | `couldn't create signal pipe, Win32 error 5` | `-1073741502` |

Two producers have been measured under a confining mode:

1. **An MSYS2 / Git-Bash program** ([`#7877`]). The restricted token's runtime
   cannot create the pipe it uses for signals, so bash aborts in the loader
   phase, while `cmd.exe` and `pwsh` run fine in the same workspace under the
   same mode. The plugin's own composition has no way around this: `tool-bash`
   and `bash-sandbox` are `disabled` on win32
   (`@deepseek-ai/dsh-base/cordis.patch.yml`), so the combination is likely
   never covered upstream. The **one conversion a model can make itself** is to
   write the same work as a PowerShell or `cmd` command.
2. **The packaged desktop app's sandbox runner** ([`#7876`]).
   `dsh-sandbox-local` launches the runner as `[process.execPath, entry]`, and
   in the packaged build `process.execPath` is the Electron executable, which
   starts as an *application* unless the child's environment carries
   `ELECTRON_RUN_AS_NODE=1` — so the runner never runs and every confined command
   reports this code with **no output at all**. The unpacked node host
   (`node apps/cli/lib/bin.js web`) is unaffected. The plugin reports whether
   *this* process is an Electron binary (`process.versions.electron`) as a
   measured fact rather than assuming it, because that is the check the
   discriminator turns on.

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

Two producers have been measured under a confining Windows mode. Check which one this is:
  1. An MSYS2 / Git-Bash program ... (#7877)
     If that is what could not start: write the same work as a PowerShell or `cmd` command instead
  2. The packaged desktop application's sandbox runner ... (#7876)
     This process is NOT an Electron binary (`process.versions.electron` is unset), so that producer does not apply here.

Do not retry this call: the environment has not changed, and the identical call produces the identical code.

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
which the plugin answers (is this host the packaged desktop binary). It never
offers `danger-full-access` as a fix and never suggests a sandbox setting be
relaxed.

## What it does with a recognized failure

1. **One durable advisory per agent, per family.** An agent that hits two
   families is told about **both**, once each. The notice carries its own
   producer-owned `source.kind` (`sandbox-grant-advisor`) — not the retired
   `plugin` wrapper, which the current session format refuses — and a bounded
   one-line `summary` for the transcript row. The host log gets one matching
   `warn` line, so the fact survives outside the transcript too.
2. **A disclosure when it withholds.** The PTY and native-init advisories are
   only sent when the
   resolved mode actually confines. If the mode is `danger-full-access`, or
   cannot be resolved at all (no `sandboxPolicy` service mounted, no agent
   session, a resolver that throws), the failure is left exactly as it was
   **and the host log says so once**. Silence alone would make "the sandbox is
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

   **Why the blocking half does not extend to the two mode-gated families** (it
   is ACL-only by construction, in the parameter type): the ACL remedy is a
   command
   the user can run *while the session continues*, so refusing further identical
   calls cannot make the session unfinishable — spending the budget always lets
   the call through, and a repaired environment is discovered by exactly that.
   The PTY remedy is a preset swap, which happens **between** sessions, and the
   native-init remedy is a launch fix on the user's side — whose one in-session
   part, rewriting an MSYS2 command, the model does by calling a *different*
   command, which has a different call key and is therefore never the call being
   refused. Refusing calls in those families could only pad a session that is
   already unable to do the thing being refused.

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
- **Only one advisory per agent, per family.** The environment is explained
  once; repeating it per failed command would be noise competing with the
  failure itself.

## Honest boundaries

- **The Windows path itself cannot be witnessed on macOS**, where this plugin
  was built. What the test suite proves is the decision layer — classification
  of all three families (the third from the producer's own canonical value,
  built by the suite with the reported `-1073741502` and the report's stderr
  line), the once-per-agent-per-family rule, the sandbox-mode gate
  and its fail-closed behaviour, the fail-fast budget and its self-feeding
  guard, and the wiring to a real cordis `Context` and the real `ToolRuntime` —
  driven by fixtures that throw the producers' exact error shapes
  (`Win32Error`, `packages/subprocess/win32-process/src/errors.ts`; the
  terminal throws, `packages/terminal/terminal-bash/src/{index,session}.ts`). It
  does **not** prove that `icacls ... :(OI)(CI)F` fixes a given machine, nor that
  a given Windows host reproduces the PTY startup failure; those are the user's
  one-line experiment and the reporter's own control, and both advisories say
  where they stop. The native-init family is the one that needs no Windows to be
  faithful, because what it reads is a number inside a JSON value.
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
- **The real fix is upstream, in all three families.** For the ACL failure,
  `grantWrite` already computes `hasExactGrant` / `hasExactDeny` /
  `hasExactLabel` and discards which one was false, so the diagnostic that turns
  a 52-minute detour into one line belongs at that site. For the PTY failure,
  the startup path should either report "this sandbox mode is incompatible with
  the PTY backend" or fall back to a one-shot shell. For the native-init death,
  the runner should be launched with the environment its own execution needs
  (`ELECTRON_RUN_AS_NODE=1` when `argv[0]` is an Electron binary — [`#7876`]'s
  three candidate fixes) or refuse, in a checkable way, an MSYS2 program under a
  restricted token. This plugin is the stopgap for all three.

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
the plugin, so `0.6.0` re-ran all five lines above. A line whose probe fails is
removed from the range rather than left claimed. The scratch tree's resolved
versions are the ones to read back when a probe is quoted as evidence — the probe
script pins them by exact version, and `--keep` leaves the tree in place to check.

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
error path, the family keyed on the rendered text — and requires that specific
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
[discussion #7638]: https://github.com/deepseek-ai/deepseek-harness/discussions/7638
[discussion #7876]: https://github.com/deepseek-ai/deepseek-harness/discussions/7876
[discussion #7877]: https://github.com/deepseek-ai/deepseek-harness/discussions/7877
[#7750]: https://github.com/deepseek-ai/deepseek-harness/discussions/7750
[#7771]: https://github.com/deepseek-ai/deepseek-harness/discussions/7771
[#7804]: https://github.com/deepseek-ai/deepseek-harness/discussions/7804
[#7876]: https://github.com/deepseek-ai/deepseek-harness/discussions/7876
[#7877]: https://github.com/deepseek-ai/deepseek-harness/discussions/7877
